import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/**
 * =============================================================================
 * 资源门禁模型说明
 * =============================================================================
 *
 * 本模块用于控制“高资源开销任务”的并发启动/执行节奏，例如：
 * - bgutil 的 generatePoToken
 * - 未来其他高内存/高 CPU 开销任务
 *
 * 核心目标：
 * 1. 不只看某一瞬间的内存值，尽量降低瞬时误判
 * 2. 多进程/多实例场景下，通过 reservation 预占位，提前把“即将到来的资源消耗”算进去
 * 3. 通过 gate lock，避免多个进程在同一时刻一起穿透判断
 *
 * 当前模型的核心判断公式为：
 *
 *   windowMinAvailableMb
 *   - pendingReservedMb
 *   - additionalReservedMb
 *   >= minFreeAfterLaunchMb
 *
 * 并同时要求：
 *
 *   windowMaxUsedPercent <= maxMemoryPercent
 *
 * 含义如下：
 * - windowMinAvailableMb:
 *     最近一段采样窗口内，“可用内存”的最小值
 * - pendingReservedMb:
 *     当前已经登记、但尚未完成的 reservation 总量
 * - additionalReservedMb:
 *     本次准备启动/执行的新重任务的预算
 * - minFreeAfterLaunchMb:
 *     即使启动/执行该任务后，系统仍至少要保留的可用内存
 * - windowMaxUsedPercent:
 *     最近一段采样窗口内，内存使用率的最大值
 * - maxMemoryPercent:
 *     允许继续执行新重任务的最大内存使用率阈值
 *
 * 注意：
 * - 该模型不是为了精确估算“某个任务最终 RSS”
 * - 而是为了在多进程竞争资源时，提供一个偏保守、可落地的准入机制
 */

/* ============================================================================
 * 默认参数
 * ========================================================================== */

/**
 * 目录锁/门闩锁抢占失败后的重试间隔（毫秒）。
 */
const DEFAULT_LOCK_RETRY_INTERVAL_MS = 50;

/**
 * reservation 记录的默认过期时间（毫秒）。
 *
 * 说明：
 * - 若进程异常退出，reservation 未来不及清理，超过该时间后会被视为陈旧记录并清理
 * - 当前默认值取 10 分钟，通常足以覆盖一次 POT 生成流程
 */
const DEFAULT_RESERVATION_STALE_MS = 10 * 60 * 1000;

/**
 * 单个高开销任务的默认预留内存预算（MB）。
 *
 * 说明：
 * - 这不是“精确 RSS”
 * - 而是资源准入时使用的保守预算值
 * - 后续你可以根据实际压测结果继续调
 */
export const DEFAULT_RESERVED_MB = 0;

/**
 * 启动/执行一个新高开销任务后，系统至少还应剩余多少可用内存（MB）。
 */
export const DEFAULT_MIN_FREE_AFTER_LAUNCH_MB = 0;

/**
 * 允许启动/执行新任务时的最大内存使用率（百分比）。
 */
export const DEFAULT_MAX_MEMORY_PERCENT = 200.0;

/**
 * 滑动窗口采样次数。
 */
export const DEFAULT_MEMORY_SAMPLE_COUNT = 5;

/**
 * 相邻采样间隔（毫秒）。
 */
export const DEFAULT_MEMORY_SAMPLE_INTERVAL_MS = 500;

/**
 * 当资源不足时，整体下一轮重试前的等待时间（毫秒）。
 */
export const DEFAULT_RETRY_INTERVAL_MS = 2000;

/* ============================================================================
 * 类型定义
 * ========================================================================== */

/**
 * 资源门禁使用的最小日志接口。
 *
 * 说明：
 * - 不强依赖具体 Logger 实现
 * - 只要调用方能提供 debug / warn 方法即可
 */
export interface ResourceGateLogger {
    debug?: (msg: string) => void;
    warn?: (msg: string) => void;
}

/**
 * 某一时刻的系统内存快照。
 *
 * 字段说明：
 * - totalBytes:
 *     系统总内存
 * - availableBytes:
 *     当前可用内存
 * - usedPercent:
 *     当前内存使用率（百分比）
 * - swapTotalBytes:
 *     swap 总量
 * - swapUsedBytes:
 *     当前已使用 swap
 */
export type MemorySnapshot = {
    totalBytes: number;
    availableBytes: number;
    usedPercent: number;
    swapTotalBytes: number;
    swapUsedBytes: number;
};

/**
 * 滑动窗口采样统计结果。
 *
 * 字段说明：
 * - minAvailableMb:
 *     最近 N 次采样中的最小可用内存
 * - maxUsedPercent:
 *     最近 N 次采样中的最大内存使用率
 * - latestSwapUsedMb:
 *     最近一次采样时的 swap 已使用量
 * - sampleCount:
 *     实际采样次数
 */
export type MemoryWindowStats = {
    minAvailableMb: number;
    maxUsedPercent: number;
    latestSwapUsedMb: number;
    sampleCount: number;
};

/**
 * reservation 落盘结构。
 *
 * 字段说明：
 * - reservationId:
 *     reservation 唯一标识
 * - pid:
 *     创建 reservation 的进程 PID
 * - createdAt:
 *     创建时间戳（毫秒）
 * - reservedMb:
 *     当前 reservation 预留的内存预算（MB）
 */
export type LaunchReservation = {
    reservationId: string;
    pid: number;
    createdAt: number;
    reservedMb: number;
};

/* ============================================================================
 * 通用小工具
 * ========================================================================== */

/**
 * 简单 sleep。
 */
function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * 字节转 MB，向下取整。
 */
function bytesToMb(bytes: number): number {
    return Math.floor(bytes / 1024 / 1024);
}

/**
 * 确保目录存在。
 */
function ensureDir(dir: string): string {
    fs.mkdirSync(dir, { recursive: true });
    return dir;
}

/* ============================================================================
 * 基础目录锁
 * ========================================================================== */

/**
 * 一个简单的跨平台目录锁。
 *
 * 设计说明：
 * - Node 标准库没有像 flock 那样简单统一的跨平台文件锁 API
 * - 因此这里采用“mkdir 成功即获得锁”的方式实现轻量互斥
 *
 * 语义：
 * - 创建锁目录成功 => 获得锁
 * - 若锁目录已存在 => 说明锁被别人持有
 *
 * 适用场景：
 * - 保护短时临界区
 * - 不依赖第三方库
 * - 跨平台
 */
class DirectoryLock {
    private readonly lockPath: string;
    private readonly retryIntervalMs: number;
    private readonly staleMs: number;
    private acquired = false;

    constructor(
        lockPath: string,
        options?: {
            retryIntervalMs?: number;
            staleMs?: number;
        },
    ) {
        this.lockPath = lockPath;
        this.retryIntervalMs =
            options?.retryIntervalMs ?? DEFAULT_LOCK_RETRY_INTERVAL_MS;
        this.staleMs = options?.staleMs ?? DEFAULT_RESERVATION_STALE_MS;
    }

    /**
     * 获取锁。
     *
     * 流程：
     * 1. 尝试 mkdir(lockPath)
     * 2. 若目录已存在，则判断是否为陈旧锁
     * 3. 若仍不可用，则等待后重试
     */
    async acquire(): Promise<void> {
        ensureDir(path.dirname(this.lockPath));

        for (;;) {
            try {
                fs.mkdirSync(this.lockPath);
                this.writeOwnerMeta();
                this.acquired = true;
                return;
            } catch (e: any) {
                if (e?.code !== "EEXIST") {
                    throw e;
                }

                this.cleanupIfStale();
                await sleep(this.retryIntervalMs);
            }
        }
    }

    /**
     * 释放锁。
     */
    release(): void {
        if (!this.acquired) {
            return;
        }

        try {
            const ownerPath = path.resolve(this.lockPath, "owner.json");
            if (fs.existsSync(ownerPath)) {
                fs.rmSync(ownerPath, { force: true });
            }
        } catch {
            // ignore
        }

        try {
            fs.rmdirSync(this.lockPath);
        } catch {
            // ignore
        } finally {
            this.acquired = false;
        }
    }

    /**
     * 写入 owner 元数据，便于判断陈旧锁。
     */
    private writeOwnerMeta(): void {
        const ownerPath = path.resolve(this.lockPath, "owner.json");
        const owner = {
            pid: process.pid,
            createdAt: Date.now(),
        };
        fs.writeFileSync(ownerPath, JSON.stringify(owner), "utf8");
    }

    /**
     * 若锁目录过旧，则尝试清理。
     *
     * 说明：
     * - 这里只做“保守清理”
     * - 若 owner.json 缺失、损坏或时间戳异常，则不贸然删除
     * - 仅当 createdAt 明确存在且超过 staleMs 时，才尝试清理
     */
    private cleanupIfStale(): void {
        try {
            const ownerPath = path.resolve(this.lockPath, "owner.json");
            if (!fs.existsSync(ownerPath)) {
                return;
            }

            const raw = fs.readFileSync(ownerPath, "utf8");
            const parsed = JSON.parse(raw);
            const createdAt = Number(parsed?.createdAt ?? 0);

            if (!createdAt || Number.isNaN(createdAt)) {
                return;
            }

            if (Date.now() - createdAt < this.staleMs) {
                return;
            }

            try {
                fs.rmSync(ownerPath, { force: true });
            } catch {
                // ignore
            }

            try {
                fs.rmdirSync(this.lockPath);
            } catch {
                // ignore
            }
        } catch {
            // ignore
        }
    }
}

/* ============================================================================
 * Memory 快照读取
 * ========================================================================== */

/**
 * 尝试从 Linux 的 /proc/meminfo 读取更贴近“可用内存”的数据。
 *
 * 返回：
 * - 成功：MemorySnapshot
 * - 失败：undefined
 *
 * 说明：
 * - Linux 下的 MemAvailable 比 os.freemem() 更接近“真正还可安全使用”的内存量
 * - 因此优先使用
 */
function tryReadLinuxMemInfo(): MemorySnapshot | undefined {
    if (process.platform !== "linux") {
        return undefined;
    }

    try {
        const raw = fs.readFileSync("/proc/meminfo", "utf8");
        const lines = raw.split(/\r?\n/);

        const kv = new Map<string, number>();

        for (const line of lines) {
            const match = line.match(/^([A-Za-z_]+):\s+(\d+)\s+kB$/);

            /**
             * 这里不要直接使用 match[1] / match[2]，
             * 因为在 TypeScript 严格模式下，它们会被视为 string | undefined。
             *
             * 因此这里显式做一次判空，避免：
             * - TS2345: Argument of type 'string | undefined' is not assignable to parameter of type 'string'
             */
            const key = match?.[1];
            const valueKbRaw = match?.[2];

            if (!key || !valueKbRaw) {
                continue;
            }

            const valueBytes = Number(valueKbRaw) * 1024;
            kv.set(key, valueBytes);
        }

        const totalBytes = Number(kv.get("MemTotal") ?? 0);
        const availableBytes = Number(
            kv.get("MemAvailable") ?? kv.get("MemFree") ?? 0,
        );
        const swapTotalBytes = Number(kv.get("SwapTotal") ?? 0);
        const swapFreeBytes = Number(kv.get("SwapFree") ?? 0);
        const swapUsedBytes = Math.max(0, swapTotalBytes - swapFreeBytes);

        /**
         * 这里要求 totalBytes / availableBytes 都必须有效。
         *
         * 若关键字段读不到，则回退到上层的 os.totalmem()/os.freemem() 方案。
         */
        if (!totalBytes || !availableBytes) {
            return undefined;
        }

        const usedPercent =
            totalBytes > 0
                ? ((totalBytes - availableBytes) / totalBytes) * 100
                : 0;

        return {
            totalBytes,
            availableBytes,
            usedPercent,
            swapTotalBytes,
            swapUsedBytes,
        };
    } catch {
        return undefined;
    }
}

/**
 * 获取当前系统内存快照。
 *
 * 优先级：
 * 1. Linux 下优先读取 /proc/meminfo
 * 2. 其他平台或读取失败时，回退到 os.totalmem()/os.freemem()
 *
 * 注意：
 * - 非 Linux 平台下，swap 数据这里无法统一可靠获取，因此默认置 0
 */
export function getSystemMemorySnapshot(): MemorySnapshot {
    const linuxSnapshot = tryReadLinuxMemInfo();
    if (linuxSnapshot) {
        return linuxSnapshot;
    }

    const totalBytes = os.totalmem();
    const freeBytes = os.freemem();
    const availableBytes = freeBytes;
    const usedPercent =
        totalBytes > 0 ? ((totalBytes - availableBytes) / totalBytes) * 100 : 0;

    return {
        totalBytes,
        availableBytes,
        usedPercent,
        swapTotalBytes: 0,
        swapUsedBytes: 0,
    };
}

/* ============================================================================
 * ResourceGate
 * ========================================================================== */

/**
 * 通用高开销任务资源门禁。
 *
 * 这个类不关心你真正执行的是什么任务，它只负责：
 *
 *   “当前资源是否允许再执行一个新的高开销任务？”
 *
 * 当前机制由 4 部分组成：
 * 1. 滑动窗口内存采样
 * 2. reservation（预占位）
 * 3. gate lock（门闩锁）
 * 4. 资源准入判断
 *
 * 关键设计：
 * - 不在门外只看一次瞬时值
 * - 不让多个进程同时穿透判断
 * - 不让未来即将消耗的资源被忽略
 */
export class ResourceGate {
    readonly gateName: string;
    readonly baseDir: string;
    readonly reservedMb: number;
    readonly minFreeAfterLaunchMb: number;
    readonly maxMemoryPercent: number;
    readonly reservationStaleMs: number;
    readonly sampleCount: number;
    readonly sampleIntervalMs: number;
    readonly retryIntervalMs: number;

    constructor(options: {
        gateName: string;
        baseDir: string;
        reservedMb?: number;
        minFreeAfterLaunchMb?: number;
        maxMemoryPercent?: number;
        reservationStaleMs?: number;
        sampleCount?: number;
        sampleIntervalMs?: number;
        retryIntervalMs?: number;
    }) {
        this.gateName = options.gateName;
        this.baseDir = path.resolve(options.baseDir);
        this.reservedMb = options.reservedMb ?? DEFAULT_RESERVED_MB;
        this.minFreeAfterLaunchMb =
            options.minFreeAfterLaunchMb ?? DEFAULT_MIN_FREE_AFTER_LAUNCH_MB;
        this.maxMemoryPercent =
            options.maxMemoryPercent ?? DEFAULT_MAX_MEMORY_PERCENT;
        this.reservationStaleMs =
            options.reservationStaleMs ?? DEFAULT_RESERVATION_STALE_MS;
        this.sampleCount = options.sampleCount ?? DEFAULT_MEMORY_SAMPLE_COUNT;
        this.sampleIntervalMs =
            options.sampleIntervalMs ?? DEFAULT_MEMORY_SAMPLE_INTERVAL_MS;
        this.retryIntervalMs =
            options.retryIntervalMs ?? DEFAULT_RETRY_INTERVAL_MS;

        ensureDir(this.baseDir);
        ensureDir(this.reservationsDir);
    }

    /**
     * gate lock 目录路径。
     *
     * 说明：
     * - 使用目录锁，而不是普通文件锁
     */
    get gateLockPath(): string {
        return path.resolve(this.baseDir, `${this.gateName}.gate.lock`);
    }

    /**
     * reservation 目录路径。
     */
    get reservationsDir(): string {
        return path.resolve(this.baseDir, `${this.gateName}.reservations`);
    }

    /**
     * 某个 reservation 对应的 JSON 文件路径。
     */
    getReservationFilePath(reservationId: string): string {
        return path.resolve(this.reservationsDir, `${reservationId}.json`);
    }

    /**
     * 连续采样最近一段时间的系统内存状态，并统计出一个“窗口最差值”。
     *
     * 当前统计指标：
     * - minAvailableMb:
     *     最近 N 次采样中，available 的最小值
     * - maxUsedPercent:
     *     最近 N 次采样中，used_percent 的最大值
     * - latestSwapUsedMb:
     *     最后一次采样时的 swap 已使用量
     */
    async sampleMemoryWindow(): Promise<MemoryWindowStats> {
        const snapshots: MemorySnapshot[] = [];

        /**
         * 这里强制至少采样 1 次，避免出现空数组。
         */
        const actualCount = Math.max(1, this.sampleCount);

        for (let i = 0; i < actualCount; i++) {
            snapshots.push(getSystemMemorySnapshot());

            if (i !== actualCount - 1) {
                await sleep(this.sampleIntervalMs);
            }
        }

        /**
         * 在 TypeScript 严格模式下，数组按下标读取会被推断为可能 undefined，
         * 即使从逻辑上 snapshots 一定非空。
         *
         * 因此这里显式取出最后一个元素并做保护，避免：
         * - TS2532: Object is possibly 'undefined'
         */
        const lastSnapshot = snapshots[snapshots.length - 1];
        if (!lastSnapshot) {
            throw new Error(
                "sampleMemoryWindow: lastSnapshot is undefined",
            );
        }

        return {
            minAvailableMb: Math.min(
                ...snapshots.map((s) => bytesToMb(s.availableBytes)),
            ),
            maxUsedPercent: Math.max(...snapshots.map((s) => s.usedPercent)),
            latestSwapUsedMb: bytesToMb(lastSnapshot.swapUsedBytes),
            sampleCount: snapshots.length,
        };
    }

    /**
     * 写入 reservation 文件。
     *
     * 写入策略：
     * - 先写临时文件
     * - 再 rename 到正式文件
     *
     * 这样可以降低半写文件风险。
     */
    writeReservation(reservation: LaunchReservation): string {
        ensureDir(this.reservationsDir);

        const filePath = this.getReservationFilePath(reservation.reservationId);
        const tmpPath = `${filePath}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2, 8)}`;

        try {
            fs.writeFileSync(tmpPath, JSON.stringify(reservation), "utf8");
            fs.renameSync(tmpPath, filePath);
        } finally {
            try {
                if (fs.existsSync(tmpPath)) {
                    fs.rmSync(tmpPath, { force: true });
                }
            } catch {
                // ignore
            }
        }

        return filePath;
    }

    /**
     * 删除 reservation 文件。
     */
    removeReservation(filePath: string): void {
        try {
            if (fs.existsSync(filePath)) {
                fs.rmSync(filePath, { force: true });
            }
        } catch {
            // ignore
        }
    }

    /**
     * 读取当前所有有效 reservation。
     *
     * 同时会清理：
     * - JSON 损坏的文件
     * - 超过 TTL 的僵尸 reservation
     */
    loadActiveReservations(logger?: ResourceGateLogger): LaunchReservation[] {
        ensureDir(this.reservationsDir);

        const now = Date.now();
        const active: LaunchReservation[] = [];

        for (const name of fs.readdirSync(this.reservationsDir)) {
            if (!name.endsWith(".json")) {
                continue;
            }

            const filePath = path.resolve(this.reservationsDir, name);

            try {
                const raw = JSON.parse(
                    fs.readFileSync(filePath, "utf8"),
                ) as LaunchReservation;

                const createdAt = Number(raw?.createdAt ?? 0);
                if (!createdAt || Number.isNaN(createdAt)) {
                    throw new Error("invalid createdAt");
                }

                if (now - createdAt > this.reservationStaleMs) {
                    logger?.debug?.(
                        `[${this.gateName}] removed stale reservation. file=${filePath}`,
                    );
                    this.removeReservation(filePath);
                    continue;
                }

                active.push(raw);
            } catch (e: any) {
                logger?.warn?.(
                    `[${this.gateName}] removed invalid reservation file. file=${filePath}, err=${e?.message ?? e}`,
                );
                this.removeReservation(filePath);
            }
        }

        return active;
    }

    /**
     * 统计当前所有有效 reservation 的总预留内存（MB）。
     */
    getTotalPendingReservedMb(logger?: ResourceGateLogger): number {
        return this.loadActiveReservations(logger).reduce(
            (sum, item) => sum + Number(item.reservedMb || 0),
            0,
        );
    }

    /**
     * 根据“采样窗口 + 已有 reservation + 本次新增预算”判断是否允许继续执行。
     */
    isLaunchAllowed(options: {
        memoryWindow: MemoryWindowStats;
        pendingReservedMb: number;
        additionalReservedMb: number;
    }): boolean {
        const { memoryWindow, pendingReservedMb, additionalReservedMb } =
            options;

        if (memoryWindow.maxUsedPercent > this.maxMemoryPercent) {
            return false;
        }

        const projectedFreeMb =
            memoryWindow.minAvailableMb -
            pendingReservedMb -
            additionalReservedMb;

        return projectedFreeMb >= this.minFreeAfterLaunchMb;
    }

    /**
     * 门外等待，直到资源允许再执行一个新任务。
     *
     * 注意：
     * - 这里不持有 gate lock
     * - 目的是避免在资源明显不足时，所有进程都去争抢门闩锁
     */
    async waitUntilAllowed(logger?: ResourceGateLogger): Promise<void> {
        for (;;) {
            const memoryWindow = await this.sampleMemoryWindow();
            const pendingReservedMb = this.getTotalPendingReservedMb(logger);

            if (
                this.isLaunchAllowed({
                    memoryWindow,
                    pendingReservedMb,
                    additionalReservedMb: this.reservedMb,
                })
            ) {
                return;
            }

            const projectedFreeMb =
                memoryWindow.minAvailableMb -
                pendingReservedMb -
                this.reservedMb;

            logger?.debug?.(
                `[${this.gateName}] launch delayed due to memory pressure. ` +
                    `minAvailableMb=${memoryWindow.minAvailableMb}, ` +
                    `maxUsedPercent=${memoryWindow.maxUsedPercent.toFixed(2)}, ` +
                    `pendingReservedMb=${pendingReservedMb}, ` +
                    `reservedMb=${this.reservedMb}, ` +
                    `projectedFreeMb=${projectedFreeMb}, ` +
                    `minFreeAfterLaunchMb=${this.minFreeAfterLaunchMb}, ` +
                    `latestSwapUsedMb=${memoryWindow.latestSwapUsedMb}. ` +
                    `Retry in ${this.retryIntervalMs}ms.`,
            );

            await sleep(this.retryIntervalMs);
        }
    }

    /**
     * 在资源门禁保护下执行一个高开销异步任务。
     *
     * 关键流程：
     * 1. 门外等待资源允许
     * 2. 获取短时 gate lock，避免多个进程同时穿透判断
     * 3. 在 gate lock 内写入 reservation
     * 4. 门内再做一次判断
     * 5. 释放 gate lock，但保留 reservation
     * 6. 执行真正的高开销任务 fn()
     * 7. fn 完成后删除 reservation
     *
     * 为什么 gate lock 不覆盖整个 fn 生命周期：
     * - 如果整个生命周期都持有 gate lock，就会把所有任务完全串行化
     * - 这不是我们要的
     *
     * 为什么 reservation 要覆盖整个 fn 生命周期：
     * - 因为 fn 真正执行期间，资源仍在被占用
     * - 若太早删除 reservation，会让后续进程误以为资源已经释放
     */
    async runExclusiveWithPermission<T>(
        logger: ResourceGateLogger | undefined,
        fn: () => Promise<T>,
    ): Promise<T> {
        await this.waitUntilAllowed(logger);

        const gateLock = new DirectoryLock(this.gateLockPath, {
            retryIntervalMs: DEFAULT_LOCK_RETRY_INTERVAL_MS,
            staleMs: this.reservationStaleMs,
        });

        let reservationPath: string | undefined;

        await gateLock.acquire();

        try {
            const reservation: LaunchReservation = {
                reservationId: `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                pid: process.pid,
                createdAt: Date.now(),
                reservedMb: this.reservedMb,
            };

            reservationPath = this.writeReservation(reservation);

            /**
             * 门内二次判断。
             *
             * 注意：
             * - 此时 pendingReservedMb 已经包含“我自己”刚刚写入的 reservation
             * - 因此 additionalReservedMb 应传 0
             */
            for (;;) {
                const memoryWindow = await this.sampleMemoryWindow();
                const pendingReservedMb =
                    this.getTotalPendingReservedMb(logger);

                if (
                    this.isLaunchAllowed({
                        memoryWindow,
                        pendingReservedMb,
                        additionalReservedMb: 0,
                    })
                ) {
                    break;
                }

                const projectedFreeMb =
                    memoryWindow.minAvailableMb - pendingReservedMb;

                logger?.debug?.(
                    `[${this.gateName}] launch still delayed inside gate. ` +
                        `minAvailableMb=${memoryWindow.minAvailableMb}, ` +
                        `maxUsedPercent=${memoryWindow.maxUsedPercent.toFixed(2)}, ` +
                        `pendingReservedMb=${pendingReservedMb}, ` +
                        `projectedFreeMb=${projectedFreeMb}, ` +
                        `minFreeAfterLaunchMb=${this.minFreeAfterLaunchMb}, ` +
                        `latestSwapUsedMb=${memoryWindow.latestSwapUsedMb}. ` +
                        `Retry in ${this.retryIntervalMs}ms.`,
                );

                await sleep(this.retryIntervalMs);
            }
        } catch (e) {
            if (reservationPath) {
                this.removeReservation(reservationPath);
            }
            gateLock.release();
            throw e;
        }

        /**
         * 关键点：
         * - 到这里，reservation 已经写好
         * - 门内判断也通过了
         * - 现在释放 gate lock，让其他进程继续排队判断
         * - 但 reservation 仍然保留，直到 fn 真正执行完成
         */
        gateLock.release();

        try {
            return await fn();
        } finally {
            if (reservationPath) {
                this.removeReservation(reservationPath);
            }
        }
    }
}
