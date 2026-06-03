import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";

/**
 * 单条 POT 缓存数据。
 *
 * 字段命名与当前 SessionManager / generate_once.ts 中使用的结构保持一致，
 * 方便后续最小代价接入与维护。
 */
export interface YoutubeSessionData {
    poToken: string;
    contentBinding: string;
    expiresAt: Date;
}

/**
 * 仅用于磁盘持久化时的 JSON 结构。
 *
 * 注意：
 * - expiresAt 落盘时是字符串
 * - 读取后再恢复成 Date
 */
type YoutubeSessionDataJson = {
    poToken: string;
    contentBinding: string;
    expiresAt: string;
};

/**
 * 缓存根目录内部结构说明：
 *
 * <cachedir>/
 *   ├── entries/
 *   │   └── <sha256(contentBinding)>.json
 *   └── locks/
 *       └── <sha256(contentBinding)>.lock
 *
 * 设计目标：
 * 1. 不同 contentBinding 完全并发
 * 2. 同一个 contentBinding 串行，避免重复 mint
 * 3. 不再使用单个 cache.json，避免多进程写回互相覆盖
 * 4. 写入采用“临时文件 + rename”方式，降低半写文件风险
 */

/* ============================================================================
 * 路径工具
 * ========================================================================== */

/**
 * 计算 bgutil 缓存根目录。
 *
 * 路径规则：
 * 1. XDG_CACHE_HOME/bgutil-ytdlp-pot-provider
 * 2. HOME/.cache/bgutil-ytdlp-pot-provider
 * 3. USERPROFILE/.cache/bgutil-ytdlp-pot-provider
 * 4. fallbackDir/bgutil-ytdlp-pot-provider
 * 5. 当前工作目录下的 .cache-bgutil
 *
 * 说明：
 * - 这个函数更适合“未显式传入最终 cachedir 时，自动计算默认目录”
 * - 如果外部已经明确给了完整 cachedir，应直接 path.resolve(cachedir)
 *   而不是再把它作为 fallbackDir 传进来
 */
export function getBgutilCacheDir(fallbackDir?: string): string {
    const homeDirectory = process.env.HOME || process.env.USERPROFILE;
    const { XDG_CACHE_HOME } = process.env;

    if (XDG_CACHE_HOME !== undefined) {
        return path.resolve(XDG_CACHE_HOME, "bgutil-ytdlp-pot-provider");
    }

    if (homeDirectory) {
        return path.resolve(
            homeDirectory,
            ".cache",
            "bgutil-ytdlp-pot-provider",
        );
    }

    if (fallbackDir) {
        return path.resolve(fallbackDir, "bgutil-ytdlp-pot-provider");
    }

    return path.resolve(process.cwd(), ".cache-bgutil");
}

/**
 * 返回 entries 目录。
 */
export function getCacheEntriesDir(cachedir: string): string {
    return path.resolve(cachedir, "entries");
}

/**
 * 返回 locks 目录。
 */
export function getCacheLocksDir(cachedir: string): string {
    return path.resolve(cachedir, "locks");
}

/**
 * 确保缓存根目录及内部目录存在。
 */
export function ensureCacheDir(cachedir: string): string {
    fs.mkdirSync(getCacheEntriesDir(cachedir), { recursive: true });
    fs.mkdirSync(getCacheLocksDir(cachedir), { recursive: true });
    return cachedir;
}

/**
 * 根据 contentBinding 生成稳定、安全的 cache key。
 *
 * 不直接把 contentBinding 用作文件名，原因与 WPC 一样：
 * - 可能包含不适合作为路径名的字符
 * - 不利于跨平台与路径安全
 */
export function makeCacheKey(contentBinding: string): string {
    return crypto
        .createHash("sha256")
        .update(contentBinding, "utf8")
        .digest("hex");
}

/**
 * 返回某个 contentBinding 对应的缓存文件路径。
 */
export function getCacheEntryPath(
    cachedir: string,
    contentBinding: string,
): string {
    return path.resolve(
        getCacheEntriesDir(cachedir),
        `${makeCacheKey(contentBinding)}.json`,
    );
}

/**
 * 返回某个 contentBinding 对应的锁目录路径。
 *
 * 注意：
 * - 虽然名字叫 .lock，但当前实现里它是“目录锁”
 * - 不是普通文件锁
 */
export function getCacheLockPath(
    cachedir: string,
    contentBinding: string,
): string {
    return path.resolve(
        getCacheLocksDir(cachedir),
        `${makeCacheKey(contentBinding)}.lock`,
    );
}

/* ============================================================================
 * 单 key 锁
 * ========================================================================== */

/**
 * 一个非常轻量的“单 key 目录锁”。
 *
 * 设计说明：
 * - Node 标准库没有像 flock 一样跨平台、简单且稳定的统一 API
 * - 这里采用 mkdir 作为互斥锁：
 *   * 创建成功 => 获得锁
 *   * 目录已存在 => 说明锁已被别人持有
 *
 * 目录锁优点：
 * - 简单
 * - 跨平台
 * - 不依赖第三方库
 *
 * 注意：
 * - 锁目录路径虽然以 ".lock" 结尾，但它本身是一个目录，不是普通文件
 */
export class CacheEntryLock {
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
        this.retryIntervalMs = options?.retryIntervalMs ?? 50;
        this.staleMs = options?.staleMs ?? 30 * 1000;
    }

    /**
     * 获取锁。
     *
     * 策略：
     * 1. 尝试 mkdir(lockPath)
     * 2. 若已存在，则判断是否是陈旧锁
     * 3. 若不是陈旧锁，则循环等待
     */
    async acquire(): Promise<void> {
        const parentDir = path.dirname(this.lockPath);
        fs.mkdirSync(parentDir, { recursive: true });

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

                // 已存在时，尝试判断是否为陈旧锁
                this.cleanupIfStale();

                // 等待后重试
                await sleep(this.retryIntervalMs);
            }
        }
    }

    /**
     * 释放锁。
     */
    release(): void {
        if (!this.acquired) return;

        try {
            const metaPath = path.resolve(this.lockPath, "owner.json");
            if (fs.existsSync(metaPath)) {
                fs.rmSync(metaPath, { force: true });
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
     * 带锁执行。
     */
    async runExclusive<T>(fn: () => Promise<T>): Promise<T> {
        await this.acquire();
        try {
            return await fn();
        } finally {
            this.release();
        }
    }

    /**
     * 写入 owner 元数据，便于判断锁是否陈旧。
     */
    private writeOwnerMeta(): void {
        const metaPath = path.resolve(this.lockPath, "owner.json");
        const data = {
            pid: process.pid,
            createdAt: Date.now(),
        };
        fs.writeFileSync(metaPath, JSON.stringify(data), "utf8");
    }

    /**
     * 清理陈旧锁。
     *
     * 判定逻辑：
     * - 读取 owner.json 的 createdAt
     * - 若超出 staleMs，则认为锁可能已失效
     *
     * 注意：
     * - 这里只做“保守清理”
     * - 仅在确实很久没释放时才尝试删除
     */
    private cleanupIfStale(): void {
        try {
            const metaPath = path.resolve(this.lockPath, "owner.json");
            if (!fs.existsSync(metaPath)) {
                return;
            }

            const raw = fs.readFileSync(metaPath, "utf8");
            const parsed = JSON.parse(raw);
            const createdAt = Number(parsed?.createdAt ?? 0);

            if (!createdAt || Number.isNaN(createdAt)) {
                return;
            }

            if (Date.now() - createdAt < this.staleMs) {
                return;
            }

            // 先删 owner，再删目录
            try {
                fs.rmSync(metaPath, { force: true });
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
 * 单条缓存对象转换
 * ========================================================================== */

function toJsonEntry(entry: YoutubeSessionData): YoutubeSessionDataJson {
    return {
        poToken: entry.poToken,
        contentBinding: entry.contentBinding,
        expiresAt: entry.expiresAt.toISOString(),
    };
}

function fromJsonEntry(raw: YoutubeSessionDataJson): YoutubeSessionData {
    const expiresAt = new Date(raw.expiresAt);
    if (Number.isNaN(expiresAt.getTime())) {
        throw new Error(`Invalid expiresAt: ${raw.expiresAt}`);
    }

    return {
        poToken: raw.poToken,
        contentBinding: raw.contentBinding,
        expiresAt,
    };
}

/**
 * 判断单条缓存是否已过期。
 */
export function isYoutubeSessionDataExpired(
    entry: YoutubeSessionData,
    now = new Date(),
): boolean {
    return now > entry.expiresAt;
}

/**
 * 构造一条新的 YoutubeSessionData。
 */
export function buildYoutubeSessionData(
    contentBinding: string,
    poToken: string,
    tokenTtlHours = 6,
    now = new Date(),
): YoutubeSessionData {
    return {
        poToken,
        contentBinding,
        expiresAt: new Date(now.getTime() + tokenTtlHours * 60 * 60 * 1000),
    };
}

/* ============================================================================
 * 无锁读写
 * ========================================================================== */

/**
 * 无锁读取单条缓存。
 *
 * 调用方必须确保自己已经拿到该 key 对应的锁。
 */
export function loadYoutubeSessionDataUnlocked(
    cachedir: string,
    contentBinding: string,
): YoutubeSessionData | undefined {
    const entryPath = getCacheEntryPath(cachedir, contentBinding);
    if (!fs.existsSync(entryPath)) {
        return undefined;
    }

    try {
        const raw = JSON.parse(
            fs.readFileSync(entryPath, "utf8"),
        ) as YoutubeSessionDataJson;
        const entry = fromJsonEntry(raw);

        if (entry.contentBinding !== contentBinding) {
            return undefined;
        }

        return entry;
    } catch {
        return undefined;
    }
}

/**
 * 无锁删除单条缓存。
 *
 * 调用方必须确保自己已经拿到该 key 对应的锁。
 */
export function removeYoutubeSessionDataUnlocked(
    cachedir: string,
    contentBinding: string,
): void {
    const entryPath = getCacheEntryPath(cachedir, contentBinding);
    if (!fs.existsSync(entryPath)) {
        return;
    }
    fs.rmSync(entryPath, { force: true });
}

/**
 * 无锁写入单条缓存。
 *
 * 调用方必须确保自己已经拿到该 key 对应的锁。
 * 使用“临时文件 + rename”原子替换。
 */
export function saveYoutubeSessionDataUnlocked(
    cachedir: string,
    entry: YoutubeSessionData,
): void {
    ensureCacheDir(cachedir);

    const entryPath = getCacheEntryPath(cachedir, entry.contentBinding);
    const tmpPath = `${entryPath}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2, 8)}`;

    try {
        fs.writeFileSync(tmpPath, JSON.stringify(toJsonEntry(entry)), "utf8");
        fs.renameSync(tmpPath, entryPath);
    } finally {
        try {
            if (fs.existsSync(tmpPath)) {
                fs.rmSync(tmpPath, { force: true });
            }
        } catch {
            // ignore
        }
    }
}

/* ============================================================================
 * 对外：带锁访问
 * ========================================================================== */

/**
 * 读取单条缓存（带锁）。
 */
export async function getYoutubeSessionData(
    cachedir: string,
    contentBinding: string,
    cleanup = true,
): Promise<YoutubeSessionData | undefined> {
    ensureCacheDir(cachedir);

    const lock = new CacheEntryLock(getCacheLockPath(cachedir, contentBinding));
    return await lock.runExclusive(async () => {
        const entry = loadYoutubeSessionDataUnlocked(cachedir, contentBinding);
        if (!entry) {
            return undefined;
        }

        if (isYoutubeSessionDataExpired(entry)) {
            if (cleanup) {
                removeYoutubeSessionDataUnlocked(cachedir, contentBinding);
            }
            return undefined;
        }

        return entry;
    });
}

/**
 * 在“调用方已持有锁”的前提下读取缓存。
 */
export function getYoutubeSessionDataLocked(
    cachedir: string,
    contentBinding: string,
    cleanup = true,
): YoutubeSessionData | undefined {
    const entry = loadYoutubeSessionDataUnlocked(cachedir, contentBinding);
    if (!entry) {
        return undefined;
    }

    if (isYoutubeSessionDataExpired(entry)) {
        if (cleanup) {
            removeYoutubeSessionDataUnlocked(cachedir, contentBinding);
        }
        return undefined;
    }

    return entry;
}

/**
 * 写入单条缓存（带锁）。
 */
export async function setYoutubeSessionData(
    cachedir: string,
    entry: YoutubeSessionData,
): Promise<void> {
    ensureCacheDir(cachedir);

    const lock = new CacheEntryLock(
        getCacheLockPath(cachedir, entry.contentBinding),
    );
    await lock.runExclusive(async () => {
        saveYoutubeSessionDataUnlocked(cachedir, entry);
    });
}

/**
 * 在“调用方已持有锁”的前提下写入缓存。
 */
export function setYoutubeSessionDataLocked(
    cachedir: string,
    entry: YoutubeSessionData,
): void {
    saveYoutubeSessionDataUnlocked(cachedir, entry);
}

/**
 * 返回某个 contentBinding 对应的锁对象。
 *
 * 使用场景：
 * - 外层希望自己控制锁范围
 * - 在同一把锁内完成：
 *   1. 再次检查缓存
 *   2. miss 才真正生成
 *   3. 成功后写回
 */
export function getCacheEntryLock(
    cachedir: string,
    contentBinding: string,
): CacheEntryLock {
    ensureCacheDir(cachedir);
    return new CacheEntryLock(getCacheLockPath(cachedir, contentBinding));
}

/* ============================================================================
 * 工具
 * ========================================================================== */

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
