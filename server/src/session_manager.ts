import axios, {AxiosRequestConfig} from "axios";
import {
    BG,
    BgConfig,
    DescrambledChallenge,
    WebPoSignalOutput,
    FetchFunction,
    buildURL,
    getHeaders,
    USER_AGENT,
} from "bgutils-js";
import {Agent} from "node:https";
import {ProxyAgent} from "proxy-agent";
import {JSDOM} from "jsdom";
import * as path from "node:path";
import {Innertube, Context as InnertubeContext} from "youtubei.js";

import {
    buildYoutubeSessionData,
    getBgutilCacheDir,
    getCacheEntryLock,
    getYoutubeSessionDataLocked,
    setYoutubeSessionDataLocked,
    type YoutubeSessionData,
    type CacheEntryLock,
} from "./cache_store.ts";
import {ResourceGate} from "./resource_gate.ts";
import {BGUTIL_RUNTIME_CONFIG} from "./runtime_config.ts";

/**
 * 进程内“按 contentBinding 索引”的 POT 缓存。
 *
 * 说明：
 * - 这是当前 Node / Deno 进程内的内存缓存
 * - 与磁盘缓存不同，它不会跨进程共享
 * - 现在它作为“二级缓存”保留：
 *   1. 先查磁盘缓存（跨进程共享）
 *   2. 再查当前进程内缓存
 *   3. 最后再真正生成
 */
interface YoutubeSessionDataCaches {
    [contentBinding: string]: YoutubeSessionData;
}

/**
 * 简单日志封装。
 *
 * 设计目标：
 * - shouldLog=true 时，debug/log 生效
 * - shouldLog=false 时，debug/log 静默
 * - warn/error 始终输出
 *
 * 说明：
 * - 当前仍保持你原先的实现风格
 * - 后续若接统一 logger，可在这里集中替换
 */
class Logger {
    readonly debug: (msg: string) => void;
    readonly log: (msg: string) => void;
    readonly warn: (msg: string) => void;
    readonly error: (msg: string) => void;

    constructor(shouldLog = true) {
        if (shouldLog) {
            this.debug = (msg: string) => {
                console.debug(msg);
            };
            this.log = (msg: string) => {
                console.log(msg);
            };
        } else {
            this.debug = this.log = () => {
            };
        }
        this.warn = (msg: string) => {
            console.warn(msg);
        };
        this.error = (msg: string) => {
            console.error(msg);
        };
    }
}

/**
 * 代理配置规格。
 *
 * 字段说明：
 * - proxyUrl:
 *   规范化后的代理 URL
 * - sourceAddress:
 *   本地源地址（若指定）
 * - disableTlsVerification:
 *   是否禁用 TLS 校验
 * - ipFamily:
 *   若 sourceAddress 指定，则推断为 IPv4 / IPv6
 *
 * 说明：
 * - 这里主要负责“代理相关参数的规范化与 https agent / proxy agent 创建”
 */
class ProxySpec {
    public proxyUrl?: URL;
    public sourceAddress?: string;
    public disableTlsVerification: boolean = false;
    public readonly ipFamily?: number;

    constructor({sourceAddress, disableTlsVerification}: Partial<ProxySpec>) {
        this.sourceAddress = sourceAddress;
        this.disableTlsVerification = disableTlsVerification || false;

        if (!this.sourceAddress) {
            this.ipFamily = undefined;
        } else {
            this.ipFamily = this.sourceAddress?.includes(":") ? 6 : 4;
        }
    }

    public get proxy(): string | undefined {
        return this.proxyUrl?.href;
    }

    public set proxy(newProxy: string | undefined) {
        if (!newProxy) {
            this.proxyUrl = undefined;
            return;
        }

        try {
            this.proxyUrl = new URL(newProxy);
        } catch {
            const fallback = `http://${newProxy}`;
            try {
                this.proxyUrl = new URL(fallback);
            } catch (e) {
                throw new Error(`Invalid proxy URL: ${fallback}`, {
                    cause: e,
                });
            }
        }
    }

    /**
     * 构造 Node 路径下使用的 https dispatcher / proxy agent。
     *
     * 说明：
     * - 无代理时，直接返回 https.Agent
     * - 有代理时，返回 ProxyAgent
     * - 日志中会隐藏代理密码
     */
    public asDispatcher(
        this: Readonly<this>,
        logger: Logger,
    ): Agent | undefined {
        const {proxyUrl, sourceAddress, disableTlsVerification} = this;

        if (!proxyUrl) {
            return new Agent({
                localAddress: sourceAddress,
                family: this.ipFamily,
                rejectUnauthorized: !disableTlsVerification,
            });
        }

        // 只要 proxyUrl 存在，这里 proxy 一定是可用字符串
        const pxyStr = this.proxy!;
        const {password} = proxyUrl;

        const loggedProxy = password
            ? pxyStr.replace(password, "****")
            : pxyStr;

        logger.log(`Using proxy: ${loggedProxy}`);

        try {
            return new ProxyAgent({
                getProxyForUrl: () => pxyStr,
                localAddress: sourceAddress,
                family: this.ipFamily,
                rejectUnauthorized: !disableTlsVerification,
            });
        } catch (e) {
            throw new Error(`Failed to create proxy agent for ${loggedProxy}`, {
                cause: e,
            });
        }
    }
}

/**
 * minter 级缓存 key 规格。
 *
 * 说明：
 * - bgutil 的 _minterCache 不是按 contentBinding 存，而是按“网络环境”存
 * - 当前 key 由以下信息构成：
 *   1. remoteHost（若存在）
 *   2. 否则退化为 [proxy, sourceAddress]
 *
 * 这与上层的“磁盘 POT 缓存按 contentBinding 存”是两层不同粒度的缓存：
 * - 磁盘缓存：缓存最终 poToken
 * - _minterCache：缓存 token minter
 */
class CacheSpec {
    constructor(
        public pxySpec: ProxySpec,
        public ip: string | null,
    ) {
    }

    /**
     * 进程内 minterCache 的 key。
     *
     * 说明：
     * - 当前逻辑保持与原实现一致
     * - 这个 key 主要用于区分“代理 / sourceAddress / remoteHost”等环境差异
     */
    public get key(): string {
        return JSON.stringify(
            this.ip || [this.pxySpec.proxy, this.pxySpec.sourceAddress],
        );
    }
}

/**
 * token minter 缓存条目。
 *
 * 字段说明：
 * - expiry:
 *   当前 minter 失效时间
 * - integrityToken:
 *   生成 minter 时拿到的 integrity token
 * - minter:
 *   真正用于 mint POT 的 WebPoMinter
 */
type TokenMinter = {
    expiry: Date;
    integrityToken: string;
    minter: BG.WebPoMinter;
};

/**
 * 进程内 minter 缓存。
 *
 * key:
 * - CacheSpec.key
 *
 * value:
 * - TokenMinter
 */
type MinterCache = Map<string, TokenMinter>;

/**
 * challenge 数据结构。
 *
 * 说明：
 * - 当前沿用你现有项目中的 challenge 结构定义
 * - 主要用于：
 *   1. 直接使用网页里带的 challenge
 *   2. 若缺失，则再走 /att/get 获取
 */
export type ChallengeData = {
    interpreterUrl: {
        privateDoNotAccessOrElseTrustedResourceUrlWrappedValue: string;
    };
    interpreterHash: string;
    program: string;
    globalName: string;
    clientExperimentsStateBlob: string;
};

export class SessionManager {
    /**
     * hardcoded API key that has been used by youtube for years
     */
    private static readonly REQUEST_KEY = "O43z0dpjhgX20SCx4KAo";

    /**
     * 是否已经初始化过全局 DOM 环境。
     *
     * 说明：
     * - BG client 运行依赖浏览器环境对象
     * - 这里通过 JSDOM 只初始化一次，避免重复污染 globalThis
     */
    private static hasDom = false;

    /**
     * 进程内 minter 缓存。
     *
     * 说明：
     * - 这是当前进程私有缓存
     * - 不跨进程共享
     * - 会在“磁盘 POT 缓存 miss”后作为二级缓存继续生效
     */
    private _minterCache: MinterCache = new Map();

    /**
     * 当前进程内的 sessionData 缓存。
     *
     * 说明：
     * - 这是“进程内缓存”
     * - 与磁盘缓存并存
     * - 保留这个结构，便于快速命中同进程内的重复请求
     */
    private youtubeSessionDataCaches: YoutubeSessionDataCaches = {};

    /**
     * POT TTL（小时）。
     *
     * 默认：
     * - 取环境变量 TOKEN_TTL
     * - 否则默认为 6
     */
    private readonly TOKEN_TTL_HOURS: number;

    /**
     * 当前 SessionManager 使用的磁盘缓存根目录。
     *
     * 目录示例：
     *   ~/.cache/bgutil-ytdlp-pot-provider
     *
     * 内部结构由 cache_store.ts 自己维护：
     *   entries/
     *   locks/
     */
    private readonly cachedir: string;

    /**
     * 当前 SessionManager 统一使用的资源门禁。
     *
     * 说明：
     * - script 模式与 http 模式都会走到这里
     * - 因此只要调用 generatePoToken()，就都会遵循同一套资源限制
     */
    private readonly resourceGate: ResourceGate;

    /**
     * 日志对象。
     */
    private readonly logger: Logger;

    constructor(
        shouldLog = true,
        /**
         * 可选 cachedir。
         *
         * 说明：
         * - 若外部显式传入，则优先使用外部传入值
         * - 若未传，则内部自动按 XDG / HOME / USERPROFILE 规则计算默认目录
         * - 这样 generate_once.ts 与 main.ts 都不需要再各自决定缓存目录
         */
        cachedir?: string,
    ) {
        this.logger = new Logger(shouldLog);

        this.TOKEN_TTL_HOURS = process.env.TOKEN_TTL
            ? parseInt(process.env.TOKEN_TTL)
            : 6;

        /**
         * cachedir 的优先级规则：
         * 1. 外部显式传入 -> 直接使用
         * 2. 未传 -> 按 cache_store.ts 内部默认规则自动计算
         *
         * 注意：
         * - 这里不能直接写成 getBgutilCacheDir(cachedir)
         * - 因为 getBgutilCacheDir 的参数语义更接近“fallbackDir”
         * - 若这里直接把显式 cachedir 传进去，会让“显式传入目录”失去最高优先级
         */
        this.cachedir = cachedir ? path.resolve(cachedir) : getBgutilCacheDir();

        this.resourceGate = this.buildBgutilResourceGate();

        /**
         * 初始化一次全局 DOM 环境。
         *
         * 说明：
         * - BG client / 某些网页脚本执行依赖 window/document/location/navigator 等对象
         * - 这里统一用 JSDOM 做一次全局补齐
         */
        if (!SessionManager.hasDom) {
            const dom = new JSDOM(
                '<!DOCTYPE html><html lang="en"><head><title></title></head><body></body></html>',
                {
                    url: "https://www.youtube.com/",
                    referrer: "https://www.youtube.com/",
                    userAgent: USER_AGENT,
                },
            );

            Object.assign(globalThis, {
                window: dom.window,
                document: dom.window.document,
                location: dom.window.location,
                origin: dom.window.origin,
            });

            if (!Reflect.has(globalThis, "navigator")) {
                Object.defineProperty(globalThis, "navigator", {
                    value: dom.window.navigator,
                });
            }

            SessionManager.hasDom = true;
        }
    }

    /**
     * 构造 bgutil 使用的统一资源门禁。
     *
     * 当前目录布局：
     * cachedir/resource_gate
     *
     * 说明：
     * - ResourceGate 仍然由 SessionManager 统一管理；
     * - script 模式与 http 模式都会走这里；
     * - 具体阈值从 BGUTIL_RUNTIME_CONFIG 读取，便于线上通过环境变量调参；
     * - 是否真正使用 ResourceGate，由 runWithResourceGate() 判断。
     */
    private buildBgutilResourceGate(): ResourceGate {
        const cfg = BGUTIL_RUNTIME_CONFIG.resourceGate;

        this.logger.log(
            `[resource_gate] build config ` +
            this.safeStringify({
                disabled: BGUTIL_RUNTIME_CONFIG.disableResourceGate,
                baseDir: path.resolve(this.cachedir, "resource_gate"),
                reservedMb: cfg.reservedMb,
                minFreeAfterLaunchMb: cfg.minFreeAfterLaunchMb,
                maxMemoryPercent: cfg.maxMemoryPercent,
                reservationStaleMs: cfg.reservationStaleMs,
                sampleCount: cfg.sampleCount,
                sampleIntervalMs: cfg.sampleIntervalMs,
                retryIntervalMs: cfg.retryIntervalMs,
            }),
        );

        return new ResourceGate({
            gateName: "bgutil_generate_pot",
            baseDir: path.resolve(this.cachedir, "resource_gate"),

            /**
             * 单个 POT 生成任务预估会占用的内存。
             *
             * 说明：
             * - 原来写死 500；
             * - 现在允许通过 BGUTIL_RESOURCE_GATE_RESERVED_MB 调整。
             */
            reservedMb: cfg.reservedMb,

            /**
             * 允许启动新任务后，系统仍需保留的最小空闲内存。
             *
             * 说明：
             * - 原来写死 2000；
             * - 现在允许通过 BGUTIL_RESOURCE_GATE_MIN_FREE_AFTER_LAUNCH_MB 调整。
             */
            minFreeAfterLaunchMb: cfg.minFreeAfterLaunchMb,

            /**
             * 最大内存占用百分比。
             *
             * 说明：
             * - 原来写死 80；
             * - 现在允许通过 BGUTIL_RESOURCE_GATE_MAX_MEMORY_PERCENT 调整。
             */
            maxMemoryPercent: cfg.maxMemoryPercent,

            /**
             * reservation 文件的 stale 时间。
             *
             * 说明：
             * - 原来写死 10 分钟；
             * - 如果进程异常退出，超过该时间后 reservation 可被视为陈旧。
             */
            reservationStaleMs: cfg.reservationStaleMs,

            /**
             * 资源采样次数。
             */
            sampleCount: cfg.sampleCount,

            /**
             * 每次采样间隔。
             */
            sampleIntervalMs: cfg.sampleIntervalMs,

            /**
             * 资源不足时重试间隔。
             */
            retryIntervalMs: cfg.retryIntervalMs,
        });
    }

    /**
     * 用资源门禁包裹真正的高开销生成动作。
     *
     * 设计目标：
     * - 缓存命中时不走 ResourceGate；
     * - 只有真正要 mint POT 时，才进入资源门禁；
     * - 允许通过 BGUTIL_DISABLE_RESOURCE_GATE=1 跳过资源门禁；
     * - 跳过后不会等待 reservation / 内存阈值 / 资源采样。
     *
     * 为什么需要可禁用：
     * - script-node 模式下，每个 yt-dlp 调用都会拉起一个 Node 进程；
     * - 高并发冷启动时，ResourceGate 可能让多个 Node 子进程一直等待；
     * - Python plugin 外层 300 秒超时会直接 kill Node；
     * - 因此在你当前下载系统里，需要允许“尽量使用资源”，而不是内部排队。
     */
    private async runWithResourceGate<T>(fn: () => Promise<T>): Promise<T> {
        if (BGUTIL_RUNTIME_CONFIG.disableResourceGate) {
            this.logger.warn(
                `[resource_gate] disabled by BGUTIL_DISABLE_RESOURCE_GATE, run directly`,
            );

            return await fn();
        }

        return await this.resourceGate.runExclusiveWithPermission(
            {
                debug: (msg) => this.logger.debug(msg),
                warn: (msg) => this.logger.warn(msg),
            },
            fn,
        );
    }

    /**
     * 使缓存失效。
     *
     * 当前行为：
     * - 清空当前进程内的 youtubeSessionDataCaches
     * - 清空当前进程内的 _minterCache
     *
     * 注意：
     * - 这里不清理磁盘缓存
     * - 磁盘缓存若也要清理，应由外层单独提供接口处理
     */
    public invalidateCaches() {
        this.youtubeSessionDataCaches = {};
        this._minterCache.clear();
    }

    /**
     * 仅让当前进程内的 minter 失效。
     *
     * 做法：
     * - 将所有 minter 的 expiry 设为 1970
     *
     * 说明：
     * - 这样下次命中 _minterCache 时，会自动触发 regenerate
     */
    public invalidateIT() {
        this._minterCache.forEach((minterCache) => {
            minterCache.expiry = new Date(0);
        });
    }

    /**
     * 清理当前进程内已经过期的 sessionData 缓存。
     *
     * 注意：
     * - 这里只清理内存缓存
     * - 磁盘缓存过期清理由 cache_store.ts 在读取时处理
     */
    public cleanupCaches() {
        for (const contentBinding of Object.keys(this.youtubeSessionDataCaches)) {
            const sessionData = this.youtubeSessionDataCaches[contentBinding];
            if (!sessionData) {
                continue;
            }
            if (new Date() > sessionData.expiresAt) {
                delete this.youtubeSessionDataCaches[contentBinding];
            }
        }
    }

    /**
     * 获取当前进程内的 minterCache。
     */
    public get minterCache(): MinterCache {
        return this._minterCache;
    }

    /**
     * 获取并解扰 BotGuard challenge。
     *
     * challenge 来源有两种：
     * 1. 若调用方已传 challenge，则直接使用
     * 2. 否则通过 /att/get 获取
     * 3. 然后下载 interpreter JS，组装为 DescrambledChallenge
     */
    private async getDescrambledChallenge(
        bgConfig: BgConfig,
        challenge?: ChallengeData,
        innertubeContext?: InnertubeContext,
    ): Promise<DescrambledChallenge> {
        try {
            if (!challenge) {
                this.logger.debug("Using challenge from /att/get");

                const attGetResponse = await bgConfig.fetch(
                    "https://www.youtube.com/youtubei/v1/att/get?prettyPrint=false",
                    {
                        method: "POST",
                        headers: {
                            ...getHeaders(),
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify({
                            context: innertubeContext || {
                                client: {
                                    clientName: "WEB",
                                    clientVersion: "2.20260227.01.00",
                                },
                            },
                            engagementType: "ENGAGEMENT_TYPE_UNBOUND",
                        }),
                    },
                );

                const attestation = await attGetResponse.json();
                if (!attestation) {
                    throw new Error("Failed to get challenge from /att/get");
                }

                challenge = attestation.bgChallenge as ChallengeData;
            } else {
                this.logger.debug("Using challenge from the webpage");
            }

            const {program, globalName, interpreterHash} = challenge;
            const {privateDoNotAccessOrElseTrustedResourceUrlWrappedValue} =
                challenge.interpreterUrl;

            const interpreterJSResponse = await bgConfig.fetch(
                `https:${privateDoNotAccessOrElseTrustedResourceUrlWrappedValue}`,
            );
            const interpreterJS = await interpreterJSResponse.text();

            return {
                program,
                globalName,
                interpreterHash,
                interpreterJavascript: {
                    privateDoNotAccessOrElseSafeScriptWrappedValue:
                    interpreterJS,
                    privateDoNotAccessOrElseTrustedResourceUrlWrappedValue,
                },
            };
        } catch (e) {
            throw new Error("Could not get BotGuard challenge", {cause: e});
        }
    }

    /**
     * 生成 TokenMinter，并写入当前进程内 _minterCache。
     *
     * 说明：
     * - 这是“进程内 minter 缓存”层
     * - 与磁盘层的“最终 POT 缓存”不是一回事
     */
    private async generateTokenMinter(
        cacheSpec: CacheSpec,
        bgConfig: BgConfig,
        challenge?: ChallengeData,
        innertubeContext?: InnertubeContext,
    ): Promise<TokenMinter> {
        const descrambledChallenge = await this.getDescrambledChallenge(
            bgConfig,
            challenge,
            innertubeContext,
        );

        const {program, globalName} = descrambledChallenge;
        const interpreterJavascript =
            descrambledChallenge.interpreterJavascript
                .privateDoNotAccessOrElseSafeScriptWrappedValue;

        if (interpreterJavascript) {
            new Function(interpreterJavascript)();
        } else {
            throw new Error("Could not load VM");
        }

        let bgClient: BG.BotGuardClient;
        try {
            bgClient = await BG.BotGuardClient.create({
                program,
                globalName,
                globalObj: bgConfig.globalObj,
            });
        } catch (e) {
            throw new Error("Failed to create BG client.", {cause: e});
        }

        try {
            const webPoSignalOutput: WebPoSignalOutput = [];
            const botguardResponse = await bgClient.snapshot({
                webPoSignalOutput,
            });

            const integrityTokenResp = await bgConfig.fetch(
                buildURL("GenerateIT"),
                {
                    method: "POST",
                    headers: getHeaders(),
                    body: JSON.stringify([
                        SessionManager.REQUEST_KEY,
                        botguardResponse,
                    ]),
                },
            );

            const [
                integrityToken,
                estimatedTtlSecs,
                mintRefreshThreshold,
                websafeFallbackToken,
            ] = (await integrityTokenResp.json()) as [
                string,
                number,
                number,
                string,
            ];

            const integrityTokenData = {
                integrityToken,
                estimatedTtlSecs,
                mintRefreshThreshold,
                websafeFallbackToken,
            };

            if (!integrityToken) {
                throw new Error(
                    `Unexpected empty integrity token, response: ${JSON.stringify(integrityTokenData)}`,
                );
            }

            this.logger.debug(
                `Generated IntegrityToken: ${JSON.stringify(integrityTokenData)}`,
            );

            const tokenMinter: TokenMinter = {
                expiry: new Date(Date.now() + estimatedTtlSecs * 1000),
                integrityToken,
                minter: await BG.WebPoMinter.create(
                    integrityTokenData,
                    webPoSignalOutput,
                ),
            };

            this._minterCache.set(cacheSpec.key, tokenMinter);
            return tokenMinter;
        } catch (e) {
            throw new Error("Failed to generate an integrity token.", {
                cause: e,
            });
        }
    }

    /**
     * 使用已有 tokenMinter 为某个 contentBinding mint POT。
     *
     * 说明：
     * - 这是“真正 mint 最终 POT”的最后一步
     * - 成功后会同步写回当前进程内 youtubeSessionDataCaches
     * - 磁盘缓存的写回由 generatePoToken 外层统一处理
     */
    private async tryMintPOT(
        contentBinding: string,
        tokenMinter: TokenMinter,
    ): Promise<YoutubeSessionData> {
        this.logger.log(`Generating POT for ${contentBinding}`);

        try {
            const poToken =
                await tokenMinter.minter.mintAsWebsafeString(contentBinding);

            if (!poToken) {
                throw new Error("Unexpected empty POT");
            }

            this.logger.log(`poToken: ${poToken}`);

            const youtubeSessionData = buildYoutubeSessionData(
                contentBinding,
                poToken,
                this.TOKEN_TTL_HOURS,
            );

            /**
             * 成功生成后，同时更新当前进程内缓存。
             *
             * 注意：
             * - 磁盘缓存写回不在这里做
             * - 磁盘缓存统一由 generatePoToken 主流程在持锁状态下写回
             */
            this.youtubeSessionDataCaches[contentBinding] = youtubeSessionData;

            return youtubeSessionData;
        } catch (e: any) {
            throw new Error(
                `Failed to mint POT for ${contentBinding}: ${e?.message}`,
                {cause: e},
            );
        }
    }

    /**
     * 判断当前是否运行在 Deno 环境。
     */
    private _isDenoRuntime(): boolean {
        return typeof (globalThis as any).Deno !== "undefined";
    }

    /**
     * 构造 Deno 下使用的 HttpClient。
     *
     * 说明：
     * - Deno 的 proxy 直接接受 url 字符串
     * - 当前未在这里进一步处理“跳过 TLS 校验”，以避免引入更多不确定性
     */
    private _getDenoHttpClient(proxySpec: ProxySpec, logger: Logger): any {
        const DenoNS = (globalThis as any).Deno;
        if (!DenoNS?.createHttpClient) {
            throw new Error(
                "Deno.createHttpClient is not available in this runtime",
            );
        }

        // 这里模仿 asDispatcher，也打印一次代理信息
        const proxyUrl = proxySpec.proxy;
        if (proxyUrl) {
            try {
                const parsed = new URL(proxyUrl);
                const loggedProxy = parsed.password
                    ? proxyUrl.replace(parsed.password, "****")
                    : proxyUrl;
                logger.log(`Using proxy: ${loggedProxy}`);
            } catch {
                logger.log(`Using proxy: ${proxyUrl}`);
            }
        }

        // Deno 的 proxy 直接用 string（http://user:pass@host:port）
        return DenoNS.createHttpClient({
            proxy: proxySpec.proxy ? {url: proxySpec.proxy} : undefined,
            // 语义对齐：disableTlsVerification=true => 不校验证书
            // Deno 里是 `caCerts` / `cert` / `key` 之类更细项；最简单做法：
            // 如果你需要“跳过证书校验”，建议在代理侧保证证书正确，或者只用于 https proxy。
            // 目前先不额外配置（否则会引入更多不确定性）。
        });
    }

    /**
     * 对 headers 做规范化：
     * - 支持普通对象 / Headers
     * - key 统一转小写
     * - 同名 key 后写覆盖前写
     *
     * 主要用于修复 Deno fetch 下大小写不同但语义相同的 header 冲突问题。
     */
    private normalizeHeaders(input: any): Headers {
        const h = new Headers();

        // 支持 input 是普通对象 或 Headers
        const entries: Array<[string, string]> = [];
        if (input instanceof Headers) {
            input.forEach((v, k) => entries.push([k, v]));
        } else if (input && typeof input === "object") {
            for (const [k, v] of Object.entries(input)) {
                if (v === undefined || v === null) continue;
                entries.push([k, String(v)]);
            }
        }

        // key 统一小写，后写覆盖前写（同名只留一个）
        const m = new Map<string, string>();
        for (const [k, v] of entries) {
            m.set(k.toLowerCase(), v);
        }

        for (const [k, v] of m.entries()) {
            h.set(k, v);
        }

        return h;
    }

    /**
     * 将 options.params 追加到 URL 上。
     *
     * 说明：
     * - 支持 string / URL 输入
     * - 支持 params 为对象 / query string
     * - 支持数组值展开
     */
    private applyParamsToUrl(inputUrl: any, params: any): string {
        // params 为空直接返回原 url
        if (
            !params ||
            (typeof params === "object" && Object.keys(params).length === 0)
        ) {
            return String(inputUrl);
        }

        // 把 inputUrl 变成可操作的 URL（支持 string / URL）
        // 注意：如果 inputUrl 可能是相对路径，需要给 base；你这里基本都是 https://...，所以够用
        const u =
            inputUrl instanceof URL
                ? new URL(inputUrl.toString())
                : new URL(String(inputUrl));

        const appendOne = (k: string, v: any) => {
            if (v === undefined || v === null) return;
            if (Array.isArray(v)) {
                for (const it of v) appendOne(k, it);
                return;
            }
            u.searchParams.append(k, String(v));
        };

        if (typeof params === "object") {
            for (const [k, v] of Object.entries(params)) {
                appendOne(k, v);
            }
        } else {
            // 兜底：如果 params 不是对象（不太可能），直接当字符串拼进去
            // 例如 params="a=1&b=2"
            const s = String(params);
            if (s) {
                const sp = new URLSearchParams(
                    s.startsWith("?") ? s.slice(1) : s,
                );
                sp.forEach((v, k) => u.searchParams.append(k, v));
            }
        }

        return u.toString();
    }

    /**
     * 判断当前请求是否应该启用主动超时。
     *
     * 规则：
     * - BGUTIL_FETCH_TIMEOUT_MS <= 0：不启用；
     * - BGUTIL_FETCH_TIMEOUT_ONLY_WHEN_PROXY=false：所有请求都启用；
     * - BGUTIL_FETCH_TIMEOUT_ONLY_WHEN_PROXY=true：只有存在代理时才启用。
     */
    private shouldApplyFetchTimeout(proxySpec: ProxySpec): boolean {
        if (BGUTIL_RUNTIME_CONFIG.fetchTimeoutMs <= 0) {
            return false;
        }

        if (!BGUTIL_RUNTIME_CONFIG.fetchTimeoutOnlyWhenProxy) {
            return true;
        }

        return !!proxySpec.proxy;
    }

    /**
     * 构造 AbortController，并在 timeoutMs 后主动 abort。
     *
     * 说明：
     * - 主要用于 Deno fetch；
     * - Node axios 使用自身的 timeout 参数即可；
     * - 这里返回 controller 和 cleanup，调用方必须在 finally 中 cleanup，
     *   避免 setTimeout 泄漏。
     */
    private buildAbortControllerForTimeout(
        timeoutMs: number,
    ): {
        controller: AbortController;
        cleanup: () => void;
    } {
        const controller = new AbortController();

        const timer = setTimeout(() => {
            controller.abort();
        }, timeoutMs);

        return {
            controller,
            cleanup: () => clearTimeout(timer),
        };
    }

    /**
     * 将异常转成尽量可读的日志字符串。
     *
     * 说明：
     * - axios error / DOMException / 普通 Error 的字段不完全一致；
     * - 这里统一做一层兜底，便于日志定位。
     */
    private errorToLogString(e: unknown): string {
        if (e instanceof Error) {
            const anyError = e as any;

            return this.safeStringify({
                name: e.name,
                message: e.message,
                code: anyError.code,
                status: anyError.response?.status,
                statusText: anyError.response?.statusText,
            });
        }

        return this.safeStringify(e);
    }

    /**
     * 构造统一 fetch。
     *
     * 说明：
     * - Deno 路径：原生 fetch + createHttpClient；
     * - Node 路径：axios + httpsAgent / ProxyAgent；
     * - 带重试机制；
     * - 支持请求级超时，避免代理 / YouTube 请求无限等待。
     *
     * 重要说明：
     * - 这里的 timeout 是“单次请求 timeout”，不是整个 POT 生成流程 timeout；
     * - 外层 Python plugin 仍然有 300 秒总超时；
     * - 单次请求 timeout 建议明显小于 300 秒，例如 30 秒；
     * - 如果一次请求 timeout，会进入 retry；
     * - 全部 retry 失败后抛异常，由 generatePoToken 外层处理。
     */
    private getFetch(
        proxySpec: ProxySpec,
        maxRetries: number,
        intervalMs: number,
    ): FetchFunction {
        const {logger} = this;

        return async (url: any, options: any): Promise<Response> => {
            const method = (options?.method || "GET").toUpperCase();

            const timeoutEnabled = this.shouldApplyFetchTimeout(proxySpec);
            const timeoutMs = BGUTIL_RUNTIME_CONFIG.fetchTimeoutMs;

            for (let attempts = 1; attempts <= maxRetries; attempts++) {
                const requestStartedAt = Date.now();

                try {
                    logger.debug(
                        `[fetch] begin ` +
                        this.safeStringify({
                            method,
                            url: String(url),
                            attempt: attempts,
                            maxRetries,
                            timeoutEnabled,
                            timeoutMs: timeoutEnabled ? timeoutMs : 0,
                            hasProxy: !!proxySpec.proxy,
                        }),
                    );

                    /**
                     * ====== Deno 路径：createHttpClient + 原生 fetch ======
                     *
                     * 注意：
                     * - Deno fetch 自身不使用 axios；
                     * - 因此需要通过 AbortController 实现请求超时；
                     * - 超时时会抛 AbortError；
                     * - catch 后会走统一重试逻辑。
                     */
                    if (this._isDenoRuntime()) {
                        const client = this._getDenoHttpClient(proxySpec, logger);
                        const finalUrl = this.applyParamsToUrl(url, options?.params);

                        /**
                         * 由于 Deno 的 fetch 请求，针对 header 中重复且大小写不同的
                         * Content-Type 参数，无法正常覆盖，可能导致服务端解析失败。
                         *
                         * 这里通过 normalizeHeaders 做小写 + 去重：
                         * - content-type
                         * - Content-Type
                         *
                         * 最终只保留一个语义 header。
                         */
                        const headers = this.normalizeHeaders(options?.headers);

                        const timeoutCtx = timeoutEnabled
                            ? this.buildAbortControllerForTimeout(timeoutMs)
                            : undefined;

                        try {
                            const resp = await fetch(finalUrl, {
                                method,
                                headers,
                                body: options?.body,

                                /**
                                 * Deno 扩展字段。
                                 *
                                 * 说明：
                                 * - 在 Deno 环境下有效；
                                 * - Node 类型系统不认识，所以这里保持 as any。
                                 */
                                client,

                                /**
                                 * 标准 AbortController signal。
                                 *
                                 * 说明：
                                 * - timeoutEnabled=false 时不传；
                                 * - timeoutEnabled=true 时，超过 timeoutMs 会触发 abort。
                                 */
                                signal: timeoutCtx?.controller.signal,
                            } as any);

                            logger.debug(
                                `[fetch] done ` +
                                this.safeStringify({
                                    method,
                                    url: String(finalUrl),
                                    attempt: attempts,
                                    status: resp.status,
                                    costMs: Date.now() - requestStartedAt,
                                }),
                            );

                            return resp;
                        } finally {
                            timeoutCtx?.cleanup();
                        }
                    }

                    /**
                     * ====== Node 路径：axios + httpsAgent / ProxyAgent ======
                     *
                     * 重点修改：
                     * - 原来 axiosOpt 没有 timeout；
                     * - 代理/TLS/Google 请求如果半开，可能一直不返回；
                     * - 现在通过 timeout 避免单个请求无限等待。
                     */
                    const axiosOpt: AxiosRequestConfig = {
                        headers: options?.headers,
                        params: options?.params,

                        /**
                         * 代理 / 本地源地址 / TLS 校验由 ProxySpec 统一处理。
                         */
                        httpsAgent: proxySpec.asDispatcher(logger),

                        /**
                         * 单次请求 timeout。
                         *
                         * 注意：
                         * - axios timeout 单位是毫秒；
                         * - 0 表示不设置 timeout；
                         * - 这里 timeoutEnabled=false 时传 undefined，保持 axios 默认行为。
                         */
                        timeout: timeoutEnabled ? timeoutMs : undefined,

                        /**
                         * 避免 axios 因 4xx/5xx 自动 throw 后丢失 response body。
                         *
                         * 说明：
                         * - bgutils-js 的 fetch 语义更接近标准 fetch；
                         * - 标准 fetch 对 4xx/5xx 不会 throw；
                         * - 这里返回 response，由上层根据 body/status 判断。
                         */
                        validateStatus: () => true,
                    };

                    const response =
                        method === "GET"
                            ? await axios.get(url, axiosOpt)
                            : await axios.post(url, options?.body, axiosOpt);

                    logger.debug(
                        `[fetch] done ` +
                        this.safeStringify({
                            method,
                            url: String(url),
                            attempt: attempts,
                            status: response.status,
                            costMs: Date.now() - requestStartedAt,
                        }),
                    );

                    /**
                     * 将 axios response 包装成近似标准 Response 的对象。
                     *
                     * 说明：
                     * - bgutils-js 这里只需要 json()/text()/status/ok 这一类能力；
                     * - 保持和原有代码兼容。
                     */
                    return {
                        ok: response.status >= 200 && response.status < 300,
                        status: response.status,
                        json: async () => response.data,
                        text: async () =>
                            typeof response.data === "string"
                                ? response.data
                                : JSON.stringify(response.data),
                    } as Response;
                } catch (e) {
                    const costMs = Date.now() - requestStartedAt;

                    logger.warn(
                        `[fetch] failed ` +
                        this.safeStringify({
                            method,
                            url: String(url),
                            attempt: attempts,
                            maxRetries,
                            costMs,
                            timeoutEnabled,
                            timeoutMs: timeoutEnabled ? timeoutMs : 0,
                            hasProxy: !!proxySpec.proxy,
                            error: this.errorToLogString(e),
                        }),
                    );

                    if (attempts >= maxRetries) {
                        throw new Error(
                            `Error reaching ${method} ${url}: All ${attempts} retries failed.`,
                            {cause: e},
                        );
                    }

                    await new Promise((resolve) => setTimeout(resolve, intervalMs));
                }
            }

            throw new Error(
                `Error reaching ${method} ${url}: unexpected retry loop exit.`,
            );
        };
    }

    /**
     * 统一生成一次调用的 traceId，方便日志 grep / 对比。
     */
    private buildTraceId(): string {
        return `pot-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    }

    /**
     * 安全 stringify：避免循环引用导致日志打印崩掉。
     */
    private safeStringify(v: any): string {
        try {
            return JSON.stringify(v);
        } catch {
            return `[Unserializable:${typeof v}]`;
        }
    }

    /**
     * 对大字段做摘要，便于日志查看。
     *
     * 常见大字段：
     * - challenge
     * - innertubeContext
     */
    private summarizeForLog(v: any, limit = 500) {
        if (v === undefined) return {type: "undefined"};
        if (v === null) return {type: "null"};

        const t = typeof v;
        if (t === "string") {
            const s = v as string;
            return {
                type: "string",
                length: s.length,
                preview:
                    s.length > limit
                        ? `${s.slice(0, limit)} ...<truncated>`
                        : s,
            };
        }

        const s = this.safeStringify(v);
        return {
            type: Array.isArray(v) ? "array" : t,
            jsonLength: s.length,
            preview:
                s.length > limit ? `${s.slice(0, limit)} ...<truncated>` : s,
        };
    }

    /**
     * 生成或读取一个 POT。
     *
     * 当前整体流程：
     *
     * 1. 参数整理
     * 2. 清理当前进程内过期缓存
     * 3. 构建 ProxySpec / CacheSpec / BgConfig
     * 4. 解析最终 contentBinding
     * 5. 基于最终 contentBinding 获取“单 key 锁”
     * 6. 锁内优先查磁盘缓存（跨进程共享）
     * 7. 磁盘缓存 miss 后，再查当前进程内缓存：
     *    - youtubeSessionDataCaches
     *    - _minterCache
     * 8. 进入资源门禁
     * 9. 仍 miss 时，再真正生成 minter 与 poToken
     * 10. 成功后写回磁盘缓存
     *
     * 这样 script / http 两条链路最终都统一复用这一个入口。
     */
    async generatePoToken(
        contentBinding: string | undefined,
        proxy: string = "",
        bypassCache = false,
        sourceAddress: string | undefined = undefined,
        disableTlsVerification: boolean = false,
        challenge: ChallengeData | undefined = undefined,
        innertubeContext?: InnertubeContext,
    ): Promise<YoutubeSessionData> {
        const traceId = this.buildTraceId();

        /**
         * =========================
         * 入口打印：原始入参快照
         * =========================
         * 注意：
         * - 这里打印的是“调用方传入的原始值”
         * - proxy 为空字符串时，后面会 fallback 到环境变量，因此这里要把 env 候选一起打印
         */
        const envProxy =
            process.env.HTTPS_PROXY ||
            process.env.HTTP_PROXY ||
            process.env.ALL_PROXY ||
            "";

        this.logger.log(
            `[${traceId}] generatePoToken:enter ` +
            this.safeStringify({
                content_binding: contentBinding ?? "",
                proxy_arg: proxy ?? "",
                proxy_env_candidate: envProxy,
                bypass_cache: !!bypassCache,
                source_address: sourceAddress ?? "",
                disable_tls_verification: !!disableTlsVerification,
                challenge: this.summarizeForLog(challenge),
                innertube_context: this.summarizeForLog(innertubeContext),
            }),
        );

        /**
         * =========================
         * 清理当前进程内过期缓存
         * =========================
         *
         * 注意：
         * - 这里只清理进程内 youtubeSessionDataCaches
         * - 不清理磁盘缓存
         */
        this.cleanupCaches();

        /**
         * =========================
         * ProxySpec 构建 & 最终代理选择
         * =========================
         */
        const pxySpec = new ProxySpec({
            sourceAddress,
            disableTlsVerification,
        });

        if (proxy) {
            pxySpec.proxy = proxy;
            this.logger.log(
                `[${traceId}] generatePoToken:proxy_selected from_arg ` +
                this.safeStringify({proxy_selected: pxySpec.proxy}),
            );
        } else {
            pxySpec.proxy =
                process.env.HTTPS_PROXY ||
                process.env.HTTP_PROXY ||
                process.env.ALL_PROXY;

            this.logger.log(
                `[${traceId}] generatePoToken:proxy_selected from_env ` +
                this.safeStringify({
                    proxy_selected: pxySpec.proxy ?? "",
                }),
            );
        }

        /**
         * =========================
         * BgConfig / contentBinding 解析
         * =========================
         *
         * 注意：
         * - 单 key 锁必须建立在“最终 contentBinding 已知”的前提下
         * - 因此这里先把 contentBinding 解析完整
         */
        const bgFetch = this.getFetch(pxySpec, 3, 5000);
        let innertube: Innertube | undefined = undefined;

        if (!contentBinding && innertubeContext) {
            this.logger.warn(
                "No content binding provided, using the one from the supplied Innertube context...",
            );
            contentBinding = innertubeContext.client.visitorData;
        }

        if (!contentBinding) {
            this.logger.warn(
                "No content binding provided, generating visitor data via Innertube...",
            );
            innertube = await Innertube.create({
                retrieve_player: false,
                fetch: bgFetch,
            });
            contentBinding = innertube.session.context.client.visitorData;
        }

        if (!contentBinding) {
            throw new Error("Unable to generate visitor data");
        }

        if (!innertubeContext) {
            innertubeContext = innertube?.session.context;
        }

        /**
         * 走到这里时，最终的 contentBinding 已经确定。
         *
         * 后续所有：
         * - 单 key 锁
         * - 磁盘缓存
         * - 进程内缓存
         * - 真正生成
         *
         * 都统一基于这个 resolvedContentBinding 进行。
         */
        const resolvedContentBinding = contentBinding;

        /**
         * =========================
         * CacheSpec 构建
         * =========================
         *
         * 说明：
         * - 这是 minterCache 的 key 维度
         * - 与磁盘 POT 缓存按 contentBinding 存，不是同一层级
         */
        const cacheSpec = new CacheSpec(
            pxySpec,
            innertubeContext?.client.remoteHost || null,
        );

        this.logger.log(
            `[${traceId}] generatePoToken:cacheSpec ` +
            this.safeStringify({
                remoteHost: innertubeContext?.client.remoteHost || null,
                cacheKey: cacheSpec.key,
                cachedir: this.cachedir,
            }),
        );

        const bgConfig: BgConfig = {
            fetch: bgFetch,
            globalObj: globalThis,
            identifier: resolvedContentBinding,
            requestKey: SessionManager.REQUEST_KEY,
        };

        this.logger.log(
            `[${traceId}] generatePoToken:bgConfig_ready ` +
            this.safeStringify({
                identifier: bgConfig.identifier,
                requestKey: bgConfig.requestKey,
            }),
        );

        /**
         * =========================
         * 单 key 锁：以 resolvedContentBinding 为粒度
         * =========================
         *
         * 原始设计目标：
         * - 相同 contentBinding 串行，避免并发重复 mint；
         * - 不同 contentBinding 并发，不互相阻塞；
         * - 后来的请求能读取前一个请求刚写入的磁盘缓存。
         *
         * 新增配置：
         * - BGUTIL_DISABLE_CACHE_LOCK=1 时，跳过该目录锁；
         * - 跳过锁后可以避免 stale lock / 等锁导致 generate_once.js 卡住；
         * - 代价是相同 contentBinding 可能被多个进程重复生成。
         */
        const generateWithinOptionalLock = async (): Promise<YoutubeSessionData> => {
            /**
             * ================================================================
             * Step 1. 先查单 key 磁盘缓存（跨进程共享）
             * ================================================================
             *
             * 注意：
             * - 即使禁用目录锁，也仍然可以查磁盘缓存；
             * - 禁用目录锁只是不再串行化；
             * - 读取缓存本身是轻量动作，仍有价值。
             */
            if (!bypassCache) {
                const diskCached = getYoutubeSessionDataLocked(
                    this.cachedir,
                    resolvedContentBinding,
                    true,
                );

                if (diskCached) {
                    this.logger.log(
                        `[${traceId}] generatePoToken:hit_disk_cache -> return_cached_token`,
                    );

                    /**
                     * 命中磁盘缓存后，同步写入当前进程内缓存。
                     */
                    this.youtubeSessionDataCaches[resolvedContentBinding] = diskCached;

                    return diskCached;
                }

                this.logger.log(`[${traceId}] generatePoToken:miss_disk_cache`);
            } else {
                this.logger.log(
                    `[${traceId}] generatePoToken:bypassCache=true -> skip_disk_cache`,
                );
            }

            /**
             * ================================================================
             * Step 2. 再查当前进程内 sessionData 缓存
             * ================================================================
             */
            if (!bypassCache) {
                const memoryCached = this.youtubeSessionDataCaches[resolvedContentBinding];

                if (memoryCached && new Date() <= memoryCached.expiresAt) {
                    this.logger.log(
                        `[${traceId}] generatePoToken:hit_memory_session_cache -> return_cached_token`,
                    );

                    return memoryCached;
                }

                this.logger.log(`[${traceId}] generatePoToken:miss_memory_session_cache`);
            }

            /**
             * ================================================================
             * Step 3. 进入真正高开销生成路径前，统一走资源门禁
             * ================================================================
             *
             * 注意：
             * - ResourceGate 自身也可通过 BGUTIL_DISABLE_RESOURCE_GATE=1 跳过；
             * - 只有缓存 miss 时才会走到这里。
             */
            return await this.runWithResourceGate(async () => {
                /**
                 * ============================================================
                 * Step 4. 检查当前进程内 minterCache
                 * ============================================================
                 *
                 * 说明：
                 * - minterCache 是按网络环境区分；
                 * - 不是按 contentBinding 区分；
                 * - 如果 minter 未过期，可以直接 mint 当前 contentBinding。
                 */
                const cachedMinter = this._minterCache.get(cacheSpec.key);

                let tokenMinter: TokenMinter;

                if (cachedMinter && new Date() <= cachedMinter.expiry) {
                    this.logger.log(
                        `[${traceId}] generatePoToken:hit_minter_cache -> mint_pot`,
                    );

                    tokenMinter = cachedMinter;
                } else {
                    if (cachedMinter) {
                        this.logger.log(
                            `[${traceId}] generatePoToken:expired_minter_cache -> regenerate_minter`,
                        );
                    } else {
                        this.logger.log(
                            `[${traceId}] generatePoToken:miss_minter_cache -> generate_minter`,
                        );
                    }

                    tokenMinter = await this.generateTokenMinter(
                        cacheSpec,
                        bgConfig,
                        challenge,
                        innertubeContext,
                    );
                }

                /**
                 * ============================================================
                 * Step 5. 使用 minter mint 最终 POT
                 * ============================================================
                 */
                const generatedSessionData = await this.tryMintPOT(
                    resolvedContentBinding,
                    tokenMinter,
                );

                /**
                 * ============================================================
                 * Step 6. 写回磁盘缓存
                 * ============================================================
                 *
                 * 注意：
                 * - 即使禁用了目录锁，也仍然写磁盘缓存；
                 * - 多进程同时写相同 key 的概率存在，但 saveYoutubeSessionDataUnlocked()
                 *   内部使用 “临时文件 + rename” 原子替换；
                 * - generatedSessionData 自身已经包含 contentBinding 字段，
                 *   因此 setYoutubeSessionDataLocked() 不需要额外传 resolvedContentBinding。
                 */
                if (!bypassCache) {
                    setYoutubeSessionDataLocked(
                        this.cachedir,
                        generatedSessionData,
                    );

                    this.logger.log(
                        `[${traceId}] generatePoToken:write_disk_cache_done`,
                    );
                } else {
                    this.logger.log(
                        `[${traceId}] generatePoToken:bypassCache=true -> skip_write_disk_cache`,
                    );
                }

                return generatedSessionData;
            });
        };

        if (BGUTIL_RUNTIME_CONFIG.disableCacheLock) {
            this.logger.warn(
                `[${traceId}] cache_lock disabled by BGUTIL_DISABLE_CACHE_LOCK, run without contentBinding lock`,
            );

            return await generateWithinOptionalLock();
        }

        this.logger.log(
            `[${traceId}] cache_lock waiting ` +
            this.safeStringify({
                contentBinding: resolvedContentBinding,
                cachedir: this.cachedir,
            }),
        );

        const contentBindingLock: CacheEntryLock = getCacheEntryLock(
            this.cachedir,
            resolvedContentBinding,
        );

        return await contentBindingLock.runExclusive(async () => {
            this.logger.log(
                `[${traceId}] cache_lock acquired ` +
                this.safeStringify({
                    contentBinding: resolvedContentBinding,
                }),
            );

            return await generateWithinOptionalLock();
        });
    }
}
