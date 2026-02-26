import axios, { AxiosRequestConfig } from "axios";
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
import { Agent } from "node:https";
import { ProxyAgent } from "proxy-agent";
import { JSDOM } from "jsdom";
import { Innertube, Context as InnertubeContext } from "youtubei.js";
import { strerror } from "./utils.ts";

interface YoutubeSessionData {
    poToken: string;
    contentBinding: string;
    expiresAt: Date;
}

export interface YoutubeSessionDataCaches {
    [contentBinding: string]: YoutubeSessionData;
}

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
            this.debug = this.log = () => {};
        }
        this.warn = (msg: string) => {
            console.warn(msg);
        };
        this.error = (msg: string) => {
            console.error(msg);
        };
    }
}

class ProxySpec {
    public proxyUrl?: URL;
    public sourceAddress?: string;
    public disableTlsVerification: boolean = false;
    public readonly ipFamily?: number;
    constructor({ sourceAddress, disableTlsVerification }: Partial<ProxySpec>) {
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
        if (newProxy) {
            // Normalize and sanitize the proxy URL
            try {
                this.proxyUrl = new URL(newProxy);
            } catch {
                newProxy = `http://${newProxy}`;
                try {
                    this.proxyUrl = new URL(newProxy);
                } catch (e) {
                    throw new Error(`Invalid proxy URL: ${newProxy}`, {
                        cause: e,
                    });
                }
            }
        }
    }

    public asDispatcher(
        this: Readonly<this>,
        logger: Logger,
    ): Agent | undefined {
        const { proxyUrl, sourceAddress, disableTlsVerification } = this;
        if (!proxyUrl) {
            return new Agent({
                localAddress: sourceAddress,
                family: this.ipFamily,
                rejectUnauthorized: !disableTlsVerification,
            });
        }
        // Proxy must be a string as long as the URL is truthy
        const pxyStr = this.proxy!;
        const { password } = proxyUrl;

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

class CacheSpec {
    constructor(
        public pxySpec: ProxySpec,
        public ip: string | null,
    ) {}
    public get key(): string {
        return JSON.stringify(
            this.ip || [this.pxySpec.proxy, this.pxySpec.sourceAddress],
        );
    }
}

type TokenMinter = {
    expiry: Date;
    integrityToken: string;
    minter: BG.WebPoMinter;
};

type MinterCache = Map<string, TokenMinter>;

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
    // hardcoded API key that has been used by youtube for years
    private static readonly REQUEST_KEY = "O43z0dpjhgX20SCx4KAo";
    private static hasDom = false;
    private _minterCache: MinterCache = new Map();
    private TOKEN_TTL_HOURS: number;
    private logger: Logger;

    constructor(
        shouldLog = true,
        // This needs to be reworked as POTs are IP-bound
        private youtubeSessionDataCaches?: YoutubeSessionDataCaches,
    ) {
        this.logger = new Logger(shouldLog);
        this.TOKEN_TTL_HOURS = process.env.TOKEN_TTL
            ? parseInt(process.env.TOKEN_TTL)
            : 6;
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

    public invalidateCaches() {
        this.setYoutubeSessionDataCaches();
        this._minterCache.clear();
    }

    public invalidateIT() {
        this._minterCache.forEach((minterCache) => {
            minterCache.expiry = new Date(0);
        });
    }

    public cleanupCaches() {
        for (const contentBinding in this.youtubeSessionDataCaches) {
            const sessionData = this.youtubeSessionDataCaches[contentBinding];
            if (sessionData && new Date() > sessionData.expiresAt)
                delete this.youtubeSessionDataCaches[contentBinding];
        }
    }

    public getYoutubeSessionDataCaches(cleanup = false) {
        if (cleanup) this.cleanupCaches();
        return this.youtubeSessionDataCaches;
    }

    public setYoutubeSessionDataCaches(
        youtubeSessionData?: YoutubeSessionDataCaches,
    ) {
        this.youtubeSessionDataCaches = youtubeSessionData;
    }

    public async generateVisitorData(): Promise<string | null> {
        const innertube = await Innertube.create({ retrieve_player: false });
        const visitorData = innertube.session.context.client.visitorData;
        if (!visitorData) {
            this.logger.error("Unable to generate visitor data via Innertube");
            return null;
        }

        return visitorData;
    }

    public get minterCache(): MinterCache {
        return this._minterCache;
    }

    private async getDescrambledChallenge(
        bgConfig: BgConfig,
        challenge?: ChallengeData,
        innertubeContext?: InnertubeContext,
        disableInnertube?: boolean,
    ): Promise<DescrambledChallenge> {
        try {
            if (disableInnertube) throw null;
            if (!challenge) {
                if (!innertubeContext)
                    throw new Error("Innertube context unavailable");
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
                            context: innertubeContext,
                            engagementType: "ENGAGEMENT_TYPE_UNBOUND",
                        }),
                    },
                );
                const attestation = await attGetResponse.json();
                if (!attestation)
                    throw new Error("Failed to get challenge from /att/get");
                challenge = attestation.bgChallenge as ChallengeData;
            } else {
                this.logger.debug("Using challenge from the webpage");
            }
            const { program, globalName, interpreterHash } = challenge;
            const { privateDoNotAccessOrElseTrustedResourceUrlWrappedValue } =
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
            if (e === null)
                this.logger.debug(
                    "Using the /Create endpoint as innertube challenges are disabled",
                );
            else
                this.logger.warn(
                    `Failed to get descrambled challenge from Innertube, trying the /Create endpoint. (caused by ${strerror(e)})`,
                );
            try {
                const descrambledChallenge =
                    await BG.Challenge.create(bgConfig);
                if (descrambledChallenge) return descrambledChallenge;
            } catch (eInner) {
                throw new Error(
                    `Error while attempting to retrieve BG challenge.`,
                    { cause: eInner },
                );
            }
            throw new Error("Could not get Botguard challenge");
        }
    }

    private async generateTokenMinter(
        cacheSpec: CacheSpec,
        bgConfig: BgConfig,
        challenge?: ChallengeData,
        innertubeContext?: InnertubeContext,
        disableInnertube?: boolean,
    ): Promise<TokenMinter> {
        const descrambledChallenge = await this.getDescrambledChallenge(
            bgConfig,
            challenge,
            innertubeContext,
            disableInnertube,
        );

        const { program, globalName } = descrambledChallenge;
        const interpreterJavascript =
            descrambledChallenge.interpreterJavascript
                .privateDoNotAccessOrElseSafeScriptWrappedValue;

        if (interpreterJavascript) {
            new Function(interpreterJavascript)();
        } else throw new Error("Could not load VM");

        let bgClient: BG.BotGuardClient;
        try {
            bgClient = await BG.BotGuardClient.create({
                program,
                globalName,
                globalObj: bgConfig.globalObj,
            });
        } catch (e) {
            throw new Error(`Failed to create BG client.`, { cause: e });
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

            if (!integrityToken)
                throw new Error(
                    `Unexpected empty integrity token, response: ${JSON.stringify(integrityTokenData)}`,
                );
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
            throw new Error(`Failed to generate an integrity token.`, {
                cause: e,
            });
        }
    }

    private async tryMintPOT(
        contentBinding: string,
        tokenMinter: TokenMinter,
    ): Promise<YoutubeSessionData> {
        this.logger.log(`Generating POT for ${contentBinding}`);
        try {
            const poToken =
                await tokenMinter.minter.mintAsWebsafeString(contentBinding);
            if (poToken) {
                this.logger.log(`poToken: ${poToken}`);
                const youtubeSessionData: YoutubeSessionData = {
                    contentBinding,
                    poToken,
                    expiresAt: new Date(
                        Date.now() + this.TOKEN_TTL_HOURS * 60 * 60 * 1000,
                    ),
                };
                if (this.youtubeSessionDataCaches)
                    this.youtubeSessionDataCaches[contentBinding] =
                        youtubeSessionData;
                return youtubeSessionData;
            } else throw new Error("Unexpected empty POT");
        } catch (e) {
            throw new Error(
                `Failed to mint POT for ${contentBinding}: ${e.message}`,
                { cause: e },
            );
        }
    }

    private _isDenoRuntime(): boolean {
        return typeof (globalThis as any).Deno !== "undefined";
    }

    private _getDenoHttpClient(proxySpec: ProxySpec, logger: Logger): any {
        const DenoNS = (globalThis as any).Deno;
        if (!DenoNS?.createHttpClient) {
            throw new Error("Deno.createHttpClient is not available in this runtime");
        }

        // Deno 的 proxy 直接用 string（http://user:pass@host:port）
        return DenoNS.createHttpClient({
            proxy: {url: proxySpec.proxy},
            // 语义对齐：disableTlsVerification=true => 不校验证书
            // Deno 里是 `caCerts` / `cert` / `key` 之类更细项；最简单做法：
            // 如果你需要“跳过证书校验”，建议在代理侧保证证书正确，或者只用于 https proxy。
            // 目前先不额外配置（否则会引入更多不确定性）。
        });
    }

    private applyParamsToUrl(inputUrl: any, params: any): string {
        // params 为空直接返回原 url
        if (!params || (typeof params === "object" && Object.keys(params).length === 0)) {
            return String(inputUrl);
        }

        // 把 inputUrl 变成可操作的 URL（支持 string / URL）
        // 注意：如果 inputUrl 可能是相对路径，需要给 base；你这里基本都是 https://...，所以够用
        const u = inputUrl instanceof URL ? new URL(inputUrl.toString()) : new URL(String(inputUrl));

        const appendOne = (k: string, v: any) => {
            if (v === undefined || v === null) return;
            if (Array.isArray(v)) {
                for (const it of v) appendOne(k, it);
                return;
            }
            u.searchParams.append(k, String(v));
        };

        if (typeof params === "object") {
            for (const [k, v] of Object.entries(params)) appendOne(k, v);
        } else {
            // 兜底：如果 params 不是对象（不太可能），直接当字符串拼进去
            // 例如 params="a=1&b=2"
            const s = String(params);
            if (s) {
                const sp = new URLSearchParams(s.startsWith("?") ? s.slice(1) : s);
                sp.forEach((v, k) => u.searchParams.append(k, v));
            }
        }

        return u.toString();
    }

    private getFetch(
        proxySpec: ProxySpec,
        maxRetries: number,
        intervalMs: number,
    ): FetchFunction {
        const { logger } = this;
        return async (url: any, options: any): Promise<any> => {
            const method = (options?.method || "GET").toUpperCase();
            for (let attempts = 1; attempts <= maxRetries; attempts++) {
                try {
                    // ====== Deno 路径：createHttpClient + 原生 fetch ======
                    if (this._isDenoRuntime()) {
                        const client = this._getDenoHttpClient(proxySpec, logger);
                        const finalUrl = this.applyParamsToUrl(url, options?.params);
                        const resp = await fetch(finalUrl, {
                            method,
                            headers: options?.headers,
                            body: options?.body,
                            // Deno 扩展：把 client 传给 fetch
                            client,
                        } as any);

                        return resp; // 已经是标准 Response
                    }

                    // ====== Node 路径：axios + httpsAgent，然后包装成 Response ======
                    const axiosOpt: AxiosRequestConfig = {
                        headers: options?.headers,
                        params: options?.params,
                        httpsAgent: proxySpec.asDispatcher(logger),
                    };
                    const response = await (method === "GET"
                        ? axios.get(url, axiosOpt)
                        : axios.post(url, options?.body, axiosOpt));

                    return {
                        ok: response.status >= 200 && response.status < 300,
                        status: response.status,
                        json: async () => response.data,
                        text: async () =>
                            typeof response.data === "string"
                                ? response.data
                                : JSON.stringify(response.data),
                    };
                } catch (e) {
                    if (attempts >= maxRetries)
                        throw new Error(
                            `Error reaching ${method} ${url}: All ${attempts} retries failed.`,
                            { cause: e },
                        );
                    await new Promise((resolve) =>
                        setTimeout(resolve, intervalMs),
                    );
                }
            }
        };
    }

    // 注意：当前方法是对 generatePoToken 的日志完善，并不修改原有代码逻辑
    async generatePoToken(
        contentBinding: string | undefined,
        proxy: string = "",
        bypassCache = false,
        sourceAddress: string | undefined = undefined,
        disableTlsVerification: boolean = false,
        challenge: ChallengeData | undefined = undefined,
        disableInnertube: boolean = false,
        innertubeContext?: InnertubeContext,
    ): Promise<YoutubeSessionData> {
        // 生成一次调用的 traceId，方便 grep / 对比（不要求全局唯一，但足够区分）
        const traceId =
            `pot-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

        // 安全 stringify：避免循环引用导致 console 崩
        const safeStringify = (v: any): string => {
            try {
                return JSON.stringify(v);
            } catch {
                return `[Unserializable:${typeof v}]`;
            }
        };

        /**
         * 对大字段做摘要（challenge/innertubeContext 常常特别大）
         * - type: string/object/array/undefined/null
         * - jsonLength: JSON 字符串长度（用于快速对比是否“同一份内容”）
         * - preview: 截断预览（默认 500 字符）
         */
        const summarize = (v: any, limit = 500) => {
            if (v === undefined) return {type: "undefined"};
            if (v === null) return {type: "null"};

            const t = typeof v;
            if (t === "string") {
                const s = v as string;
                return {
                    type: "string",
                    length: s.length,
                    preview: s.length > limit ? s.slice(0, limit) + " ...<truncated>" : s,
                };
            }

            const s = safeStringify(v);
            return {
                type: Array.isArray(v) ? "array" : t, // object/array/number/boolean
                jsonLength: s.length,
                preview: s.length > limit ? s.slice(0, limit) + " ...<truncated>" : s,
            };
        };

        /**
         * =========================
         * 入口打印：原始入参快照
         * =========================
         * 注意：
         * - 这里打印的是“调用方传入的原始值”
         * - proxy 为空字符串时，你后面会 fallback 到环境变量，因此这里要把 env 候选一起打印
         */
        const envProxy =
            process.env.HTTPS_PROXY || process.env.HTTP_PROXY || process.env.ALL_PROXY || "";

        this.logger.log(
            `[${traceId}] generatePoToken:enter ` +
            safeStringify({
                content_binding: contentBinding ?? "",
                proxy_arg: proxy ?? "",
                proxy_env_candidate: envProxy,
                bypass_cache: !!bypassCache,
                source_address: sourceAddress ?? "",
                disable_tls_verification: !!disableTlsVerification,
                disable_innertube: !!disableInnertube,
                challenge: summarize(challenge),
                innertube_context: summarize(innertubeContext),
            }),
        );

        /**
         * =========================
         * contentBinding 兜底逻辑
         * =========================
         */
        if (!contentBinding) {
            this.logger.log(
                `[${traceId}] generatePoToken:contentBinding_missing -> generateVisitorData via Innertube`,
            );

            this.logger.warn(
                "No content binding provided, generating visitor data via Innertube...",
            );
            const visitorData = await this.generateVisitorData();
            if (!visitorData) throw new Error("Unable to generate visitor data");
            contentBinding = visitorData;

            this.logger.log(
                `[${traceId}] generatePoToken:contentBinding_generated ` +
                safeStringify({content_binding: contentBinding}),
            );
        }

        /**
         * =========================
         * 清理缓存
         * =========================
         */
        this.cleanupCaches();

        /**
         * =========================
         * ProxySpec 构建 & 最终 proxy 选择
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
                safeStringify({proxy_selected: pxySpec.proxy}),
            );
        } else {
            pxySpec.proxy =
                process.env.HTTPS_PROXY || process.env.HTTP_PROXY || process.env.ALL_PROXY;

            this.logger.log(
                `[${traceId}] generatePoToken:proxy_selected from_env ` +
                safeStringify({proxy_selected: pxySpec.proxy ?? ""}),
            );
        }

        /**
         * =========================
         * CacheSpec 构建（也会影响 key / 缓存命中）
         * =========================
         * 注意：
         * - cacheSpec 的 key 如果不同，会导致一边走缓存/复用 minter，另一边重新生成
         * - remoteHost 缺失/不同也会影响 key
         */
        const remoteHost = innertubeContext?.client?.remoteHost || null;

        const cacheSpec = new CacheSpec(pxySpec, remoteHost);

        this.logger.log(
            `[${traceId}] generatePoToken:cacheSpec ` +
            safeStringify({
                remoteHost: remoteHost ?? "",
                cacheKey: (cacheSpec as any)?.key ?? "<no_key_field>",
            }),
        );

        /**
         * =========================
         * BgConfig
         * =========================
         */
        const bgConfig: BgConfig = {
            fetch: this.getFetch(pxySpec, 3, 5000),
            globalObj: globalThis,
            identifier: contentBinding,
            requestKey: SessionManager.REQUEST_KEY,
        };

        this.logger.log(
            `[${traceId}] generatePoToken:bgConfig_ready ` +
            safeStringify({
                identifier: bgConfig.identifier,
                requestKey: bgConfig.requestKey,
            }),
        );

        /**
         * =========================
         * 缓存分支
         * =========================
         */
        if (!bypassCache) {
            // 1) JSON cache（youtubeSessionDataCaches）
            if (this.youtubeSessionDataCaches) {
                const sessionData = this.youtubeSessionDataCaches[contentBinding];
                if (sessionData) {
                    this.logger.log(
                        `[${traceId}] generatePoToken:hit_youtubeSessionDataCaches -> return_cached_token`,
                    );

                    this.logger.log(
                        `POT for ${contentBinding} still fresh, returning cached token`,
                    );
                    return sessionData;
                } else {
                    this.logger.log(
                        `[${traceId}] generatePoToken:miss_youtubeSessionDataCaches`,
                    );
                }
            } else {
                this.logger.log(
                    `[${traceId}] generatePoToken:youtubeSessionDataCaches_absent`,
                );
            }

            // 2) _minterCache（按 cacheSpec.key）
            let tokenMinter = this._minterCache.get(cacheSpec.key);
            if (tokenMinter) {
                this.logger.log(
                    `[${traceId}] generatePoToken:hit_minterCache ` +
                    safeStringify({
                        minter_expiry: (tokenMinter as any)?.expiry
                            ? String((tokenMinter as any).expiry)
                            : "<no_expiry>",
                    }),
                );

                // Replace minter if expired
                if (new Date() >= tokenMinter.expiry) {
                    this.logger.log(
                        `[${traceId}] generatePoToken:minter_expired -> regenerate_tokenMinter`,
                    );

                    this.logger.log("POT minter expired, getting a new one");
                    tokenMinter = await this.generateTokenMinter(
                        cacheSpec,
                        bgConfig,
                        challenge,
                        innertubeContext,
                        disableInnertube,
                    );
                } else {
                    this.logger.log(
                        `[${traceId}] generatePoToken:minter_fresh -> reuse_tokenMinter`,
                    );
                }

                this.logger.log(
                    `[${traceId}] generatePoToken:tryMintPOT(using_cached_or_refreshed_minter)`,
                );
                return await this.tryMintPOT(contentBinding, tokenMinter);
            } else {
                this.logger.log(`[${traceId}] generatePoToken:miss_minterCache`);
            }
        } else {
            this.logger.log(`[${traceId}] generatePoToken:bypassCache=true`);
        }

        /**
         * =========================
         * 走到这里：一定会生成新的 tokenMinter
         * =========================
         */
        this.logger.log(
            `[${traceId}] generatePoToken:generateTokenMinter ` +
            safeStringify({
                disable_innertube: !!disableInnertube,
                challenge: summarize(challenge), // 再打一次摘要，确认进入 minter 时的 challenge 状态
                innertube_context: summarize(innertubeContext),
            }),
        );

        const tokenMinter = await this.generateTokenMinter(
            cacheSpec,
            bgConfig,
            challenge,
            innertubeContext,
            disableInnertube,
        );

        this.logger.log(`[${traceId}] generatePoToken:tryMintPOT(new_minter)`);

        const result = await this.tryMintPOT(contentBinding, tokenMinter);

        this.logger.log(
            `[${traceId}] generatePoToken:done ` +
            safeStringify({
                poToken: (result as any)?.poToken ? (result as any).poToken : "",
                expiresAt: (result as any)?.expiresAt ? String((result as any).expiresAt) : "",
            }),
        );

        return result;
    }
}
