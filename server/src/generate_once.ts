import { SessionManager } from "./session_manager.ts";
import { VERSION } from "./utils.ts";
import { Command } from "commander";

/**
 * =========================
 * stdin / JSON 工具函数
 * =========================
 */

/**
 * 读取 stdin 全部内容（UTF-8），用于承载大 JSON payload。
 *
 * 设计原因：
 * - 这样可以绕过 Windows CreateProcess 206（命令行过长）限制；
 * - 也能让 script 模式与 http 模式在入参结构上尽量保持一致。
 *
 * 注意：
 * - 当由 Python provider 通过 stdin 喂数据时，stdin 会被自动关闭，因此这里会正常返回；
 * - 如果你手动执行 `node xxx.js --stdin-json`，需要确保管道最终结束（EOF），否则会一直等待。
 */
async function readAllStdin(): Promise<string> {
    return await new Promise((resolve, reject) => {
        let data = "";
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", (chunk) => (data += chunk));
        process.stdin.on("end", () => resolve(data));
        process.stdin.on("error", reject);
    });
}

/**
 * 安全 JSON.parse：失败时返回 undefined（而不是抛异常），便于容错。
 */
function safeJsonParse<T = any>(s?: string): T | undefined {
    if (!s) return undefined;
    try {
        return JSON.parse(s) as T;
    } catch {
        return undefined;
    }
}

/**
 * 把 CLI 的 challenge 字符串转换成对象。
 *
 * 逻辑：
 * - 如果是 JSON 字符串，优先 JSON.parse
 * - 如果不是合法 JSON，则返回 undefined
 *
 * 说明：
 * - 当前正常情况下，Python 侧传入的是 challenge 对象（JSON），
 *   因此这里本质上就是做一层安全 parse。
 */
function normalizeChallengeFromCli(ch?: string): any | undefined {
    if (!ch) return undefined;
    const obj = safeJsonParse<any>(ch);
    if (obj && typeof obj === "object") return obj;

    // 若未来你改成传纯字符串，可按需启用包装逻辑
    // return { bgChallenge: ch };
    return undefined;
}

/**
 * innertube_context 本质是 JSON 对象，直接 parse 即可。
 */
function normalizeInnertubeContextFromCli(s?: string): any | undefined {
    return safeJsonParse<any>(s);
}

/**
 * =========================
 * stdin payload 类型定义（与 Python provider 对齐）
 * =========================
 */
type StdinPayload = {
    bypass_cache?: boolean;
    challenge?: any;
    content_binding?: string;
    disable_innertube?: boolean;
    disable_tls_verification?: boolean;
    proxy?: string;
    innertube_context?: any;
    source_address?: string;
};

const program = new Command()
    .option("-c, --content-binding <content-binding>")
    .option("-v, --visitor-data <visitordata>") // to be removed in a future version
    .option("-d, --data-sync-id <data-sync-id>") // to be removed in a future version
    .option("-p, --proxy <proxy-all>")
    .option("-b, --bypass-cache")
    .option("-s, --source-address <source-address>")
    .option("--innertube-context <innertube-context>")
    .option("--disable-tls-verification")
    .option("--version")
    .option("--verbose")

    // ===== 兼容 CLI 模式 =====
    .option(
        "--challenge <challenge>",
        "Challenge JSON string (legacy CLI mode)",
    )

    // ===== stdin-json 模式 =====
    .option(
        "--stdin-json",
        "Read all options as JSON from stdin (recommended on Windows to avoid argv length limits)",
    )

    .exitOverride();

try {
    program.parse();
} catch (err: any) {
    if (err.code === "commander.unknownOption") {
        console.log();
        program.outputHelp();
    }
}

const options = program.opts();

(async () => {
    if (options.version) {
        console.log(VERSION);
        process.exit(0);
    }

    if (options.dataSyncId) {
        console.error(
            "Data sync id is deprecated, use --content-binding instead",
        );
        process.exit(1);
    }

    if (options.visitorData) {
        console.error(
            "Visitor data is deprecated, use --content-binding instead",
        );
        process.exit(1);
    }

    const verbose = options.verbose || false;

    /**
     * SessionManager 现在已经内部统一处理：
     * - 默认 cachedir 计算
     * - 单 key 锁
     * - 单 key 磁盘缓存
     * - 当前进程内缓存
     *
     * 因此 generate_once.ts 不再自己读取 / 写入 cache.json，
     * 也不再需要自己预加载 YoutubeSessionDataCaches。
     */
    const sessionManager = new SessionManager(verbose);

    /**
     * ==============
     * 统一参数入口（stdin-json 优先）
     * ==============
     *
     * 注意 disable_tls_verification 的语义：
     * - true  表示“禁用 TLS 校验”
     * - false 表示“正常校验 TLS”
     *
     * 这一点要与 Python provider 的 payload 保持一致。
     */
    let contentBinding: string | undefined = options.contentBinding;
    let proxy: string = options.proxy || "";
    let bypassCache: boolean = !!options.bypassCache;
    let sourceAddress: string | undefined = options.sourceAddress;
    let disableTlsVerification: boolean = !!options.disableTlsVerification;

    // 这两个对象通常很大（尤其 challenge），stdin-json 模式下直接从 payload 拿
    let challengeObj: any | undefined;
    let innertubeContextObj: any | undefined;

    if (options.stdinJson) {
        const raw = await readAllStdin();
        const payload = safeJsonParse<StdinPayload>(raw);

        if (!payload) {
            console.error("Invalid stdin JSON payload");
            console.log(JSON.stringify({}));
            process.exit(1);
        }

        // payload 优先级最高
        contentBinding = payload.content_binding ?? contentBinding;
        proxy = payload.proxy ?? proxy;
        bypassCache = payload.bypass_cache ?? bypassCache;
        sourceAddress = payload.source_address ?? sourceAddress;
        disableTlsVerification =
            payload.disable_tls_verification ?? disableTlsVerification;

        challengeObj = payload.challenge;
        innertubeContextObj = payload.innertube_context;
    } else {
        // 兼容 CLI 模式：从命令行参数解析 JSON
        challengeObj = normalizeChallengeFromCli(options.challenge);
        innertubeContextObj = normalizeInnertubeContextFromCli(
            options.innertubeContext,
        );
    }

    /**
     * contentBinding 可以为空传给 SessionManager。
     *
     * 原因：
     * - SessionManager 内部已经支持：
     *   1. 从 innertubeContext.client.visitorData 补
     *   2. 若仍没有，则通过 Innertube.create() 生成
     *
     * 因此这里不再强制要求 generate_once.ts 自己先校验 contentBinding 必须存在。
     * 只要 SessionManager 最终也无法推导出 contentBinding，它会在内部报错。
     */

    try {
        const sessionData = await sessionManager.generatePoToken(
            contentBinding,
            proxy,
            bypassCache,
            sourceAddress,
            disableTlsVerification,
            // 官方使用 script 模式 时，默认配置 这里的 challenge 参数为 undefined，这点与 http 模式不一致。
            // 我猜测是 challenge 内容过大，通过 官方 使用的 传统 shell 参数传递方案 无法传递，
            // 而我这里改版 shell 参数传递方案为 stdin 方案，解决了这个问题，因而这里就可以跟 http 模式参数一致，直接通过参数传入 challenge。
            // 由此产生的好处是，因为通过参数传入了 challenge 内容，因而无需在通过 /att/get 接口再次请求，节省 pot 生成时间。
            // 关于 challenge 的 /att/get 接口请求，参考 session_manager.ts 中的 getDescrambledChallenge 方法，
            // 通过对源码分析，确定了对应 challenge 获取逻辑为：若不通过参数传递，则会通过请求 /att/get 接口，获取 challenge，
            // 需要注意的是，challenge 是必须要获取的，否则无法生成 pot，并抛出异常 Could not get BotGuard challenge。
            // 若打开日志，则会明确打印 challenge 来源，如：Using challenge from /att/get 或 Using challenge from the webpage。
            challengeObj,
            innertubeContextObj,
        );

        /**
         * 约定：
         * - stdout 最后一行输出 JSON
         * - Python provider 侧会把最后一行作为 JSON 响应解析
         */
        console.log(JSON.stringify(sessionData));
    } catch (e: any) {
        console.error(
            `Failed while generating POT. err.name = ${e?.name}. err.message = ${e?.message}. err.stack = ${e?.stack}`,
        );
        console.log(JSON.stringify({}));
        process.exit(1);
    }
})();