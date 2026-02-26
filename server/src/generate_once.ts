import { SessionManager, YoutubeSessionDataCaches } from "./session_manager.ts";
import { VERSION } from "./utils.ts";
import { Command } from "commander";
import * as fs from "node:fs";
import * as path from "node:path";

/**
 * =========================
 * stdin / JSON 工具函数
 * =========================
 */

/**
 * 读取 stdin 全部内容（UTF-8），用于承载大 JSON payload。
 * 这样可以绕过 Windows CreateProcess 206（命令行过长）限制。
 *
 * 注意：
 * - 当由 Python provider 通过 stdin 喂数据时，stdin 会被自动关闭，因此这里会正常返回。
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
 * 把 CLI 的 challenge 字符串转换成对象：
 * - 如果是 JSON 字符串，优先 JSON.parse
 * - 如果是纯字符串（未来可能出现），可以按需包装
 *
 * 当前正常情况下：Python 侧会传 challenge 对象（JSON），因此这里基本就是 JSON.parse。
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

// Follow XDG Base Directory Specification: https://specifications.freedesktop.org/basedir-spec/latest/
let cachedir;
const homeDirectory = process.env.HOME || process.env.USERPROFILE;
const { XDG_CACHE_HOME } = process.env;
if (XDG_CACHE_HOME !== undefined) {
    cachedir = path.resolve(XDG_CACHE_HOME, "bgutil-ytdlp-pot-provider");
} else if (homeDirectory) {
    cachedir = path.resolve(
        homeDirectory,
        ".cache",
        "bgutil-ytdlp-pot-provider",
    );
} else {
    // fall back to a known path if environment variables are not found
    cachedir = path.resolve(import.meta.dirname, "..");
}
if (!fs.existsSync(cachedir)) {
    fs.mkdir(cachedir, { recursive: true }, (err) => {
        if (err) throw err;
    });
}
const CACHE_PATH = path.resolve(cachedir, "cache.json");

const program = new Command()
    .option("-c, --content-binding <content-binding>")
    .option("-v, --visitor-data <visitordata>") // to be removed in a future version
    .option("-d, --data-sync-id <data-sync-id>") // to be removed in a future version
    .option("-p, --proxy <proxy-all>")
    .option("-b, --bypass-cache")
    .option("-s, --source-address <source-address>")
    .option("--disable-tls-verification")
    .option("--version")
    .option("--verbose")

    // ===== 兼容 CLI 模式=====
    .option("--challenge <challenge>", "Challenge JSON string (legacy CLI mode)")
    .option("--disable-innertube", "Disable innertube challenge flow (legacy CLI mode)")
    .option("--innertube-context <innertube-context>", "Innertube context JSON string (legacy CLI mode)")

    // ===== stdin-json 模式=====
    .option("--stdin-json", "Read all options as JSON from stdin (recommended on Windows to avoid argv length limits)")

    .exitOverride();

try {
    program.parse();
} catch (err) {
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
    const cache: YoutubeSessionDataCaches = {};
    if (fs.existsSync(CACHE_PATH)) {
        try {
            const parsedCaches = JSON.parse(
                fs.readFileSync(CACHE_PATH, "utf8"),
            );
            for (const contentBinding in parsedCaches) {
                const parsedCache = parsedCaches[contentBinding];
                if (parsedCache) {
                    const expiresAt = new Date(parsedCache.expiresAt);
                    if (!isNaN(expiresAt.getTime()))
                        cache[contentBinding] = {
                            poToken: parsedCache.poToken,
                            expiresAt,
                            contentBinding: contentBinding,
                        };
                    else
                        console.warn(
                            `Ignored cache entry: invalid expiresAt for content binding '${contentBinding}'.`,
                        );
                }
            }
        } catch (e) {
            console.warn(`Error parsing cache. e = ${e}`);
        }
    }

    const sessionManager = new SessionManager(verbose, cache || {});

    /**
     * ==============
     * 统一参数入口（stdin-json 优先）
     * ==============
     *
     * 注意 disable_tls_verification 的语义：
     * - True  表示“禁用 TLS 校验”
     * - False 表示“正常校验 TLS”
     * 这一点要和 Python provider 的 payload 保持一致
     */
    let contentBinding: string | undefined = options.contentBinding;
    let proxy: string = options.proxy || "";
    let bypassCache: boolean = !!options.bypassCache;
    let sourceAddress: string | undefined = options.sourceAddress;
    let disableTlsVerification: boolean = !!options.disableTlsVerification;

    // 这两个对象通常很大（尤其 challenge），stdin-json 模式下直接从 payload 拿
    let challengeObj: any | undefined;
    let innertubeContextObj: any | undefined;
    let disableInnertube: boolean = !!options.disableInnertube;

    if (options.stdinJson) {
        const raw = await readAllStdin();
        const payload = safeJsonParse<StdinPayload>(raw);

        if (!payload) {
            console.error("Invalid stdin JSON payload");
            console.log(JSON.stringify({}));
            process.exit(1);
        }

        // 覆盖基础字段（payload 优先级最高）
        contentBinding = payload.content_binding ?? contentBinding;
        proxy = payload.proxy ?? proxy;
        bypassCache = payload.bypass_cache ?? bypassCache;
        sourceAddress = payload.source_address ?? sourceAddress;

        // payload.disable_tls_verification 语义：是否禁用 TLS 验证
        disableTlsVerification = payload.disable_tls_verification ?? disableTlsVerification;

        // 大对象字段
        challengeObj = payload.challenge;
        innertubeContextObj = payload.innertube_context;

        // 是否禁用 innertube
        disableInnertube = payload.disable_innertube ?? disableInnertube;
    } else {
        // 兼容 CLI 模式：从命令行参数解析 JSON
        challengeObj = normalizeChallengeFromCli(options.challenge);
        innertubeContextObj = normalizeInnertubeContextFromCli(options.innertubeContext);
    }

    // 基础校验：contentBinding 必须存在
    if (!contentBinding) {
        console.error(
            "Missing content binding. Pass -c/--content-binding or provide it in stdin JSON payload.",
        );
        console.log(JSON.stringify({}));
        process.exit(1);
    }

    try {
        const sessionData = await sessionManager.generatePoToken(
            contentBinding,
            proxy,
            bypassCache,
            sourceAddress,
            disableTlsVerification,
            challengeObj,
            disableInnertube,
            innertubeContextObj,
        );

        try {
            fs.writeFileSync(
                CACHE_PATH,
                JSON.stringify(
                    sessionManager.getYoutubeSessionDataCaches(true),
                ),
                "utf8",
            );
        } catch (e) {
            console.warn(
                `Error writing cache. err.name = ${e.name}. err.message = ${e.message}. err.stack = ${e.stack}`,
            );
        } finally {
            console.log(JSON.stringify(sessionData));
        }
    } catch (e) {
        console.error(
            `Failed while generating POT. err.name = ${e.name}. err.message = ${e.message}. err.stack = ${e.stack}`,
        );
        console.log(JSON.stringify({}));
        process.exit(1);
    }
})();
