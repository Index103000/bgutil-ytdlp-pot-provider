import { SessionManager } from "./session_manager.ts";
import { strerror, VERSION } from "./utils.ts";
import { Command } from "commander";
import express from "express";

const program = new Command().option("-p, --port <PORT>").parse();

const options = program.opts();
const PORT_NUMBER = options.port || 4416;

const httpServer = express();
httpServer.use(express.json());
httpServer.use(express.urlencoded({ extended: true }));

/**
 * SessionManager 现在内部已经统一处理：
 * - 默认 cachedir 计算
 * - 单 key 锁
 * - 单 key 磁盘缓存
 * - 当前进程内缓存
 *
 * 因此 HTTP 模式这里只需要保留一个共享 SessionManager 实例即可。
 */
const sessionManager = new SessionManager();

/**
 * 启动 HTTP 服务。
 *
 * 当前策略：
 * 1. 先尝试监听 [::]
 * 2. 若失败，再退回 0.0.0.0
 *
 * 说明：
 * - 这是当前项目已有的兼容策略
 * - 暂时保持不变
 */
httpServer
    .listen(
        {
            host: "::",
            port: PORT_NUMBER,
        },
        (err) => {
            if (err) {
                console.error(
                    `Could not listen on [::]:${PORT_NUMBER}, falling back to 0.0.0.0 (Caused by ${strerror(err)})`,
                );
            } else {
                console.log(
                    `Started POT server (v${VERSION}) on on address [::]:${PORT_NUMBER}`,
                );
            }
        },
    )
    .on("error", () => {
        // ipv4 only systems might not be able to bind to "::", so we try 0.0.0.0 instead
        // this is temporary as we plan to bind to localhost in the next major version
        httpServer.listen(
            {
                host: "0.0.0.0",
                port: PORT_NUMBER,
            },
            (err) => {
                if (err) {
                    console.error(
                        `Could not listen on [::]:${PORT_NUMBER} (Caused by ${strerror(err)})`,
                    );
                } else {
                    console.log(
                        `Started POT server (v${VERSION}) on address 0.0.0.0:${PORT_NUMBER}`,
                    );
                }
            },
        );
    });

/**
 * 统一 POT 获取入口。
 *
 * 注意：
 * - 当前缓存与锁逻辑已经下沉到 SessionManager.generatePoToken()
 * - 因此这里不再需要 HTTP 层自己额外包锁或做磁盘缓存判断
 */
httpServer.post("/get_pot", async (request, response) => {
    const body = request.body || {};

    if (body.data_sync_id) {
        return response.status(400).send({
            error: "data_sync_id is deprecated, use content_binding instead",
        });
    }

    if (body.visitor_data) {
        return response.status(400).send({
            error: "visitor_data is deprecated, use content_binding instead",
        });
    }

    if (body.disable_innertube) {
        return response.status(400).send({
            error: "disable_innertube is deprecated because the /Create endpoint doesn't work anymore",
        });
    }

    const contentBinding: string | undefined = body.content_binding;
    const proxy: string = body.proxy || "";
    const bypassCache: boolean = body.bypass_cache || false;
    const sourceAddress: string | undefined = body.source_address;
    const disableTlsVerification: boolean =
        body.disable_tls_verification || false;

    try {
        const sessionData = await sessionManager.generatePoToken(
            contentBinding,
            proxy,
            bypassCache,
            sourceAddress,
            disableTlsVerification,
            body.challenge,
            body.innertube_context,
        );

        response.send(sessionData);
    } catch (e: any) {
        const msg = strerror(e, /*update=*/ true);
        console.error(e?.stack);
        response.status(500).send({ error: msg });
    }
});

/**
 * 仅使当前进程内缓存失效。
 *
 * 注意：
 * - 这里仍然只清空 SessionManager 内部的内存缓存
 * - 不会清理磁盘缓存
 */
httpServer.post("/invalidate_caches", async (_request, response) => {
    sessionManager.invalidateCaches();
    response.status(204).send();
});

/**
 * 仅使当前进程内 minterCache 失效。
 */
httpServer.post("/invalidate_it", async (_request, response) => {
    sessionManager.invalidateIT();
    response.status(204).send();
});

/**
 * 基础健康检查接口。
 */
httpServer.get("/ping", async (_request, response) => {
    response.send({
        server_uptime: process.uptime(),
        version: VERSION,
    });
});

/**
 * 调试接口：查看当前进程内 minterCache 的 key。
 *
 * 说明：
 * - 这里只能看到当前 HTTP server 进程里的内存态 minter cache
 * - 看不到磁盘缓存内容
 */
httpServer.get("/minter_cache", async (_request, response) => {
    console.debug(sessionManager.minterCache);
    response.send(Array.from(sessionManager.minterCache.keys()));
});
