// server/src/runtime_config.ts

/**
 * bgutil 运行时配置。
 *
 * 设计目标：
 * 1. 所有“运行期可调参数”集中放在这里；
 * 2. 避免在 session_manager.ts 里散落大量 process.env 解析逻辑；
 * 3. 保持默认行为尽量兼容原项目；
 * 4. 支持高并发/冷启动场景下，通过环境变量主动跳过内部资源限制。
 *
 * 当前新增配置：
 *
 * - BGUTIL_DISABLE_RESOURCE_GATE
 *   是否禁用 ResourceGate 资源门禁。
 *
 * - BGUTIL_DISABLE_CACHE_LOCK
 *   是否禁用按 contentBinding 粒度的目录锁。
 *
 * - BGUTIL_FETCH_TIMEOUT_MS
 *   外部 HTTP 请求单次超时时间，单位毫秒。
 *   主要用于避免代理连接、YouTube 接口、BotGuard 相关请求无限等待。
 *
 * - BGUTIL_FETCH_TIMEOUT_ONLY_WHEN_PROXY
 *   是否只在启用代理时才应用请求超时。
 *   默认 false，也就是无论是否代理都加超时。
 *
 * - BGUTIL_RESOURCE_GATE_RESERVED_MB
 * - BGUTIL_RESOURCE_GATE_MIN_FREE_AFTER_LAUNCH_MB
 * - BGUTIL_RESOURCE_GATE_MAX_MEMORY_PERCENT
 * - BGUTIL_RESOURCE_GATE_RESERVATION_STALE_MS
 * - BGUTIL_RESOURCE_GATE_SAMPLE_COUNT
 * - BGUTIL_RESOURCE_GATE_SAMPLE_INTERVAL_MS
 * - BGUTIL_RESOURCE_GATE_RETRY_INTERVAL_MS
 *   ResourceGate 的参数化配置。
 */

/**
 * 将环境变量解析为 boolean。
 *
 * 支持值：
 * - true:  "1" / "true" / "yes" / "on"
 * - false: "0" / "false" / "no" / "off"
 *
 * 说明：
 * - 未配置或空字符串时返回 defaultValue；
 * - 其他无法识别的值也返回 defaultValue，避免因为误配置直接崩溃。
 */
function readBoolEnv(name: string, defaultValue: boolean): boolean {
  const raw = process.env[name];

  if (raw === undefined || raw.trim() === "") {
    return defaultValue;
  }

  const normalized = raw.trim().toLowerCase();

  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }

  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }

  return defaultValue;
}

/**
 * 将环境变量解析为整数。
 *
 * 说明：
 * - 未配置时返回 defaultValue；
 * - 配置了非数字时返回 defaultValue；
 * - 若配置小于 min，则返回 min；
 * - 若配置大于 max，则返回 max。
 */
function readIntEnv(
  name: string,
  defaultValue: number,
  options: {
    min?: number;
    max?: number;
  } = {},
): number {
  const raw = process.env[name];

  if (raw === undefined || raw.trim() === "") {
    return defaultValue;
  }

  const parsed = Number.parseInt(raw.trim(), 10);

  if (!Number.isFinite(parsed)) {
    return defaultValue;
  }

  let value = parsed;

  if (options.min !== undefined && value < options.min) {
    value = options.min;
  }

  if (options.max !== undefined && value > options.max) {
    value = options.max;
  }

  return value;
}

/**
 * 将环境变量解析为浮点数。
 *
 * 主要用于 maxMemoryPercent 这种百分比参数。
 */
function readFloatEnv(
  name: string,
  defaultValue: number,
  options: {
    min?: number;
    max?: number;
  } = {},
): number {
  const raw = process.env[name];

  if (raw === undefined || raw.trim() === "") {
    return defaultValue;
  }

  const parsed = Number.parseFloat(raw.trim());

  if (!Number.isFinite(parsed)) {
    return defaultValue;
  }

  let value = parsed;

  if (options.min !== undefined && value < options.min) {
    value = options.min;
  }

  if (options.max !== undefined && value > options.max) {
    value = options.max;
  }

  return value;
}

/**
 * bgutil 运行时配置对象。
 *
 * 注意：
 * - 这里在模块加载时读取一次环境变量；
 * - 对于 generate_once.js 这种短生命周期脚本，这种方式足够；
 * - 对于 HTTP server 长生命周期模式，如果想运行中动态改变配置，需要重启进程。
 */
export const BGUTIL_RUNTIME_CONFIG = {
  /**
   * 是否禁用 ResourceGate。
   *
   * 默认：false
   *
   * 配置示例：
   * BGUTIL_DISABLE_RESOURCE_GATE=1
   *
   * 启用后：
   * - generatePoToken() 不再进入 ResourceGate；
   * - 不会因为内存占用、reservation、资源门禁等待导致 Node 脚本长时间挂起；
   * - 适合你当前“高并发下载任务 + script-node 模式”的场景。
   */
  disableResourceGate: readBoolEnv("BGUTIL_DISABLE_RESOURCE_GATE", true),

  /**
   * 是否禁用 contentBinding 目录锁。
   *
   * 默认：false
   *
   * 配置示例：
   * BGUTIL_DISABLE_CACHE_LOCK=1
   *
   * 启用后：
   * - 不再对相同 contentBinding 串行化；
   * - 可以避免目录锁 stale / 等锁导致 generate_once.js 卡住；
   * - 代价是同一个 contentBinding 可能被多个进程重复生成 POT。
   */
  disableCacheLock: readBoolEnv("BGUTIL_DISABLE_CACHE_LOCK", true),

  /**
   * HTTP 请求单次超时时间。
   *
   * 默认：30000ms
   *
   * 配置示例：
   * BGUTIL_FETCH_TIMEOUT_MS=30000
   *
   * 说明：
   * - 0 表示禁用主动超时；
   * - 建议生产环境设置 30000 ~ 60000；
   * - 这个超时是“单次请求”的超时，不是整个 POT 生成流程总超时。
   */
  fetchTimeoutMs: readIntEnv("BGUTIL_FETCH_TIMEOUT_MS", 30_000, {
    min: 0,
    max: 10 * 60 * 1000,
  }),

  /**
   * 是否只在存在代理时应用请求超时。
   *
   * 默认：false
   *
   * 说明：
   * - false：无论是否代理，都加请求超时；
   * - true：只有 proxySpec.proxy 存在时，才加请求超时。
   *
   * 你的场景主要是代理请求挂住，但无代理的 YouTube 请求也可能半开卡死，
   * 所以默认 false 更稳。
   */
  fetchTimeoutOnlyWhenProxy: readBoolEnv(
    "BGUTIL_FETCH_TIMEOUT_ONLY_WHEN_PROXY",
    false,
  ),

  /**
   * ResourceGate 参数。
   *
   * 默认值保持你当前分支里的保守配置：
   * - reservedMb=500
   * - minFreeAfterLaunchMb=2000
   * - maxMemoryPercent=80
   * - reservationStaleMs=10min
   * - sampleCount=5
   * - sampleIntervalMs=500
   * - retryIntervalMs=2000
   */
  resourceGate: {
    reservedMb: readIntEnv("BGUTIL_RESOURCE_GATE_RESERVED_MB", 500, {
      min: 0,
      max: 1024 * 1024,
    }),

    minFreeAfterLaunchMb: readIntEnv(
      "BGUTIL_RESOURCE_GATE_MIN_FREE_AFTER_LAUNCH_MB",
      2000,
      {
        min: 0,
        max: 1024 * 1024,
      },
    ),

    maxMemoryPercent: readFloatEnv(
      "BGUTIL_RESOURCE_GATE_MAX_MEMORY_PERCENT",
      80.0,
      {
        min: 1,
        max: 100,
      },
    ),

    reservationStaleMs: readIntEnv(
      "BGUTIL_RESOURCE_GATE_RESERVATION_STALE_MS",
      10 * 60 * 1000,
      {
        min: 1_000,
        max: 24 * 60 * 60 * 1000,
      },
    ),

    sampleCount: readIntEnv("BGUTIL_RESOURCE_GATE_SAMPLE_COUNT", 5, {
      min: 1,
      max: 100,
    }),

    sampleIntervalMs: readIntEnv(
      "BGUTIL_RESOURCE_GATE_SAMPLE_INTERVAL_MS",
      500,
      {
        min: 0,
        max: 60_000,
      },
    ),

    retryIntervalMs: readIntEnv(
      "BGUTIL_RESOURCE_GATE_RETRY_INTERVAL_MS",
      2000,
      {
        min: 100,
        max: 10 * 60 * 1000,
      },
    ),
  },
};