from __future__ import annotations

__version__ = '1.3.0'

import abc
import json
import os
from typing import TypeVar

from yt_dlp.extractor.youtube.pot.provider import (
    ExternalRequestFeature,
    PoTokenContext,
    PoTokenProvider,
    PoTokenProviderRejectedRequest,
)
from yt_dlp.extractor.youtube.pot.utils import WEBPO_CLIENTS
from yt_dlp.utils import js_to_json
from yt_dlp.utils.traversal import traverse_obj

T = TypeVar('T')


class BgUtilPTPBase(PoTokenProvider, abc.ABC):
    PROVIDER_VERSION = __version__
    BUG_REPORT_LOCATION = 'https://github.com/Brainicism/bgutil-ytdlp-pot-provider/issues'
    _SUPPORTED_EXTERNAL_REQUEST_FEATURES = (
        ExternalRequestFeature.PROXY_SCHEME_HTTP,
        ExternalRequestFeature.PROXY_SCHEME_HTTPS,
        ExternalRequestFeature.PROXY_SCHEME_SOCKS4,
        ExternalRequestFeature.PROXY_SCHEME_SOCKS4A,
        ExternalRequestFeature.PROXY_SCHEME_SOCKS5,
        ExternalRequestFeature.PROXY_SCHEME_SOCKS5H,
        ExternalRequestFeature.SOURCE_ADDRESS,
        ExternalRequestFeature.DISABLE_TLS_VERIFICATION,
    )
    _SUPPORTED_CLIENTS = WEBPO_CLIENTS
    _SUPPORTED_CONTEXTS = (
        PoTokenContext.GVS,
        PoTokenContext.PLAYER,
        PoTokenContext.SUBS,
    )
    # 官方将获取 pot 的超时设置为 20秒，但是在 deno 环境下，需要更长时间，
    # 因为 deno 执行的对象是未 build 的 原始项目中的 ts 文件，运行时需要引入各种包，
    # 当配置为 20秒 时，容易出现 Timeout expired when trying to run script，
    # 经测试，当前配置 120秒，基本不会出现 timeout。
    # 在 node 环境下，由于执行的是 build 后的文件，速度相对会快一些，20秒 可以正常执行。
    _GETPOT_TIMEOUT = 120.0

    def _info_and_raise(self, msg, raise_from=None):
        self.logger.info(msg)
        raise PoTokenProviderRejectedRequest(msg) from raise_from

    def _warn_and_raise(self, msg, once=True, raise_from=None):
        self.logger.warning(msg, once=once)
        raise PoTokenProviderRejectedRequest(msg) from raise_from

    def _script_config_arg(self, key: str, default: T = None, *, casesense=True) -> str | T:
        return self.ie._configuration_arg(
            ie_key='youtubepot-bgutilscript', key=key, default=[default], casesense=casesense)[0]

    @staticmethod
    def _resolve_script_path(*ps: str):
        return os.path.abspath(
            os.path.expanduser(os.path.expandvars(os.path.join(*ps))))

    def _script_path_provided(self) -> str | None:
        if server_home := self._script_config_arg('server_home'):
            return self._resolve_script_path(server_home)

        if script_path := self._script_config_arg('script_path'):
            return self._resolve_script_path(script_path, os.pardir, os.pardir)

        return None

    def _check_version(self, got_version, *, default='unknown', name):
        def _major(version):
            return version.split('.', 1)[0]

        if got_version != self.PROVIDER_VERSION:
            self.logger.warning(
                f'The provider plugin and the {name} are on different versions, '
                f'this may cause compatibility issues. '
                f'Please ensure they are on the same version. '
                f'Otherwise, help will NOT be provided for any issues that arise. '
                f'(plugin: {self.PROVIDER_VERSION}, {name}: {got_version or default})',
                once=True)

        if not got_version or _major(got_version) != _major(self.PROVIDER_VERSION):
            self._warn_and_raise(
                f'Plugin and {name} major versions are mismatched. '
                f'Update both the plugin and the {name} to the same version to proceed.')

    def _get_attestation(self, webpage: str | None):
        if not webpage:
            return None
        raw_cd = (
            traverse_obj(
                self.ie._search_regex(
                    r'''(?sx)window\s*\.\s*ytAtN\s*\(\s*
                        (?P<js>\{.+?}\s*)
                    \s*\)\s*;''', webpage, 'ytAtP challenge', default=None),
                ({js_to_json}, {json.loads}, 'R'))
            or traverse_obj(
                self.ie._search_regex(
                    r'''(?sx)window\.ytAtR\s*=\s*(?P<raw_cd>(?P<q>['"])
                        (?:
                            \\.|
                            (?!(?P=q)).
                        )*
                    (?P=q))\s*;''', webpage, 'ytAtR challenge', default=None),
                ({js_to_json}, {json.loads})))

        if att_txt := traverse_obj(raw_cd, ({json.loads}, 'bgChallenge')):
            return att_txt
        self.logger.warning('Failed to extract initial attestation from the webpage')
        return None

    @classmethod
    def _truncate_for_log(
        cls,
        value,
        *,
        max_str_len=None,
        max_list_items=None,
        max_dict_items=None,
    ):
        """
        将任意对象转换为“适合日志打印”的精简版本。

        设计目标：
        1. 保持原始结构，便于定位具体字段；
        2. 对超长字符串进行截断，避免日志被大字段刷屏；
        3. 对超长 list / tuple / dict 仅保留前若干项；
        4. 递归处理嵌套对象；
        5. 不修改原始对象本身。

        说明：
        - 这个方法只用于“日志展示”；
        - 真正发送给脚本进程的 payload 仍然保持完整；
        - 因此这里可以放心对内容做裁剪。

        参数：
        - value:
            任意待处理对象，常见为 dict / list / tuple / str / bytes / 基础类型
        - max_str_len:
            单个字符串最大展示长度；未传则取类默认值
        - max_list_items:
            list/tuple 最大展示元素数；未传则取类默认值
        - max_dict_items:
            dict 最大展示键数；未传则取类默认值

        返回：
        - 一个适合再 json.dumps 后输出到日志中的“精简对象”
        """
        # -----------------------------
        # 日志截断相关配置
        # -----------------------------
        # 单个字符串在日志中的最大展示长度。
        # 超过后只打印前缀，并附带 <truncated N chars> 标记。
        _LOG_MAX_STR_LEN = 300

        # list / tuple 在日志中最多展示多少个元素。
        # 超过后会追加一项 ...<omitted N items>
        _LOG_MAX_LIST_ITEMS = 10

        # dict 在日志中最多展示多少个 key。
        # 超过后会补一个特殊键 "..." 表示还有多少个 key 被省略。
        _LOG_MAX_DICT_ITEMS = 20
        max_str_len = _LOG_MAX_STR_LEN if max_str_len is None else max_str_len
        max_list_items = _LOG_MAX_LIST_ITEMS if max_list_items is None else max_list_items
        max_dict_items = _LOG_MAX_DICT_ITEMS if max_dict_items is None else max_dict_items

        # 1) 字符串：如果长度过长，则仅保留前缀
        if isinstance(value, str):
            if len(value) <= max_str_len:
                return value
            omitted = len(value) - max_str_len
            return f'{value[:max_str_len]}...<truncated {omitted} chars>'

        # 2) 二进制：避免把大量 bytes 直接打进日志
        if isinstance(value, (bytes, bytearray)):
            preview = bytes(value[: min(len(value), max_str_len)])
            try:
                preview_text = preview.decode('utf-8', errors='replace')
            except Exception:
                preview_text = repr(preview)
            if len(value) <= max_str_len:
                return f'<{type(value).__name__} len={len(value)} preview={preview_text!r}>'
            omitted = len(value) - max_str_len
            return (
                f'<{type(value).__name__} len={len(value)} '
                f'preview={preview_text!r} truncated={omitted}>'
            )

        # 3) list / tuple：只保留前 N 项
        if isinstance(value, (list, tuple)):
            items = [
                cls._truncate_for_log(
                    item,
                    max_str_len=max_str_len,
                    max_list_items=max_list_items,
                    max_dict_items=max_dict_items,
                )
                for item in value[:max_list_items]
            ]
            if len(value) > max_list_items:
                items.append(f'...<omitted {len(value) - max_list_items} items>')
            return items if isinstance(value, list) else tuple(items)

        # 4) dict：只保留前 N 个 key，并递归处理每个 value
        if isinstance(value, dict):
            new_dict = {}
            for idx, (k, v) in enumerate(value.items()):
                if idx >= max_dict_items:
                    new_dict['...'] = f'<omitted {len(value) - max_dict_items} keys>'
                    break
                new_dict[k] = cls._truncate_for_log(
                    v,
                    max_str_len=max_str_len,
                    max_list_items=max_list_items,
                    max_dict_items=max_dict_items,
                )
            return new_dict

        # 5) 常见基础类型：原样返回
        if value is None or isinstance(value, (bool, int, float)):
            return value

        # 6) 其他未知对象：转成 repr 后再按字符串截断规则处理
        return cls._truncate_for_log(
            repr(value),
            max_str_len=max_str_len,
            max_list_items=max_list_items,
            max_dict_items=max_dict_items,
        )

    @classmethod
    def _payload_for_log(cls, payload: dict) -> dict:
        """
        生成专门用于日志打印的 payload 副本。

        设计说明：
        - 原始 payload 用于真正写入子进程 stdin，不能修改；
        - 这个方法只负责构造“日志展示版 payload”；
        - 可在此对某些已知特别大的字段，施加更严格的截断策略。

        当前策略：
        - challenge：通常最容易非常大，使用更严格限制；
        - innertube_context：也可能较大，单独限制；
        - 其他字段：走默认截断策略。
        """
        log_payload = dict(payload)

        if 'challenge' in log_payload:
            log_payload['challenge'] = cls._truncate_for_log(
                log_payload['challenge'],
                max_str_len=120,
                max_list_items=5,
                max_dict_items=10,
            )

        if 'innertube_context' in log_payload:
            log_payload['innertube_context'] = cls._truncate_for_log(
                log_payload['innertube_context'],
                max_str_len=150,
                max_list_items=8,
                max_dict_items=15,
            )

        return cls._truncate_for_log(log_payload)


__all__ = ['__version__']
