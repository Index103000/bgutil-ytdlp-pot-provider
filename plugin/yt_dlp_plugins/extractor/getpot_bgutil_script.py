from __future__ import annotations

import abc
import functools
import json
import os
import re
import subprocess
import sys
import sysconfig
from typing import Iterable, TypeVar

from yt_dlp.extractor.youtube.pot.provider import (
    PoTokenProviderError,
    PoTokenRequest,
    PoTokenResponse,
    register_preference,
    register_provider,
)
from yt_dlp.extractor.youtube.pot.utils import get_webpo_content_binding
from yt_dlp.utils import Popen, int_or_none
from yt_dlp.utils.traversal import traverse_obj

from yt_dlp_plugins.extractor.getpot_bgutil import BgUtilPTPBase

T = TypeVar('T')
_FALLBACK_PATHEXT = ('.COM', '.EXE', '.BAT', '.CMD')


# Copied from https://github.com/yt-dlp/yt-dlp/blob/891613b098b2b315d983c2ae16901f5de344ca56/yt_dlp/utils/_jsruntime.py#L16-L64
# NOTE: keep in sync with upstream
def _find_exe(basename: str) -> str:
    # Check in Python "scripts" path, e.g. for pipx-installed binaries
    binary = os.path.join(
        sysconfig.get_path('scripts'),
        basename + sysconfig.get_config_var('EXE'))
    if os.access(binary, os.F_OK | os.X_OK) and not os.path.isdir(binary):
        return binary

    if os.name != 'nt':
        return basename

    paths: list[str] = []

    # binary dir
    if getattr(sys, 'frozen', False):
        paths.append(os.path.dirname(sys.executable))
    # cwd
    paths.append(os.getcwd())
    # PATH items
    if path := os.environ.get('PATH'):
        paths.extend(filter(None, path.split(os.path.pathsep)))

    pathext = os.environ.get('PATHEXT')
    if pathext is None:
        exts = _FALLBACK_PATHEXT
    else:
        exts = tuple(ext for ext in pathext.split(os.pathsep) if ext)

    visited = []
    for path in map(os.path.realpath, paths):
        normed = os.path.normcase(path)
        if normed in visited:
            continue
        visited.append(normed)

        for ext in exts:
            binary = os.path.join(path, f'{basename}{ext}')
            if os.access(binary, os.F_OK | os.X_OK) and not os.path.isdir(binary):
                return binary

    return basename


def _determine_runtime_path(path, basename):
    if not path:
        return _find_exe(basename)
    if os.path.isdir(path):
        return os.path.join(path, basename)
    return path


class BgUtilScriptPTPBase(BgUtilPTPBase, abc.ABC):
    _GET_SCRIPT_VSN_TIMEOUT = 15.0

    @staticmethod
    def _jsrt_vsn_tup(v: str):
        return tuple(int_or_none(x, default=0) for x in v.split('.'))

    def __init_subclass__(cls):
        super().__init_subclass__()
        pref = cls._JSRT_PREF
        register_preference(cls)(lambda provider, request: pref)

    _SCRIPT_BASENAME: str
    _JSRT_NAME: str  # Name of the JS Runtime shown in logs
    _JSRT_EXEC: str  # Name of the executable, and the name used in yt-dlp
    _JSRT_VSN_REGEX: str
    _JSRT_MIN_VER: tuple[int, ...]
    _JSRT_PREF: int

    @abc.abstractmethod
    def _script_path_impl(self) -> str:
        raise NotImplementedError

    def _jsrt_args(self) -> Iterable[str]:
        return ()

    def _jsrt_path_impl(self) -> str | None:
        jsrt_path = _determine_runtime_path(
            traverse_obj(self.ie.get_param('js_runtimes'), (self._JSRT_EXEC, 'path')),
            self._JSRT_EXEC)
        try:
            output, _, returncode = Popen.run(
                [jsrt_path, '--version'], text=True, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5.0)
            output = output.strip()
        except subprocess.TimeoutExpired:
            self.logger.debug(
                f'Failed to check {self._JSRT_NAME} version: {self._JSRT_NAME} process '
                'did not finish in 5.0 seconds', once=True)
            return None
        except FileNotFoundError:
            self.logger.debug(
                f'{self._JSRT_NAME} executable not found. Please ensure {self._JSRT_NAME} is '
                'installed and available in PATH or passed to yt-dlp with --js-runtimes.', once=True)
            return None
        mobj = re.search(self._JSRT_VSN_REGEX, output)
        if returncode or not mobj:
            self.logger.debug(
                f'Failed to check {self._JSRT_NAME} version. '
                f'{self._JSRT_NAME} returned {returncode} exit status. '
                f'Process output:\n{output}', once=True)
            return None
        if self._jsrt_has_support(mobj.group(1)):
            return jsrt_path

    def _jsrt_has_support(self, v: str) -> bool:
        if self._jsrt_vsn_tup(v) >= self._JSRT_MIN_VER:
            self.logger.trace(f'{self._JSRT_NAME} version: {v}')
            return True
        else:
            min_vsn_str = '.'.join(map(str, self._JSRT_MIN_VER))
            self.logger.debug(
                f'{self._JSRT_NAME} version too low. '
                f'(got {v}, but at least {min_vsn_str} is required)', once=True)
            return False

    @functools.cached_property
    def _script_path(self) -> str:
        return self._script_path_impl()

    @functools.cached_property
    def _jsrt_path(self) -> str | None:
        return self._jsrt_path_impl()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._check_script = functools.cache(self._check_script_impl)

    def _base_config_arg(self, key: str, default: T = None) -> str | T:
        return self.ie._configuration_arg(
            ie_key='youtubepot-bgutilscript', key=key, default=[default])[0]

    @functools.cached_property
    def _server_home(self) -> str:
        resolve_path = lambda *ps: os.path.abspath(
            os.path.expanduser(os.path.expandvars(os.path.join(*ps))))
        if server_home := self._base_config_arg('server_home'):
            return resolve_path(server_home)

        if script_path := self._base_config_arg('script_path'):
            return resolve_path(script_path, os.pardir, os.pardir)

        # default if no arg was passed
        default_home = resolve_path('~', 'bgutil-ytdlp-pot-provider', 'server')
        self.logger.debug(
            f'No server_home or script_path passed, defaulting to {default_home}', once=True)
        return default_home

    @functools.cached_property
    def _script_cache_dir(self) -> str:
        # don't use _HOMEDIR as the server is coded this way and accepts HOME and USERPROFILE regardless of the OS
        home_dir = os.getenv('HOME') or os.getenv('USERPROFILE')
        if (xdg_cache := os.getenv('XDG_CACHE_HOME')) is not None:
            return os.path.abspath(os.path.join(xdg_cache, 'bgutil-ytdlp-pot-provider'))
        elif home_dir:
            return os.path.abspath(os.path.join(home_dir, '.cache', 'bgutil-ytdlp-pot-provider'))
        else:
            return self._server_home

    def is_available(self) -> bool:
        return self._check_script(self._script_path)

    def _check_script_impl(self, script_path) -> bool:
        if not os.path.isfile(script_path):
            self.logger.debug(
                f"Script path doesn't exist: {script_path}", once=True)
            return False
        if os.path.basename(script_path) != self._SCRIPT_BASENAME:
            self.logger.warning(
                f'The script path passed in the extractor argument '
                f'has a wrong base name, expected {self._SCRIPT_BASENAME}.', once=True)
            return False
        if not self._jsrt_path:
            return False
        stdout, _, returncode = Popen.run(
            [self._jsrt_path, *self._jsrt_args(), script_path, '--version'],
            stdout=subprocess.PIPE, text=True, timeout=self._GET_SCRIPT_VSN_TIMEOUT)
        stdout = stdout.strip()
        if returncode:
            self.logger.warning(
                f'Failed to check script version. '
                f'Script returned {returncode} exit status. '
                f'Script stdout:\n{stdout}',
                once=True)
            return False
        else:
            self._check_version(stdout, name='script')
            return True

    def _real_request_pot(
        self,
        request: PoTokenRequest,
    ) -> PoTokenResponse:
        # used for CI check
        self.logger.trace(
            f'Generating POT via script: {self._script_path}')

        # 初始化命令行
        command_args = [self._jsrt_path, *self._jsrt_args(), self._script_path]

        # 注意：这里注释掉原先项目中关于参数的使用方式，改为 stdin 方案，这样可以与 http 方案一致，且可以传递 大内容的 payload，从而防止触发命令行长度限制
        # if proxy := request.request_proxy:
        #     command_args.extend(['-p', proxy])
        # command_args.extend(['-c', get_webpo_content_binding(request)[0]])
        # if request.bypass_cache:
        #     command_args.append('--bypass-cache')
        # if request.request_source_address:
        #     command_args.extend(
        #         ['--source-address', request.request_source_address])
        # if request.request_verify_tls is False:
        #     command_args.append('--disable-tls-verification')

        # 打印 pot 生成的详细日志（用于打印 SessionManager 中的过程日志，推荐仅在debug时使用）
        command_args.append('--verbose')

        # 同步 http 方案 对应参数，确保与 http 方案 参数一致
        disable_innertube = bool(self._base_config_arg('disable_innertube'))
        challenge = self._get_attestation(None if disable_innertube else request.video_webpage)
        # The challenge is falsy when the webpage and the challenge are unavailable
        # In this case, we need to disable /att/get since it's broken for web_music
        if not challenge and request.internal_client_name == 'web_music':
            if not disable_innertube:  # if not already set, warn the user
                self.logger.warning(
                    'BotGuard challenges could not be obtained from the webpage, '
                    'overriding disable_innertube=True because InnerTube challenges '
                    'are currently broken for the web_music client. '
                    'Pass disable_innertube=1 to suppress this warning.')
            disable_innertube = True

        # 构建“stdin payload”：把所有可能用到的参数统一放进去
        # - 这样脚本端逻辑更像 HTTP body
        # - 也避免 argv 在不同 OS 上的 quoting / escaping 坑
        payload = {
            # 与 HTTP server 一致的字段命名，便于脚本端复用解析逻辑
            'bypass_cache': request.bypass_cache,
            'challenge': challenge,  # 这里是对象/字符串/None，直接塞进去，json.dumps 会处理
            'content_binding': get_webpo_content_binding(request)[0],
            'disable_innertube': disable_innertube,
            'disable_tls_verification': not request.request_verify_tls,
            'proxy': request.request_proxy,
            'innertube_context': request.innertube_context,
            'source_address': request.request_source_address,
        }
        # 序列化 payload
        # - ensure_ascii=False：保留非 ASCII（虽然这里主要是英文，但保持一致）
        # - separators：去掉空格，减小体积（虽然 stdin 不怕长，但更省）
        payload_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        # 打印 payload
        self.logger.trace(f'stdin payload={payload_str}')
        # 加一个短开关，告诉脚本“从 stdin 读取 JSON payload”
        # 这个参数非常短，不会触发命令行长度限制
        command_args.append('--stdin-json')

        self.logger.info(
            f'Generating a {request.context.value} PO Token for '
            f'{request.internal_client_name} client via bgutil script',
        )
        self.logger.debug(
            f'Executing command to get POT via script: {" ".join(command_args)}')

        try:
            # stdout, _, returncode = Popen.run(
            #     command_args, stdout=subprocess.PIPE, text=True,
            #     timeout=self._GETPOT_TIMEOUT)

            # 不能用 Popen.run(input=...)：因为 yt-dlp 的 Popen.run 不会把 input 传给 communicate()，而我们需要 input 传递大内容 payload
            # 所以这里手动创建进程，然后 communicate(input=...) 写入 stdin
            with Popen(
                    command_args,
                    text=True,  # 让 stdin/stdout 走 str（内部会设置 encoding=utf-8, errors=replace）
                    stdin=subprocess.PIPE,  # 必须：让我们可以写入 stdin
                    stdout=subprocess.PIPE,  # 捕获 stdout
                    stderr=subprocess.STDOUT,  # stderr 合并到 stdout，保持你原来的“最后一行 JSON”约定
            ) as proc:
                # 关键：communicate_or_kill 支持把 input 写入 stdin（内部调用 subprocess.Popen.communicate）
                stdout, _ = proc.communicate_or_kill(input=payload_str, timeout=self._GETPOT_TIMEOUT)
                returncode = proc.returncode

            stdout_lines = stdout.strip().splitlines()
            json_resp = stdout_lines.pop()
        except subprocess.TimeoutExpired as e:
            raise PoTokenProviderError(
                f'_get_pot_via_script failed: Timeout expired when trying to run script (caused by {e!r})')
        except Exception as e:
            raise PoTokenProviderError(
                f'_get_pot_via_script failed: Unable to run script (caused by {e!r})') from e

        if stdout_extra := stdout_lines:
            # self.logger.trace(f'script stdout:\n{stdout_extra}')
            # stdout_extra 是 list，直接 f-string 会变成 ['line1', 'line2'] 这种一行，不直观
            # 改成更明确可见的输出（逐行输出）：
            for line in stdout_extra:
                self.logger.trace(f'script stdout: {line}')
        if returncode:
            raise PoTokenProviderError(
                f'_get_pot_via_script failed with returncode {returncode}')

        try:
            self.logger.trace(f'JSON response:\n{json_resp}')
            # The JSON response is always the last line
            script_data_resp = json.loads(json_resp)
        except json.JSONDecodeError as e:
            raise PoTokenProviderError(
                f'Error parsing JSON response from _get_pot_via_script (caused by {e!r})') from e
        if 'poToken' not in script_data_resp:
            raise PoTokenProviderError(
                'The script did not respond with a po_token')
        return PoTokenResponse(po_token=script_data_resp['poToken'])


@register_provider
class BgUtilScriptNodePTP(BgUtilScriptPTPBase):
    PROVIDER_NAME = 'bgutil:script-node'
    _SCRIPT_BASENAME = 'generate_once.js'
    _JSRT_NAME = 'Node.js'
    _JSRT_EXEC = 'node'
    _JSRT_VSN_REGEX = r'^v(\S+)'
    _JSRT_MIN_VER = (20, 0, 0)
    _JSRT_PREF = 10

    def _script_path_impl(self) -> str:
        return os.path.join(
            self._server_home, 'build', self._SCRIPT_BASENAME)


@register_provider
class BgUtilScriptDenoPTP(BgUtilScriptPTPBase):
    PROVIDER_NAME = 'bgutil:script-deno'
    _SCRIPT_BASENAME = 'generate_once.ts'
    _JSRT_NAME = 'Deno'
    _JSRT_EXEC = 'deno'
    _JSRT_VSN_REGEX = r'^deno (\S+)'
    _JSRT_MIN_VER = (2, 0, 0)
    _JSRT_PREF = 20

    def _script_path_impl(self) -> str:
        return os.path.join(
            self._server_home, 'src', self._SCRIPT_BASENAME)

    def _jsrt_args(self) -> Iterable[str]:
        def escpath(*strs: str):
            return ','.join(s.replace(',', ',,') for s in strs)
        node_mods_path = os.path.join(self._server_home, 'node_modules')
        return (
            'run', '--allow-env', '--allow-net',
            f'--allow-ffi={escpath(node_mods_path)}',
            f'--allow-write={escpath(self._script_cache_dir)}',
            f'--allow-read={escpath(self._script_cache_dir, node_mods_path)}',
        )


__all__ = [
    BgUtilScriptNodePTP.__name__,
    BgUtilScriptDenoPTP.__name__,
]
