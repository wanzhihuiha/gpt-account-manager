"""代理地址解析与代理连接能力。

这一层只负责代理 URL 的规范化、代理会话粘性和 socket/opener 注入，
不处理登录、CPA 或邮件业务流程，方便上层在不同场景复用同一套出口规则。
"""
from __future__ import annotations

import contextlib
import os
import re
import socket
import urllib.parse
import urllib.request
import uuid
from typing import Any


def _coerce_text(value: Any) -> str:
    return str(value or "").strip()


def _first_text(*values: Any) -> str:
    for value in values:
        text = _coerce_text(value)
        if text:
            return text
    return ""


def normalize_proxy_url(value: str) -> str:
    """把用户输入的代理地址统一成 urllib 可识别的 URL。

    空值和显式直连标记会被转成空字符串；格式错误直接抛出，
    让调用方保留现有失败路径。
    """
    raw = _coerce_text(value)
    if not raw or raw.lower() in {"none", "direct", "off", "false", "0", "no_proxy", "noproxy"}:
        return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, flags=re.I):
        raw = f"http://{raw}"
    parsed = urllib.parse.urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "socks4", "socks5", "socks5h"}:
        raise RuntimeError("代理只支持 http/https/socks4/socks5/socks5h")
    try:
        port = parsed.port
    except ValueError as exc:
        if "@" not in parsed.netloc and parsed.netloc.count(":") >= 3:
            raise RuntimeError("代理格式错误：请使用 http://用户名:密码@host:port，不能写成 http://host:port:用户名:密码") from exc
        raise RuntimeError("代理端口格式错误：端口必须是数字。正确格式是 http://用户名:密码@host:port") from exc
    if not parsed.hostname or not port:
        raise RuntimeError("代理地址需要包含主机和端口。正确格式是 http://用户名:密码@host:port")
    return raw


def sticky_proxy_url(proxy_url: str, job_id: str = "") -> str:
    """为支持会话标记的代理生成稳定 session 后缀。"""
    raw = _coerce_text(proxy_url)
    if not raw:
        return ""
    session_id = re.sub(r"[^a-zA-Z0-9]", "", job_id or uuid.uuid4().hex)[:12] or uuid.uuid4().hex[:12]
    for marker in ("{session}", "{SESSION}", "{{session}}", "{{SESSION}}", "$SESSION"):
        if marker in raw:
            raw = raw.replace(marker, session_id)
    parsed = urllib.parse.urlparse(raw)
    username = urllib.parse.unquote(parsed.username or "")
    if (
        parsed.scheme.lower() in {"http", "https"}
        and parsed.hostname
        and parsed.port
        and "rrp.bestgo.work" in parsed.hostname.lower()
        and "-session-" not in username
    ):
        username = f"{username}-session-{session_id}" if username else f"session-{session_id}"
        netloc = urllib.parse.quote(username, safe="-._~")
        if parsed.password is not None:
            netloc += f":{urllib.parse.quote(urllib.parse.unquote(parsed.password), safe='')}"
        netloc += f"@{parsed.hostname}:{parsed.port}"
        return urllib.parse.urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    return raw


def socks_dependency_error() -> RuntimeError:
    """集中生成 SOCKS 依赖缺失提示，避免多处文案漂移。"""
    return RuntimeError("SOCKS 代理需要安装 PySocks：sudo apt-get install -y python3-socks")


def request_proxy_url(payload: dict[str, Any] | None = None) -> str:
    """根据请求载荷和环境变量决定本次请求使用的代理 URL。"""
    payload = payload or {}
    enabled = bool(payload.get("use_proxy") or payload.get("useProxy"))
    raw = _coerce_text(payload.get("proxy_url") or payload.get("proxyUrl"))
    if not enabled and not raw:
        return ""
    if enabled and not raw:
        raw = _first_text(
            os.environ.get("HTTPS_PROXY"),
            os.environ.get("HTTP_PROXY"),
            os.environ.get("ALL_PROXY"),
        )
    return sticky_proxy_url(normalize_proxy_url(raw), _coerce_text(
        payload.get("proxy_session")
        or payload.get("proxySession")
        or payload.get("job_id")
        or payload.get("jobId")
    ))


def require_login_proxy_url(payload: dict[str, Any]) -> str:
    """登录刷新链路必须显式指定代理，避免误走服务器默认出口。"""
    raw = _coerce_text(payload.get("proxy_url") or payload.get("proxyUrl"))
    if not raw:
        raise RuntimeError("凭证刷新必须填写代理 URL")
    payload["use_proxy"] = True
    payload["proxy_url"] = raw
    return request_proxy_url(payload)


def proxy_opener(proxy_url: str) -> urllib.request.OpenerDirector:
    """根据代理协议构造 urllib opener。"""
    parsed = urllib.parse.urlparse(proxy_url)
    scheme = parsed.scheme.lower()
    if scheme in {"http", "https"}:
        return urllib.request.build_opener(urllib.request.ProxyHandler({
            "http": proxy_url,
            "https": proxy_url,
        }))
    try:
        import socks  # type: ignore
        import sockshandler  # type: ignore
    except Exception as exc:
        raise socks_dependency_error() from exc
    proxy_type = socks.SOCKS4 if scheme == "socks4" else socks.SOCKS5
    rdns = scheme == "socks5h"
    opener = urllib.request.build_opener(sockshandler.SocksiPyHandler(
        proxy_type,
        parsed.hostname,
        parsed.port,
        rdns,
        parsed.username,
        parsed.password,
    ))
    return opener


def playwright_proxy_options(proxy_url: str) -> dict[str, str]:
    """把统一代理 URL 转成 Playwright 使用的代理配置。"""
    parsed = urllib.parse.urlparse(proxy_url)
    scheme = "socks5" if parsed.scheme.lower() == "socks5h" else parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port
    if not host or not port:
        raise RuntimeError("代理地址需要包含主机和端口")
    options = {"server": f"{scheme}://{host}:{port}"}
    if parsed.username:
        options["username"] = urllib.parse.unquote(parsed.username)
    if parsed.password:
        options["password"] = urllib.parse.unquote(parsed.password)
    return options


@contextlib.contextmanager
def temporary_socket_proxy(proxy_url: str):
    """对 SOCKS 代理临时替换全局 socket，退出时恢复原状。"""
    if not proxy_url:
        yield
        return
    parsed = urllib.parse.urlparse(proxy_url)
    scheme = parsed.scheme.lower()
    if scheme not in {"socks4", "socks5", "socks5h"}:
        yield
        return
    try:
        import socks  # type: ignore
    except Exception as exc:
        raise socks_dependency_error() from exc
    proxy_type = socks.SOCKS4 if scheme == "socks4" else socks.SOCKS5
    original_socket = socket.socket
    original_default = socks.get_default_proxy()
    socks.set_default_proxy(
        proxy_type,
        parsed.hostname,
        parsed.port,
        rdns=scheme == "socks5h",
        username=urllib.parse.unquote(parsed.username) if parsed.username else None,
        password=urllib.parse.unquote(parsed.password) if parsed.password else None,
    )
    socket.socket = socks.socksocket
    try:
        yield
    finally:
        socket.socket = original_socket
        if original_default:
            socks.set_default_proxy(*original_default)
        else:
            socks.set_default_proxy()
