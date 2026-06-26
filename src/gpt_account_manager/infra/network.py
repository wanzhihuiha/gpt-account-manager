"""底层网络与连接帮助函数。

这一层只放 DNS、socket、重试和连接构造这类基础能力，
不关心具体业务流程，也不直接处理 HTTP 路由或页面装配。
"""
from __future__ import annotations

import contextlib
import http.client
import imaplib
import json
import ipaddress
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable


_DNS_OVERRIDE_LOCK = threading.RLock()


def network_error_message(url: str, exc: BaseException) -> str:
    """把底层网络异常翻译成更适合上层展示的中文提示。"""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or url
    reason = getattr(exc, "reason", exc)
    text = str(reason or exc)
    lowered = text.lower()
    if "Temporary failure in name resolution" in text or "Name or service not known" in text:
        return f"服务器 DNS 解析失败：{host}。服务端请求由 VPS 发起，不是用户浏览器直接访问；请检查 VPS DNS、代理或目标 API 域名。原始错误：{text}"
    if "nodename nor servname provided" in text or "getaddrinfo failed" in text:
        return f"服务器 DNS 解析失败：{host}。服务端请求由 VPS 发起，不是用户浏览器直接访问；请检查 VPS DNS、代理或目标 API 域名。原始错误：{text}"
    if "unexpected_eof_while_reading" in lowered or "eof occurred in violation of protocol" in lowered:
        return f"代理 TLS 连接被中断：{host}。当前代理出口没有稳定完成 HTTPS 握手，请更换代理或稍后重试。原始错误：{text}"
    if "connection reset" in lowered or "connection refused" in lowered or "remote end closed connection" in lowered:
        return f"代理连接失败：{host}。当前代理出口连接被关闭或拒绝，请更换代理。原始错误：{text}"
    if "timed out" in lowered or "timeout" in lowered:
        return f"代理连接超时：{host}。当前代理出口响应太慢，请更换代理或降低批量。原始错误：{text}"
    return f"服务器网络请求失败：{host}。原始错误：{text}"


def is_dns_error(exc: BaseException) -> bool:
    """判断异常是不是典型的 DNS 解析失败。"""
    text = str(getattr(exc, "reason", exc))
    return any(phrase in text for phrase in [
        "Temporary failure in name resolution",
        "Name or service not known",
        "nodename nor servname provided",
        "getaddrinfo failed",
    ])


def set_dns_fallback_cache(cache: dict[str, list[str]], host: str, addresses: list[str]) -> None:
    """把最近一次可用的解析结果塞进缓存，供后续重试复用。"""
    clean_host = str(host or "").strip().lower()
    if not clean_host:
        return
    ipv4_first = sorted(set(addresses), key=lambda value: (":" in value, value))
    if ipv4_first:
        cache[clean_host] = ipv4_first[:8]


def validate_http_base_url(
    base_url: str,
    *,
    label: str = "Worker URL",
    error_message_builder: Callable[[str, BaseException], str] | None = None,
    check_dns: bool = True,
) -> None:
    """校验 HTTP/HTTPS 地址是否带主机名且当前环境可解析。

    这个 helper 只关心最基础的协议、主机名和 DNS 解析，不掺杂 mail、
    workspace 或 cpa 的业务语义；这样各业务域就不用再重复维护同一套
    `urlparse + getaddrinfo` 细节。
    """
    raw = str(base_url or "").strip()
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError(f"{label} must start with http:// or https://")
    if not parsed.hostname:
        raise RuntimeError(f"{label} host missing")
    if not check_dns:
        return
    try:
        socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        if error_message_builder:
            raise RuntimeError(error_message_builder(raw, exc)) from exc
        raise RuntimeError(f"网络请求失败：{raw}") from exc


def is_private_host(hostname: str) -> bool:
    """判断主机名或 IP 是否属于本地/私网范围。"""
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname.lower() in {"localhost"}
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


def is_loopback_host(hostname: str) -> bool:
    """判断主机名或 IP 是否为 loopback 地址。"""
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname.lower() in {"localhost"}
    return ip.is_loopback


def validate_remote_base_url(
    base_url: str,
    *,
    allow_private_urls: bool = False,
    scheme_error: str = "base_url must use http or https",
    host_error: str = "base_url host missing",
    private_error: str = "private or local base_url is blocked",
) -> None:
    """校验远程 HTTP 地址，并按需禁止解析到本地或私网地址。"""
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError(scheme_error)
    hostname = parsed.hostname or ""
    if not hostname:
        raise RuntimeError(host_error)
    if allow_private_urls:
        return
    if is_private_host(hostname):
        raise RuntimeError(private_error)
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError:
        return
    for info in infos:
        address = info[4][0]
        if is_private_host(address):
            raise RuntimeError(private_error)


def resolve_http_host_addresses(base_url: str) -> list[str]:
    """解析 HTTP/HTTPS 地址对应的 IP 列表。

    这个 helper 只做 URL -> host -> IP 的基础解析，不夹带业务域自己的
    内网判定或错误翻译，方便 `cpa` 这类业务层只拿解析结果继续判断。
    """
    raw = str(base_url or "").strip()
    parsed = urllib.parse.urlparse(raw)
    hostname = parsed.hostname or ""
    if not hostname:
        return []
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return sorted({item[4][0] for item in infos})


@contextlib.contextmanager
def temporary_dns_overrides(overrides: dict[str, list[str]], *, lock: threading.RLock | None = None):
    """临时替换 getaddrinfo，用预置 IP 绕过瞬时 DNS 故障。"""
    clean_overrides = {
        host.lower(): list(ips)
        for host, ips in overrides.items()
        if host and ips
    }
    if not clean_overrides:
        yield
        return

    original_getaddrinfo = socket.getaddrinfo

    def fast_getaddrinfo(host: str, port: int, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0):
        clean_host = str(host or "").strip().lower()
        ips = clean_overrides.get(clean_host)
        if not ips:
            return original_getaddrinfo(host, port, family, type, proto, flags)
        rows = []
        for ip in ips:
            socket_family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            if family not in {0, socket.AF_UNSPEC, socket_family}:
                continue
            sockaddr = (ip, port, 0, 0) if socket_family == socket.AF_INET6 else (ip, port)
            rows.append((socket_family, type or socket.SOCK_STREAM, proto or socket.IPPROTO_TCP, "", sockaddr))
        return rows or original_getaddrinfo(host, port, family, type, proto, flags)

    active_lock = lock or _DNS_OVERRIDE_LOCK
    with active_lock:
        socket.getaddrinfo = fast_getaddrinfo
        try:
            yield
        finally:
            socket.getaddrinfo = original_getaddrinfo


def open_with_fast_dns(
    open_call: Callable[[urllib.request.Request], Any],
    req: urllib.request.Request,
    *,
    timeout: int = 30,
    use_cache: bool = True,
    dns_overrides_for_url: Callable[[str], dict[str, list[str]]] | None = None,
    dns_error_check: Callable[[BaseException], bool] = is_dns_error,
    dns_override_context: Callable[[dict[str, list[str]]], contextlib.AbstractContextManager[Any]] | None = None,
):
    """在直连失败时，尝试用已知 IP 和临时 DNS 覆盖再跑一遍。"""
    if not use_cache:
        return open_call(req, timeout=timeout)
    try:
        return open_call(req, timeout=timeout)
    except urllib.error.URLError as exc:
        if not dns_error_check(exc):
            raise
        overrides = dns_overrides_for_url(req.full_url) if dns_overrides_for_url else {}
        if not overrides:
            raise
        context_factory = dns_override_context or temporary_dns_overrides
        with context_factory(overrides):
            return open_call(req, timeout=timeout)


def urlopen_with_dns_retry(
    req: urllib.request.Request,
    *,
    timeout: int = 30,
    retries: int = 1,
    open_with_fast_dns_func: Callable[..., Any] = open_with_fast_dns,
    dns_error_check: Callable[[BaseException], bool] = is_dns_error,
):
    """urlopen 的轻量重试壳，专门处理短暂的 DNS 抖动。"""
    last_exc: BaseException | None = None
    for attempt in range(1 + retries):
        try:
            return open_with_fast_dns_func(urllib.request.urlopen, req, timeout=timeout)
        except urllib.error.URLError as exc:
            if attempt < retries and dns_error_check(exc):
                time.sleep(1.5)
                last_exc = exc
                continue
            raise
    raise last_exc  # type: ignore[misc]


def create_ip_connection(host: str, port: int, timeout: float | None, source_address: tuple[str, int] | None = None):
    """按 IP 直接建连接，避免被 host 名称解析卡住。"""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return socket.create_connection((host, port), timeout, source_address)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        if source_address:
            sock.bind(source_address)
        sockaddr = (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)
        sock.connect(sockaddr)
        return sock
    except Exception:
        sock.close()
        raise


class HostHeaderHTTPSConnection(http.client.HTTPSConnection):
    """支持按 IP 连接、按 Host 发送 SNI 的 HTTPS 连接壳。"""

    def __init__(self, ip: str, host_header: str, *args: Any, **kwargs: Any):
        self._host_header = host_header
        super().__init__(ip, *args, **kwargs)

    def connect(self) -> None:
        sock = create_ip_connection(self.host, self.port, self.timeout, self.source_address)
        context = self._context
        self.sock = context.wrap_socket(sock, server_hostname=self._host_header)


class HostHeaderIMAP4SSL(imaplib.IMAP4_SSL):
    """按 IP 建 IMAP SSL 连接，但保留原始主机名做 SNI。"""

    def __init__(self, host: str, connect_host: str, port: int = 993, *, timeout: int = 30):
        self._sni_host = host
        super().__init__(connect_host, port, ssl_context=ssl.create_default_context(), timeout=timeout)

    def _create_socket(self, timeout: float | None):
        sock = create_ip_connection(self.host, self.port, timeout)
        return self.ssl_context.wrap_socket(sock, server_hostname=self._sni_host)


def mail_network_probe_hosts(temp_worker_url: str = "") -> list[tuple[str, int, str]]:
    """收集网络健康检查的目标主机。

    这里只列出需要探测的 host，不直接做连接；实际的探测和结果
    拼装由 network_health_payload 统一处理，方便上层只保留一个调用点。
    """
    hosts = [
        ("auth.openai.com", 443, "OpenAI 授权"),
        ("chatgpt.com", 443, "ChatGPT 登录"),
        ("login.microsoftonline.com", 443, "Microsoft Graph 登录"),
        ("graph.microsoft.com", 443, "Microsoft Graph 收件"),
        ("outlook.office.com", 443, "Microsoft IMAP token"),
        ("outlook.live.com", 993, "Microsoft IMAP 收件"),
        ("outlook.office365.com", 993, "Microsoft IMAP 备用"),
        ("login.live.com", 443, "Microsoft Live 备用"),
    ]
    temp_host = urllib.parse.urlparse(temp_worker_url).hostname
    if temp_host:
        hosts.append((temp_host, 443 if temp_worker_url.startswith("https://") else 80, "临时邮箱 API"))
    return hosts


def network_health_payload(
    *,
    app_version: str,
    now: str,
    temp_worker_url: str = "",
    dns_fallback_cache: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """生成网络健康检查快照。

    这类诊断数据只反映 DNS 和连通性状态，不包含业务语义；某个主机
    失败时，把错误信息直接带回去，方便页面和日志原样展示。
    """
    cache = dns_fallback_cache if dns_fallback_cache is not None else {}
    checks = []
    for host, port, label in mail_network_probe_hosts(temp_worker_url):
        started = time.perf_counter()
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = sorted({item[4][0] for item in infos})[:4]
            set_dns_fallback_cache(cache, host, addresses)
            checks.append({
                "label": label,
                "host": host,
                "port": port,
                "ok": True,
                "addresses": addresses,
                "elapsed_ms": round((time.perf_counter() - started) * 1000),
            })
        except OSError as exc:
            checks.append({
                "label": label,
                "host": host,
                "port": port,
                "ok": False,
                "error": network_error_message(f"tcp://{host}:{port}", exc),
                "elapsed_ms": round((time.perf_counter() - started) * 1000),
            })
    return {
        "ok": all(item.get("ok") for item in checks),
        "version": app_version,
        "now": now,
        "checks": checks,
    }

def resolve_host_with_doh(
    host: str,
    *,
    fallback_hosts: set[str],
    default_headers: dict[str, str],
    connection_factory: Callable[..., Any] = HostHeaderHTTPSConnection,
) -> list[str]:
    """通过 DoH 查询指定主机的 A 记录。

    这是纯网络基础能力，不关心哪个业务域使用解析结果；允许上层注入
    fallback host 白名单和默认 headers，保持旧入口的行为可控。
    """
    clean_host = str(host or "").strip().lower()
    if clean_host not in fallback_hosts:
        return []
    query = urllib.parse.urlencode({"name": clean_host, "type": "A"})
    queries = [
        ("cloudflare-dns.com", "1.1.1.1", f"/dns-query?{query}"),
        ("cloudflare-dns.com", "1.0.0.1", f"/dns-query?{query}"),
        ("dns.google", "8.8.8.8", f"/resolve?{query}"),
        ("dns.google", "8.8.4.4", f"/resolve?{query}"),
    ]
    addresses: list[str] = []
    for doh_host, doh_ip, path in queries:
        conn = None
        try:
            conn = connection_factory(doh_ip, doh_host, timeout=8)
            conn.request("GET", path, headers={**default_headers, "Accept": "application/dns-json", "Host": doh_host})
            resp = conn.getresponse()
            payload = json.loads(resp.read().decode("utf-8"))
        except Exception:
            continue
        finally:
            if conn:
                conn.close()
        answers = payload.get("Answer") or []
        for item in answers:
            if item.get("type") == 1 and item.get("data"):
                addresses.append(str(item["data"]))
    return sorted(set(addresses))


def cached_fallback_ips(
    host: str,
    *,
    fallback_hosts: set[str],
    cache: dict[str, list[str]],
    static_fallback_ips: dict[str, list[str]],
    resolve_func: Callable[[str], list[str]],
    set_cache_func: Callable[[str, list[str]], None],
) -> list[str]:
    """按缓存、静态配置、DoH 解析的顺序获取 fallback IP。"""
    clean_host = str(host or "").strip().lower()
    if clean_host not in fallback_hosts:
        return []
    cached = cache.get(clean_host, [])
    if cached:
        return cached
    static = static_fallback_ips.get(clean_host, [])
    if static:
        return static
    resolved = resolve_func(clean_host)
    if resolved:
        set_cache_func(clean_host, resolved)
        return resolved
    return []


def dns_overrides_for_url(
    url: str,
    *,
    cached_fallback_ips_func: Callable[[str], list[str]],
) -> dict[str, list[str]]:
    """根据 URL 生成临时 DNS override 配置。"""
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    ips = cached_fallback_ips_func(host)
    return {host: ips} if host and ips else {}
