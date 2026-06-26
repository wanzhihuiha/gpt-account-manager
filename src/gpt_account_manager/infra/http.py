"""HTTP 请求与代理出口检测能力。

这一层只处理外部 HTTP 请求、JSON 解码、代理出口探测和网络异常翻译，
不关心业务数据语义，避免业务域直接散落 urllib 细节。
"""
from __future__ import annotations

import io
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from .network import HostHeaderHTTPSConnection, is_dns_error, network_error_message, open_with_fast_dns, urlopen_with_dns_retry
from .proxy import proxy_opener, require_login_proxy_url, temporary_socket_proxy


DEFAULT_HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; GPTAccountManager/1.0)",
}


def _headers(default_headers: dict[str, str] | None, headers: dict[str, str] | None = None) -> dict[str, str]:
    final_headers = dict(default_headers or DEFAULT_HTTP_HEADERS)
    if headers:
        final_headers.update(headers)
    return final_headers


def _coerce_text(value: Any) -> str:
    return str(value or "").strip()


def http_json(
    url: str,
    *,
    method: str = "GET",
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    default_headers: dict[str, str] | None = None,
    urlopen_with_dns_retry_func: Callable[..., Any] = urlopen_with_dns_retry,
    cached_ip_fallback: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """发送 form 风格请求并读取 JSON 响应。"""
    body = None
    final_headers = _headers(default_headers, headers)
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        final_headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=final_headers, method=method)
    try:
        with urlopen_with_dns_retry_func(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="ignore")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = {"error": text}
        message = payload.get("detail") or payload.get("error_description") or payload.get("error") or text
        raise RuntimeError(str(message)[:300]) from exc
    except urllib.error.URLError as exc:
        if is_dns_error(exc) and cached_ip_fallback:
            try:
                return cached_ip_fallback(url, method=method, body=body, headers=final_headers, timeout=timeout)
            except Exception:
                pass
        raise RuntimeError(network_error_message(url, exc)) from exc


def http_text(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    default_headers: dict[str, str] | None = None,
    urlopen_with_dns_retry_func: Callable[..., Any] = urlopen_with_dns_retry,
) -> tuple[int, str]:
    """发送 GET 请求并返回状态码与文本。"""
    final_headers = _headers(default_headers)
    final_headers["Accept"] = "application/json,text/plain,*/*"
    if headers:
        final_headers.update(headers)
    req = urllib.request.Request(url, headers=final_headers, method="GET")
    try:
        with urlopen_with_dns_retry_func(req, timeout=timeout) as resp:
            raw = resp.read()
            return int(getattr(resp, "status", 200) or 200), raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {text[:240]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(network_error_message(url, exc)) from exc


def http_request_json(
    url: str,
    *,
    method: str = "GET",
    json_data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    proxy_url: str = "",
    default_headers: dict[str, str] | None = None,
    open_with_fast_dns_func: Callable[..., Any] = open_with_fast_dns,
) -> dict[str, Any]:
    """发送 JSON 请求并解析 JSON 响应，保留空响应兼容语义。"""
    body = None
    final_headers = _headers(default_headers, headers)
    if json_data is not None:
        body = json.dumps(json_data, ensure_ascii=False).encode("utf-8")
        final_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=final_headers, method=method)
    try:
        opener = proxy_opener(proxy_url) if proxy_url else None
        open_call = opener.open if opener else urllib.request.urlopen
        with temporary_socket_proxy(proxy_url), open_with_fast_dns_func(open_call, req, timeout=timeout, use_cache=not bool(proxy_url)) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            if not raw.strip():
                return {"status": "ok"}
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {"body": raw}
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="ignore")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = {"error": text}
        message = payload.get("detail") or payload.get("error_description") or payload.get("error") or text
        raise RuntimeError(f"HTTP {exc.code}: {str(message)[:260]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(network_error_message(url, exc)) from exc


def probe_egress_trace(
    proxy_url: str = "",
    *,
    default_headers: dict[str, str] | None = None,
    open_with_fast_dns_func: Callable[..., Any] = open_with_fast_dns,
) -> dict[str, str]:
    """请求 Cloudflare trace，用于确认代理出口 IP 和地区。"""
    url = "https://www.cloudflare.com/cdn-cgi/trace"
    req = urllib.request.Request(url, headers=_headers(default_headers), method="GET")
    opener = proxy_opener(proxy_url) if proxy_url else None
    open_call = opener.open if opener else urllib.request.urlopen
    with temporary_socket_proxy(proxy_url), open_with_fast_dns_func(open_call, req, timeout=12, use_cache=not bool(proxy_url)) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    data: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def check_proxy_egress(
    payload: dict[str, Any],
    *,
    default_headers: dict[str, str] | None = None,
    open_with_fast_dns_func: Callable[..., Any] = open_with_fast_dns,
) -> dict[str, Any]:
    """校验代理出口是否能正常返回公网出口信息。"""
    proxy_url = require_login_proxy_url(dict(payload))
    trace = probe_egress_trace(
        proxy_url,
        default_headers=default_headers,
        open_with_fast_dns_func=open_with_fast_dns_func,
    )
    ip = _coerce_text(trace.get("ip"))
    if not ip:
        raise RuntimeError("代理出口检测失败：没有返回出口 IP")
    return {
        "success": True,
        "ip": ip,
        "loc": _coerce_text(trace.get("loc")),
        "colo": _coerce_text(trace.get("colo")),
        "proxy_session": _coerce_text(payload.get("proxy_session") or payload.get("proxySession")),
    }


def http_request_form_json(
    url: str,
    *,
    method: str = "POST",
    form_data: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    proxy_url: str = "",
    default_headers: dict[str, str] | None = None,
    open_with_fast_dns_func: Callable[..., Any] = open_with_fast_dns,
) -> tuple[int, dict[str, Any], str]:
    """发送表单请求，返回状态码、JSON 字典和原始文本。"""
    body = urllib.parse.urlencode(form_data or {}).encode("utf-8")
    final_headers = _headers(default_headers, headers)
    final_headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=final_headers, method=method)
    try:
        opener = proxy_opener(proxy_url) if proxy_url else None
        open_call = opener.open if opener else urllib.request.urlopen
        with temporary_socket_proxy(proxy_url), open_with_fast_dns_func(open_call, req, timeout=timeout, use_cache=not bool(proxy_url)) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                payload = {"raw": raw}
            return int(resp.status), payload if isinstance(payload, dict) else {"data": payload}, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            payload = {"raw": raw}
        return int(exc.code), payload if isinstance(payload, dict) else {"data": payload}, raw
    except urllib.error.URLError as exc:
        raise RuntimeError(network_error_message(url, exc)) from exc


def http_get_json_status(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    proxy_url: str = "",
    default_headers: dict[str, str] | None = None,
    open_with_fast_dns_func: Callable[..., Any] = open_with_fast_dns,
) -> tuple[int, dict[str, Any], str]:
    """发送 GET 请求，保留状态码和原始响应，供协议链路判断失败路径。"""
    final_headers = _headers(default_headers, headers)
    req = urllib.request.Request(url, headers=final_headers, method="GET")
    try:
        opener = proxy_opener(proxy_url) if proxy_url else None
        open_call = opener.open if opener else urllib.request.urlopen
        with temporary_socket_proxy(proxy_url), open_with_fast_dns_func(open_call, req, timeout=timeout, use_cache=not bool(proxy_url)) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                payload = {"raw": raw}
            return int(resp.status), payload if isinstance(payload, dict) else {"data": payload}, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            payload = {"raw": raw}
        return int(exc.code), payload if isinstance(payload, dict) else {"data": payload}, raw
    except urllib.error.URLError as exc:
        raise RuntimeError(network_error_message(url, exc)) from exc

def http_json_via_ip_fallback(
    url: str,
    *,
    headers: dict[str, str],
    fallback_host: str,
    fallback_ips: list[str],
    timeout: int = 30,
    connection_factory: Callable[..., Any] = HostHeaderHTTPSConnection,
) -> dict[str, Any]:
    """针对固定 host 用配置 IP 直连拉取 JSON，作为 DNS 失败兜底。"""
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or not fallback_host
        or parsed.hostname != fallback_host
        or not fallback_ips
    ):
        raise RuntimeError("No IP fallback configured for this host")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    last_error = ""
    for ip in fallback_ips:
        conn = None
        try:
            conn = connection_factory(ip, parsed.hostname, timeout=timeout, context=ssl.create_default_context())
            conn.request("GET", path, headers={**headers, "Host": parsed.hostname})
            resp = conn.getresponse()
            text = resp.read().decode("utf-8", errors="ignore")
            if resp.status >= 400:
                raise urllib.error.HTTPError(url, resp.status, resp.reason, resp.headers, None)
            return json.loads(text)
        except Exception as exc:
            last_error = str(exc)
        finally:
            if conn:
                conn.close()
    raise RuntimeError(f"临时邮箱 API DNS 兜底也失败：{last_error}")


def http_json_via_cached_ip_fallback(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    cached_fallback_ips_func: Callable[[str], list[str]],
    connection_factory: Callable[..., Any] = HostHeaderHTTPSConnection,
) -> dict[str, Any]:
    """通过已缓存的 fallback IP 直连请求 JSON。"""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("No cached IP fallback configured for this URL")
    ips = cached_fallback_ips_func(parsed.hostname)
    if not ips:
        raise RuntimeError("No cached IP fallback available for this host")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    last_error = ""
    for ip in ips:
        conn = None
        try:
            conn = connection_factory(ip, parsed.hostname, timeout=timeout, context=ssl.create_default_context())
            conn.request(method, path, body=body, headers={**(headers or {}), "Host": parsed.hostname})
            resp = conn.getresponse()
            data = resp.read()
            text = data.decode("utf-8", errors="ignore")
            if resp.status >= 400:
                raise urllib.error.HTTPError(url, resp.status, resp.reason, resp.headers, io.BytesIO(data))
            return json.loads(text)
        except Exception as exc:
            last_error = str(exc)
        finally:
            if conn:
                conn.close()
    raise RuntimeError(f"DNS IP fallback failed: {last_error}")
