"""协议登录链里的纯 helper。

这里先承接 `ChatGPTProtocolLogin` 中已经能独立成立的协议辅助逻辑：
只做 OAuth 授权地址参数解析、CPA 配置判断、回调结果规整和日志脱敏，
不直接发请求、不落盘，也不维护登录状态机。
"""
from __future__ import annotations

import base64
import os
import html
import http.client
import json
import re
import secrets
import shutil
import subprocess
import urllib.parse
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


def _coerce_text(value: Any) -> str:
    """把协议 helper 里的兼容值规整成非空文本判断。"""
    return str(value or "").strip()


def _first_text(*values: Any) -> str:
    """保持旧脚本优先级，返回第一个非空文本。"""
    for value in values:
        text = _coerce_text(value)
        if text:
            return text
    return ""


def payload_has_cpa_config(payload: dict[str, Any]) -> bool:
    """判断协议登录当前是否走“CPA 提供 authorize_url”的分支。"""
    return bool(
        _coerce_text(payload.get("base_url") or payload.get("baseUrl"))
        and _coerce_text(payload.get("management_key") or payload.get("managementKey"))
    )


def session_from_cpa_callback_result(cpa_result: dict[str, Any], email_addr: str) -> dict[str, Any]:
    """把 CPA OAuth callback 的返回结果规整成登录域统一 session 载荷。

    这里兼容 CPA 已直接返回 auth_file，以及“只确认回调提交成功、由 CPA 自管”
    两类出口，让后续成功收尾统一按 session 语义继续处理。
    """
    auth_file = (
        cpa_result.get("auth_file")
        or (cpa_result.get("result", {}).get("auth_file") if isinstance(cpa_result.get("result"), dict) else {})
        or (cpa_result.get("result", {}).get("data", {}).get("auth_file") if isinstance(cpa_result.get("result", {}).get("data"), dict) else {})
    )
    if isinstance(auth_file, dict) and _first_text(auth_file.get("access_token"), auth_file.get("accessToken")):
        return {
            "access_token": _first_text(auth_file.get("access_token"), auth_file.get("accessToken")),
            "accessToken": _first_text(auth_file.get("access_token"), auth_file.get("accessToken")),
            "refresh_token": _first_text(auth_file.get("refresh_token"), auth_file.get("refreshToken"), "cpa-managed"),
            "refreshToken": _first_text(auth_file.get("refresh_token"), auth_file.get("refreshToken"), "cpa-managed"),
            "id_token": _first_text(auth_file.get("id_token"), auth_file.get("idToken")),
            "idToken": _first_text(auth_file.get("id_token"), auth_file.get("idToken")),
            "email": _first_text(auth_file.get("email"), email_addr),
            "user": {"email": _first_text(auth_file.get("email"), email_addr)},
            "cpa_oauth_result": cpa_result,
        }
    return {
        "access_token": "cpa-managed",
        "accessToken": "cpa-managed",
        "refresh_token": "cpa-managed",
        "refreshToken": "cpa-managed",
        "email": email_addr,
        "user": {"email": email_addr},
        "cpa_callback_only": True,
        "cpa_oauth_result": cpa_result,
    }


def extract_oauth_authorize_params(
    authorize_url: str,
    *,
    current_state: str,
    current_cpa_state: str,
    current_redirect_uri: str,
    current_client_id: str,
) -> dict[str, str]:
    """从 OAuth authorize_url 里提取协议链后续要复用的关键参数。"""
    parsed = urllib.parse.urlparse(authorize_url)
    query = urllib.parse.parse_qs(parsed.query)
    return {
        "oauth_authorize_url": authorize_url,
        "oauth_state": _first_text(query.get("state", [""])[0], current_state, current_cpa_state),
        "oauth_redirect_uri": _first_text(query.get("redirect_uri", [""])[0], current_redirect_uri),
        "oauth_client_id": _first_text(query.get("client_id", [""])[0], current_client_id),
    }


def callback_has_code(url: str, oauth_redirect_uri: str) -> bool:
    """判断当前 URL 是否已经回到本轮 OAuth callback，并携带 code。"""
    if not url:
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        redirect = urllib.parse.urlparse(oauth_redirect_uri)
        if parsed.scheme != redirect.scheme or parsed.hostname != redirect.hostname:
            return False
        if (parsed.port or (443 if parsed.scheme == "https" else 80)) != (redirect.port or (443 if redirect.scheme == "https" else 80)):
            return False
        if parsed.path.rstrip("/") != redirect.path.rstrip("/"):
            return False
        query = urllib.parse.parse_qs(parsed.query)
        return bool(_first_text(query.get("code", [""])[0]))
    except Exception:
        return False


def is_workspace_or_consent_url(url: str) -> bool:
    """判断是否已经进入 workspace / consent 一类的后置授权页面。"""
    lowered = _coerce_text(url).lower()
    return any(part in lowered for part in ["/workspace", "/sign-in-with-chatgpt/", "/consent", "/organization"])


def first_workspace_id(data: dict[str, Any]) -> str:
    """从 OAuth session cookie 解析结果里拿第一个 workspace_id。"""
    if not isinstance(data, dict):
        return ""
    direct = _first_text(data.get("workspace_id"), data.get("workspaceId"))
    if direct:
        return direct
    workspaces = data.get("workspaces") if isinstance(data.get("workspaces"), list) else []
    for item in workspaces:
        if isinstance(item, dict) and item.get("id"):
            return _coerce_text(item.get("id"))
    return ""


def extract_continue_url(data: dict[str, Any]) -> str:
    """从协议登录页状态里提取后续继续授权 URL。"""
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
    return _first_text(
        data.get("continue_url"),
        data.get("continueUrl"),
        data.get("redirect_url"),
        data.get("redirectUrl"),
        data.get("url"),
        payload.get("continue_url"),
    )


def extract_page_type(data: dict[str, Any]) -> str:
    """读取协议登录页当前 page_type。"""
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    return _coerce_text(page.get("type") or data.get("page_type"))


def needs_phone_verification(data: dict[str, Any], continue_url: str = "") -> bool:
    """判断当前页是否进入手机号验证或短信 OTP 流程。"""
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
    markers = " ".join([
        _coerce_text(page.get("type")),
        _coerce_text(data.get("page_type")),
        _coerce_text(data.get("step")),
        _coerce_text(data.get("state")),
        _coerce_text(data.get("error")),
        _coerce_text(data.get("message")),
        _coerce_text(payload.get("type")),
        _coerce_text(payload.get("step")),
        _coerce_text(payload.get("state")),
        _coerce_text(continue_url),
    ]).lower()
    return any(marker in markers for marker in [
        "phone_verification",
        "phone-verification",
        "phone_otp",
        "phone-otp",
        "phone otp",
        "select-channel",
        "select_channel",
        "add-phone",
        "mfa",
        "sms",
        "phone_number",
        "phone number",
        "mobile",
    ])


def needs_phone_channel_selection(data: dict[str, Any], continue_url: str = "") -> bool:
    """判断是否到了“选择短信/电话验证通道”的页面。"""
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    markers = " ".join([
        _coerce_text(page.get("type")),
        _coerce_text(data.get("page_type")),
        _coerce_text(data.get("step")),
        _coerce_text(data.get("state")),
        _coerce_text(continue_url),
    ]).lower()
    return any(marker in markers for marker in [
        "phone_otp_select_channel",
        "phone-otp/select-channel",
        "select-channel",
        "select_channel",
    ])


def needs_add_phone(data: dict[str, Any], continue_url: str = "") -> bool:
    """判断当前页是否要求先补录手机号。"""
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    markers = " ".join([
        _coerce_text(page.get("type")),
        _coerce_text(data.get("page_type")),
        _coerce_text(data.get("step")),
        _coerce_text(data.get("state")),
        _coerce_text(continue_url),
    ]).lower()
    return "add-phone" in markers or "add_phone" in markers


def extract_email_verification_mode(data: dict[str, Any]) -> str:
    """提取邮箱验证码页的 verification mode。"""
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
    return _coerce_text(payload.get("email_verification_mode"))


def needs_modern_otp(page_type: str, continue_url: str) -> bool:
    """判断当前是否仍应继续走现代邮箱 OTP 页面链路。"""
    page = page_type.lower()
    url = continue_url.lower()
    return page == "email_otp_verification" or "/email-verification" in url or not continue_url


def normalize_auth_url(value: str) -> str:
    """把 auth.openai.com 链路里的相对地址补成完整 URL。"""
    if not value:
        return ""
    return urllib.parse.urljoin("https://auth.openai.com", value)


def extract_query_param(url: str, name: str) -> str:
    """从 URL query 里安全提取单个参数。"""
    try:
        return urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get(name, [""])[0]
    except Exception:
        return ""


def authorize_continue_requires_session_retry(status: int, data: Any) -> bool:
    """判断 authorize/continue 是否因为 login_session 失效需要先重建会话。"""
    if status != 400:
        return False
    try:
        lowered = json.dumps(data, ensure_ascii=False).lower()
    except Exception:
        lowered = _coerce_text(data).lower()
    return "invalid_auth_step" in lowered or "invalid authorization step" in lowered


def parse_oauth_callback_params(callback_url: str, expected_state: str = "") -> dict[str, str]:
    """解析 OAuth callback URL，并校验 error/state/code 这组关键字段。"""
    query = urllib.parse.parse_qs(urllib.parse.urlparse(callback_url).query)
    error = _first_text(query.get("error", [""])[0], query.get("error_description", [""])[0])
    if error:
        raise RuntimeError(f"OpenAI OAuth authorization failed: {error}")
    returned_state = _first_text(query.get("state", [""])[0])
    if expected_state and returned_state and returned_state != expected_state:
        raise RuntimeError("OpenAI OAuth state mismatch")
    code = _first_text(query.get("code", [""])[0])
    if not code:
        raise RuntimeError("OAuth callback missing authorization code")
    return {"code": code, "state": returned_state}


def validate_oauth_exchange_response(status: int, data: dict[str, Any], raw: str) -> dict[str, Any]:
    """校验 OAuth token exchange 结果，确保 access/refresh token 都已返回。"""
    if status != 200:
        compact = protocol_compact_error(data) or raw[:260]
        raise RuntimeError(f"OpenAI OAuth token exchange failed: HTTP {status} - {compact}")
    if not _coerce_text(data.get("access_token")):
        raise RuntimeError("OpenAI OAuth token exchange succeeded but returned no access_token")
    if not _coerce_text(data.get("refresh_token")):
        raise RuntimeError("OpenAI OAuth token exchange succeeded but returned no refresh_token")
    return data


def validate_session_response(status: int, data: dict[str, Any]) -> dict[str, Any]:
    """校验 `/api/auth/session` 返回值，保持旧脚本的失败文案。"""
    if status != 200:
        raise RuntimeError(f"session request failed: HTTP {status} - {protocol_compact_error(data)}")
    return data


def _protocol_trace_headers() -> dict[str, str]:
    """生成协议登录里非导航请求使用的 trace headers。"""
    parent_id = secrets.randbits(63) or 1
    return {
        "traceparent": f"00-{secrets.token_hex(16)}-{parent_id:016x}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": str(parent_id),
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": str(secrets.randbits(63) or 1),
    }


def build_protocol_headers(
    url: str,
    *,
    device_id: str,
    default_http_headers: dict[str, str],
    openai_sec_ch_ua: str,
    openai_sec_ch_ua_full_version_list: str,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """构造协议登录请求头。

    这里只负责按 URL、Accept 和 device_id 组基础头，不做真正的 HTTP 请求，
    让旧脚本里的协议状态机只保留“何时发请求”，不再自己维护整套头字段细节。
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or ""
    accept = "application/json"
    if extra and extra.get("Accept"):
        accept = extra["Accept"]
    is_navigation = "text/html" in accept
    final_headers = {
        "User-Agent": default_http_headers["User-Agent"],
        "Accept": accept,
        "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": openai_sec_ch_ua,
        "sec-ch-ua-arch": '"x86_64"',
        "sec-ch-ua-bitness": '"64"',
        "sec-ch-ua-full-version-list": openai_sec_ch_ua_full_version_list,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-model": '""',
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-platform-version": '"10.0.0"',
        "sec-fetch-dest": "document" if is_navigation else "empty",
        "sec-fetch-mode": "navigate" if is_navigation else "cors",
        "sec-fetch-site": "same-origin",
        "oai-device-id": device_id or "",
    }
    if is_navigation:
        final_headers["sec-fetch-user"] = "?1"
    else:
        final_headers.update(_protocol_trace_headers())
        final_headers.setdefault("Origin", f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else "https://auth.openai.com")
        if path.startswith("/api/") or "/api/" in path:
            final_headers.setdefault("Content-Type", "application/json")
    if not final_headers["oai-device-id"]:
        final_headers.pop("oai-device-id", None)
    if extra:
        final_headers.update(extra)
    return final_headers


def safe_url_for_log(value: str) -> str:
    """把 OAuth 链路里的 URL 脱敏成可写日志的摘要。"""
    raw = _coerce_text(value)
    if not raw:
        return ""
    try:
        parsed = urllib.parse.urlparse(raw)
        if not parsed.scheme or not parsed.netloc:
            return raw[:220]
        query = urllib.parse.parse_qs(parsed.query)
        safe_items: list[tuple[str, str]] = []
        for key in ("response_type", "client_id", "redirect_uri", "state", "screen_hint", "email"):
            if key not in query:
                continue
            item = _coerce_text(query.get(key, [""])[0])
            if key == "state" and len(item) > 10:
                item = f"...{item[-8:]}"
            elif key == "email" and item:
                item = "***"
            elif key == "redirect_uri" and item:
                redirect = urllib.parse.urlparse(item)
                item = urllib.parse.urlunparse((redirect.scheme, redirect.netloc, redirect.path, "", "", ""))
            safe_items.append((key, item))
        safe_query = urllib.parse.urlencode(safe_items)
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", safe_query, ""))[:260]
    except Exception:
        return raw[:220]


@dataclass
class ProtocolResponse:
    """协议登录链里统一使用的响应壳。"""

    status: int
    url: str
    headers: Any
    text: str

    def json(self) -> dict[str, Any]:
        if not self.text.strip():
            return {}
        try:
            data = json.loads(self.text)
        except json.JSONDecodeError:
            return {"raw": self.text[:5000]}
        return data if isinstance(data, dict) else {"data": data}

    def location(self) -> str:
        return self.headers.get("Location") or self.headers.get("location") or ""


def read_response_text(resp: Any) -> tuple[str, bool]:
    """把 HTTP 响应体读成 utf-8 文本，并标记是否被截断。"""
    try:
        return resp.read().decode("utf-8", errors="replace"), False
    except http.client.IncompleteRead as exc:
        partial = exc.partial or b""
        return partial.decode("utf-8", errors="replace"), True


def next_oauth_authorize_url(resp: ProtocolResponse, current_url: str) -> str:
    """从 OAuth 授权响应里找下一跳地址。"""
    if resp.status in {301, 302, 303, 307, 308} and resp.location():
        return urllib.parse.urljoin(current_url, resp.location())
    data = resp.json()
    candidates: list[str] = []
    if isinstance(data, dict):
        nested = data.get("data") if isinstance(data.get("data"), dict) else {}
        candidates.extend([
            _coerce_text(data.get("continue_url")),
            _coerce_text(data.get("continueUrl")),
            _coerce_text(data.get("url")),
            _coerce_text(data.get("redirect_url")),
            _coerce_text(data.get("redirectUrl")),
            _coerce_text(data.get("authorize_url")),
            _coerce_text(data.get("auth_url")),
            _coerce_text(nested.get("continue_url")),
            _coerce_text(nested.get("continueUrl")),
            _coerce_text(nested.get("url")),
            _coerce_text(nested.get("redirect_url")),
            _coerce_text(nested.get("redirectUrl")),
            _coerce_text(nested.get("authorize_url")),
            _coerce_text(nested.get("auth_url")),
        ])
    text = resp.text or ""
    patterns = [
        r"window\.location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]",
        r"location\.replace\(\s*['\"]([^'\"]+)['\"]",
        r"<a\b[^>]+href=['\"]([^'\"]+)['\"]",
        r"<form\b[^>]+action=['\"]([^'\"]+)['\"]",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.I):
            candidates.append(html.unescape(match.group(1)))
    for candidate in candidates:
        candidate = _coerce_text(candidate)
        if not candidate:
            continue
        joined = urllib.parse.urljoin(current_url, candidate)
        parsed = urllib.parse.urlparse(joined)
        if parsed.scheme in {"http", "https"} and parsed.netloc and is_oauth_chain_url(joined, current_url):
            return joined
    return ""


def analyze_oauth_authorize_hop(resp: ProtocolResponse, current_url: str, has_auth_session_cookie: bool) -> dict[str, Any]:
    """分析 OAuth authorize 链单跳结果，返回下一跳和当前摘要。"""
    last_url = resp.url or current_url
    next_url = next_oauth_authorize_url(resp, current_url)
    hint = oauth_response_hint(resp)
    session_ready = bool(has_auth_session_cookie and not next_url)
    final_login_url = ""
    if session_ready:
        final_login_url = last_url if "auth.openai.com" in last_url else "https://auth.openai.com/log-in"
    return {
        "status": resp.status,
        "last_url": last_url,
        "next_url": next_url,
        "hint": hint,
        "session_ready": session_ready,
        "final_login_url": final_login_url,
    }


def format_oauth_authorize_hop_log(label: str, hop: int, hop_result: dict[str, Any]) -> str:
    """把 OAuth authorize 链单跳结果压成统一日志文案。"""
    log_parts = [
        f"OAuth {label} 第 {hop} 跳：HTTP {hop_result.get('status') or '-'}",
        safe_url_for_log(_coerce_text(hop_result.get("last_url"))),
    ]
    next_url = _coerce_text(hop_result.get("next_url"))
    hint = _coerce_text(hop_result.get("hint"))
    if next_url:
        log_parts.append(f"-> {safe_url_for_log(next_url)}")
    elif hint:
        log_parts.append(f"摘要：{hint[:180]}")
    return " ".join(part for part in log_parts if part)


def extract_account_session_id_from_html(html_text: str) -> str:
    """从候选账号页 HTML 里提取 session_id。"""
    match = re.search(r"us_[A-Za-z0-9_-]{12,}", html_text or "")
    return match.group(0) if match else ""


def account_session_next_url(data: dict[str, Any], referer_url: str) -> str:
    """把 session/select 的 JSON 响应规整成下一跳 URL。"""
    next_url = extract_continue_url(data if isinstance(data, dict) else {})
    return normalize_auth_url(next_url) if next_url else referer_url


def extract_oauth_callback_url_from_error(value: Any, oauth_redirect_uri: str) -> str:
    """从异常文案里尝试捞出本机 OAuth callback URL。"""
    text = _coerce_text(value)
    for match in re.finditer(r"(https?://(?:localhost|127\.0\.0\.1):1455/auth/callback[^\s'\"<>]+)", text):
        candidate = match.group(1)
        if callback_has_code(candidate, oauth_redirect_uri):
            return candidate
    return ""


def analyze_oauth_callback_capture_hop(
    resp: ProtocolResponse,
    current_url: str,
    oauth_redirect_uri: str,
    *,
    chose_account: bool = False,
) -> dict[str, Any]:
    """分析 callback 捕获链单跳结果，决定下一步动作。

    这里只做 URL / 状态判断，不发起新的 HTTP 请求；调用方仍负责 workspace
    提交、账号选择和日志，这样协议主流程不会被一次性搬动。
    """
    last_url = resp.url or current_url
    if callback_has_code(last_url, oauth_redirect_uri):
        return {"action": "callback", "callback_url": last_url, "last_url": last_url}
    if resp.status == 200:
        if is_workspace_or_consent_url(current_url):
            return {"action": "workspace", "last_url": last_url}
        if "/choose-an-account" in current_url and not chose_account:
            return {"action": "choose_account", "last_url": last_url}
    if resp.status not in {301, 302, 303, 307, 308}:
        return {"action": "stop", "last_url": last_url}
    location = resp.location()
    if not location:
        return {"action": "stop", "last_url": last_url}
    next_url = urllib.parse.urljoin(current_url, location)
    if callback_has_code(next_url, oauth_redirect_uri):
        return {"action": "callback", "callback_url": next_url, "last_url": last_url}
    return {"action": "next", "next_url": next_url, "last_url": last_url}


def build_workspace_select_payload(session_data: dict[str, Any]) -> dict[str, Any]:
    """根据 OAuth session cookie 构造 workspace 选择请求。"""
    workspace_id = first_workspace_id(session_data if isinstance(session_data, dict) else {})
    if not workspace_id:
        return {}
    return {
        "url": "https://auth.openai.com/api/accounts/workspace/select",
        "json_data": {"workspace_id": workspace_id},
    }


def workspace_select_next_url(data: dict[str, Any]) -> str:
    """把 workspace/select 响应规整成下一跳 URL。"""
    return normalize_auth_url(extract_continue_url(data if isinstance(data, dict) else {}))


def build_organization_select_payload(data: dict[str, Any], session_data: dict[str, Any]) -> dict[str, Any]:
    """根据 workspace 响应和 session cookie 构造组织/项目选择请求。"""
    payload = data if isinstance(data, dict) else {}
    orgs = payload.get("data", {}).get("orgs", []) if isinstance(payload.get("data"), dict) else []
    session_payload = session_data if isinstance(session_data, dict) else {}
    if not orgs:
        orgs = session_payload.get("orgs") if isinstance(session_payload.get("orgs"), list) else []
    if not orgs:
        return {}
    org = orgs[0] if isinstance(orgs[0], dict) else {}
    org_id = _coerce_text(org.get("id"))
    if not org_id:
        return {}
    body: dict[str, Any] = {"org_id": org_id}
    projects = org.get("projects") if isinstance(org.get("projects"), list) else []
    if projects and isinstance(projects[0], dict) and projects[0].get("id"):
        body["project_id"] = projects[0]["id"]
    return {
        "url": "https://auth.openai.com/api/accounts/organization/select",
        "json_data": body,
    }


def decode_oauth_session_cookie_value(raw_value: Any) -> dict[str, Any]:
    """解析 OAuth session cookie 中的会话 JSON。

    这里仅处理 cookie 文本的 URL 解码、base64 补齐和 JSON 解析，不读取
    cookie jar，也不决定后续 workspace/org 选择，让协议登录类只负责取值。
    """
    raw_text = _coerce_text(raw_value)
    if not raw_text:
        return {}
    values = [raw_text]
    try:
        decoded = urllib.parse.unquote(raw_text)
        if decoded != raw_text:
            values.append(decoded)
    except Exception:
        pass
    for value in values:
        clean = value.strip().strip("\"'")
        parts = clean.split(".") if "." in clean else [clean]
        for part in parts[:2]:
            try:
                padded = part + "=" * (-len(part) % 4)
                data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="replace"))
                if isinstance(data, dict):
                    return data
            except Exception:
                continue
    return {}


def generate_openai_sentinel_token(
    device_id: str,
    flow: str,
    proxy_url: str = "",
    *,
    node_bin: str = "node",
    helper_path: Any = None,
    environ: dict[str, str] | None = None,
    run_func: Callable[..., Any] = subprocess.run,
    which_func: Callable[[str], str | None] = shutil.which,
) -> str:
    """调用本地 Node helper 生成 OpenAI Sentinel token。

    Sentinel 是协议登录的外部辅助能力：这里统一处理 node 路径解析、代理
    环境变量和 helper JSON 输出解析；调用方继续负责传入项目内 helper 路径。
    """
    final_node_bin = _coerce_text(node_bin) or "node"
    if os.path.sep not in final_node_bin and (os.path.altsep is None or os.path.altsep not in final_node_bin):
        final_node_bin = which_func(final_node_bin) or final_node_bin
    if not helper_path or not helper_path.exists():
        return ""
    try:
        env = dict(environ or os.environ)
        if proxy_url:
            env["HTTPS_PROXY"] = proxy_url
            env["HTTP_PROXY"] = proxy_url
            env["ALL_PROXY"] = proxy_url
        completed = run_func(
            [final_node_bin, str(helper_path)],
            input=json.dumps({"deviceId": device_id, "flow": flow}, ensure_ascii=False),
            text=True,
            capture_output=True,
            timeout=75,
            check=False,
            env=env,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    try:
        data = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return ""
    return _coerce_text(data.get("token"))


def oauth_response_hint(resp: ProtocolResponse) -> str:
    """把 OAuth 响应压成适合日志的短提示。"""
    content_type = _coerce_text(resp.headers.get("Content-Type") or resp.headers.get("content-type")).lower()
    text = resp.text or ""
    if "json" in content_type or text.lstrip().startswith(("{", "[")):
        return protocol_compact_error(resp.json())
    return protocol_compact_error(text)


def perform_protocol_request(
    *,
    url: str,
    method: str = "GET",
    json_data: dict[str, Any] | None = None,
    form_data: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 60,
    proxy_url: str = "",
    opener_open_func: Callable[..., Any],
    temporary_socket_proxy_func: Callable[[str], Any],
    open_with_fast_dns_func: Callable[..., Any],
    extract_cookies_func: Callable[[Any, Any], None],
    sleep_func: Callable[[float], None],
    network_error_message_func: Callable[[str, BaseException], str],
    response_factory: Callable[[int, str, Any, str], ProtocolResponse] = ProtocolResponse,
    read_response_text_func: Callable[[Any], tuple[str, bool]] = read_response_text,
) -> ProtocolResponse:
    """执行协议登录链里的单次 HTTP 请求，并复用旧脚本的重试语义。

    这里承接请求体编码、IncompleteRead 重试、HTTPError 读回正文和
    `ProtocolResponse` 装配；真正的 opener、代理上下文、DNS 打开方式、
    cookie 提取和网络错误文案仍通过注入函数由外层兼容入口提供。
    """
    body = None
    final_headers = dict(headers or {})
    if json_data is not None:
        body = json.dumps(json_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/json")
    elif form_data is not None:
        body = urllib.parse.urlencode(form_data).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, headers=final_headers, method=method)
    last_incomplete = ""
    attempts = 3 if proxy_url else 2
    for attempt in range(attempts):
        try:
            with temporary_socket_proxy_func(proxy_url), open_with_fast_dns_func(opener_open_func, req, timeout=timeout, use_cache=not bool(proxy_url)) as resp:
                extract_cookies_func(resp, req)
                raw, incomplete = read_response_text_func(resp)
                if incomplete and attempt + 1 < attempts:
                    last_incomplete = raw
                    sleep_func(0.6 + attempt * 0.7)
                    continue
                if incomplete:
                    raise RuntimeError("代理或目标站连接中途断开，响应没有读完整。请重试；如果连续出现，请更换更稳定的代理出口。")
                return response_factory(int(resp.status), resp.geturl(), resp.headers, raw)
        except urllib.error.HTTPError as exc:
            try:
                extract_cookies_func(exc, req)
            except Exception:
                pass
            raw, incomplete = read_response_text_func(exc)
            if incomplete and attempt + 1 < attempts:
                last_incomplete = raw
                sleep_func(0.6 + attempt * 0.7)
                continue
            return response_factory(int(exc.code), exc.geturl(), exc.headers, raw)
        except http.client.IncompleteRead:
            if attempt + 1 < attempts:
                sleep_func(0.6 + attempt * 0.7)
                continue
            raise RuntimeError("代理或目标站连接中途断开，响应没有读完整。请重试；如果连续出现，请更换更稳定的代理出口。")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"network error: {network_error_message_func(url, exc)}") from exc
    raise RuntimeError(last_incomplete or "代理或目标站连接中途断开，响应没有读完整。")


def _strip_html(text: str) -> str:
    """把 HTML 提示页压成可读纯文本摘要。"""
    clean = re.sub(r"<style.*?</style>", " ", text, flags=re.I | re.S)
    clean = re.sub(r"<script.*?</script>", " ", clean, flags=re.I | re.S)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = html.unescape(clean)
    return re.sub(r"\s+", " ", clean).strip()


def looks_like_html_challenge(value: str) -> bool:
    """判断响应内容是否像风控页 / Cloudflare 拒绝页。"""
    text = _coerce_text(value)
    if not text:
        return False
    lowered = text.lower()
    return bool(
        "<html" in lowered
        or "<body" in lowered
        or "body{font-family" in lowered
        or "cf-ray" in lowered
        or "cloudflare" in lowered
        or "csrf request failed" in lowered
        or "could not validate your token" in lowered
        or "access denied" in lowered
        or "unable to load site" in lowered
    )


def html_challenge_hint(value: str) -> str:
    """把风控页内容压成对操作者可读的提示。"""
    clean = _strip_html(value)
    lowered = value.lower()
    if "body{font-family" in lowered or "@keyframes" in lowered or ".container{" in lowered:
        return "ChatGPT 登录入口返回了风控/拒绝页。当前 VPS 或代理出口被目标站拦截，请更换稳定代理或干净出口后重试。"
    if "csrf request failed" in lowered or "could not validate your token" in lowered:
        return "CSRF 校验失败：登录会话的 cookie/state/token 不匹配或已失效。请保持同一代理出口后重试协议登录。"
    if "cloudflare" in lowered or "cf-ray" in lowered or "access denied" in lowered:
        return "目标站点返回了风控/Cloudflare 拒绝页。协议登录不会自动切换其他方案，请换干净出口 IP 或稳定代理后重试。"
    if "unable to load site" in lowered or "using a vpn" in lowered:
        return "目标站点拒绝当前网络出口。请换 VPS 出口 IP 或使用稳定代理。"
    return clean[:260] or "目标站点返回 HTML 拒绝页，未返回可用 JSON。"


def protocol_compact_error(data: Any) -> str:
    """把协议链响应压成适合日志的短错误摘要。"""
    def auth_block_hint(value: str) -> str:
        if "Unable to load site" not in value and "using a VPN" not in value:
            return ""
        ip_match = re.search(r"\[IP:([^\]|]+)", value)
        ray_match = re.search(r"Ray ID:([a-zA-Z0-9]+)", value)
        suffix = []
        if ip_match:
            suffix.append(f"IP {ip_match.group(1).strip()}")
        if ray_match:
            suffix.append(f"Ray {ray_match.group(1).strip()}")
        extra = f" ({', '.join(suffix)})" if suffix else ""
        return f"OpenAI 登录端点拒绝了当前服务器/IP。协议登录不会自动切换其他方案，请换出口 IP 或配置稳定代理后重试。{extra}"

    if not data:
        return "empty response"
    if isinstance(data, str):
        hint = auth_block_hint(data)
        if hint:
            return hint
        if looks_like_html_challenge(data):
            return html_challenge_hint(data)
        clean = _strip_html(data)
        return (clean or data)[:260]
    if isinstance(data, dict):
        raw = _coerce_text(data.get("raw"))
        if raw:
            hint = auth_block_hint(raw)
            if hint:
                return hint
            if looks_like_html_challenge(raw):
                return html_challenge_hint(raw)
            clean = _strip_html(raw)
        err = data.get("error")
        if isinstance(err, str):
            if looks_like_html_challenge(err):
                return html_challenge_hint(err)
            return err[:260]
        if isinstance(err, dict):
            parts = [err.get("message"), err.get("code"), err.get("type")]
            return " / ".join(str(item) for item in parts if item)[:260] or json.dumps(err, ensure_ascii=False)[:260]
        for key in ("message", "detail", "error_description", "raw"):
            if data.get(key):
                value = str(data.get(key))
                hint = auth_block_hint(value)
                if hint:
                    return hint
                if looks_like_html_challenge(value):
                    return html_challenge_hint(value)
                clean = _strip_html(value)
                return (clean or value)[:260]
    try:
        return str(data)[:260]
    except Exception:
        return "unprintable response"


def oauth2_auth_url_from_authorize(authorize_url: str) -> str:
    """把 authorize_url 变成 OpenAI OAuth API 的兼容起跳地址。"""
    parsed = urllib.parse.urlparse(authorize_url)
    if not parsed.query:
        return ""
    return urllib.parse.urlunparse(("https", "auth.openai.com", "/api/oauth/oauth2/auth", "", parsed.query, ""))


def is_oauth_chain_url(candidate_url: str, current_url: str) -> bool:
    """判断候选跳转是否仍属于协议登录的 OAuth 链路。"""
    try:
        parsed = urllib.parse.urlparse(candidate_url)
        host = (parsed.hostname or "").lower()
        marker = f"{parsed.path}?{parsed.query}".lower()
        oauth_markers = (
            "oauth",
            "auth",
            "callback",
            "login",
            "log-in",
            "authorize",
            "accounts",
            "session",
            "email-verification",
            "consent",
            "workspace",
            "organization",
            "codex",
        )
        if host in {"auth.openai.com", "auth0.openai.com", "chatgpt.com"}:
            return any(part in marker for part in oauth_markers)
        if "auth" in host and "openai.com" in host:
            return any(part in marker for part in oauth_markers)
        current = urllib.parse.urlparse(current_url)
        if host and host == (current.hostname or "").lower():
            return any(part in marker for part in oauth_markers)
    except Exception:
        return False
    return False


__all__ = [
    "authorize_continue_requires_session_retry",
    "callback_has_code",
    "build_protocol_headers",
    "html_challenge_hint",
    "extract_oauth_authorize_params",
    "extract_continue_url",
    "extract_email_verification_mode",
    "parse_oauth_callback_params",
    "extract_page_type",
    "extract_query_param",
    "first_workspace_id",
    "is_oauth_chain_url",
    "looks_like_html_challenge",
    "is_workspace_or_consent_url",
    "needs_add_phone",
    "needs_modern_otp",
    "needs_phone_channel_selection",
    "needs_phone_verification",
    "normalize_auth_url",
    "oauth_response_hint",
    "oauth2_auth_url_from_authorize",
    "payload_has_cpa_config",
    "perform_protocol_request",
    "ProtocolResponse",
    "protocol_compact_error",
    "read_response_text",
    "safe_url_for_log",
    "session_from_cpa_callback_result",
    "next_oauth_authorize_url",
    "analyze_oauth_authorize_hop",
    "extract_account_session_id_from_html",
    "account_session_next_url",
    "validate_oauth_exchange_response",
    "validate_session_response",
    "format_oauth_authorize_hop_log",
]
