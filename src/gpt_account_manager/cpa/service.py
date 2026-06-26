"""CPA 域的纯 helper 与 payload 组装。

这一层不做网络请求、不碰文件、不跑任务，只负责把 CPA 相关的
文本判断、payload 拼装和错误文案收敛到一个稳定位置，方便上层
继续按 service / job 拆分。
"""
from __future__ import annotations

import json
import ipaddress
import re
import urllib.parse
from typing import Any, Callable

from gpt_account_manager.infra import http_request_json, resolve_http_host_addresses, validate_http_base_url


def _coerce_text(value: Any) -> str:
    """把任意输入收敛成可比较的字符串。"""
    return str(value or "").strip()


def _first_text(*values: Any) -> str:
    """返回第一个非空文本，保持旧代码的“优先命中”语义。"""
    for value in values:
        text = _coerce_text(value)
        if text:
            return text
    return ""


def normalize_cpa_base_url(value: str) -> str:
    """把 CPA 基础地址规整成稳定的 HTTP/HTTPS 形式。"""
    clean = _coerce_text(value)
    if clean and not re.match(r"^https?://", clean, flags=re.I):
        clean = f"https://{clean}"
    clean = clean.rstrip("/")
    if not clean:
        return ""
    parsed = urllib.parse.urlparse(clean)
    if not parsed.scheme or not parsed.netloc:
        return clean
    path = parsed.path or ""
    if path in {"", "/"}:
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    if "management.html" in path or path.startswith("/management"):
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    return clean


def _is_private_host(hostname: str) -> bool:
    """判断主机名或 IP 是否属于私网地址。"""
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname.lower() in {"localhost"}
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


def _is_loopback_host(hostname: str) -> bool:
    """判断主机名或 IP 是否为 loopback。"""
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname.lower() in {"localhost"}
    return ip.is_loopback


def validate_cpa_base_url(base_url: str, *, allow_remote: bool = False) -> None:
    """校验 CPA 地址，避免把内网地址误放到默认公网路径里。"""
    validate_http_base_url(base_url, label="CPA 地址", check_dns=False)
    parsed = urllib.parse.urlparse(base_url)
    hostname = parsed.hostname or ""
    if allow_remote or _is_loopback_host(hostname):
        return
    if _is_private_host(hostname):
        raise RuntimeError("CPA 内网地址默认关闭；如需访问内网 CPA，请设置 MAIL_PICKUP_CPA_ALLOW_REMOTE=1")
    try:
        addresses = resolve_http_host_addresses(base_url)
    except OSError:
        return
    for address in addresses:
        if _is_private_host(address):
            raise RuntimeError("CPA 地址解析到内网地址；如需访问内网 CPA，请设置 MAIL_PICKUP_CPA_ALLOW_REMOTE=1")


def parse_nested_json_value(value: Any, depth: int = 4) -> Any:
    """递归剥离多层 JSON 字符串包装。"""
    current = value
    for _ in range(depth):
        if not isinstance(current, str):
            break
        text = current.strip()
        if not text or text[0] not in "{[\"":
            break
        try:
            current = json.loads(text)
        except json.JSONDecodeError:
            break
    return current


def collect_nested_error_texts(value: Any, texts: list[str] | None = None, depth: int = 0) -> list[str]:
    """从嵌套 payload 中提取错误文本，供统一文案判断使用。"""
    if texts is None:
        texts = []
    if depth > 6 or len(texts) >= 12:
        return texts
    current = parse_nested_json_value(value)
    if isinstance(current, dict):
        priority = ("detail", "message", "error_description", "error", "status", "body", "raw")
        for key in priority:
            if key in current:
                collect_nested_error_texts(current[key], texts, depth + 1)
        for key, item in current.items():
            if key not in priority:
                collect_nested_error_texts(item, texts, depth + 1)
        return texts
    if isinstance(current, list):
        for item in current[:8]:
            collect_nested_error_texts(item, texts, depth + 1)
        return texts
    text = _coerce_text(current)
    if text and text not in texts:
        texts.append(text)
    return texts


def compact_raw_status(value: Any) -> str:
    """把复杂结构压成短文本，便于错误消息兜底展示。"""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)[:600]
    return _coerce_text(value)[:600]


def cpa_status_message(value: Any, status_code: Any = None, action: str = "") -> tuple[str, str]:
    """把 CPA 返回或异常压成可展示的中文提示。"""
    raw_parts = collect_nested_error_texts(value)
    raw_text = _first_text(*raw_parts, compact_raw_status(value))
    haystack = " ".join(raw_parts + [_coerce_text(status_code), _coerce_text(action)]).lower()
    code = _coerce_text(status_code)
    if action == "skipped" or "missing auth_index" in haystack:
        message = "缺少 auth_index，无法探测"
    elif "access deactivated" in haystack or "account deactivated" in haystack or "deactivated" in haystack:
        message = "Access Deactivated：账号已停用/封禁"
    elif code == "401" or re.search(r"\b401\b", haystack) or "unauthorized" in haystack:
        message = "授权已失效，需要重新登录"
    elif code == "403" or "forbidden" in haystack:
        message = "CPA 拒绝访问，检查管理密钥或权限"
    elif code == "422" or "unprocessable entity" in haystack:
        message = "CPA 请求参数不完整或格式不对"
    elif "invalid api key" in haystack or ("management" in haystack and "key" in haystack and "invalid" in haystack):
        message = "CPA 管理密钥无效或无权限"
    elif "temporary failure in name resolution" in haystack or "name or service not known" in haystack or "getaddrinfo" in haystack:
        message = "域名解析失败，检查服务器 DNS 或 CPA 地址"
    elif "connection refused" in haystack:
        message = "CPA 接口连接被拒绝，检查地址和端口"
    elif "network unreachable" in haystack:
        message = "网络不可达，检查 VPS 网络或代理"
    elif "timed out" in haystack or "timeout" in haystack:
        message = "CPA 请求超时"
    elif "missing status_code" in haystack:
        message = "CPA 探测没有返回状态码"
    elif "non-json" in haystack:
        message = "CPA 接口返回非 JSON"
    elif code:
        message = f"HTTP {code}"
    else:
        message = raw_text[:180] if raw_text else "-"
    return message, raw_text


def cpa_item_chatgpt_account_id(item: dict[str, Any]) -> str:
    """提取 item 里可能携带的 ChatGPT 账号 ID。"""
    for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
        value = _coerce_text(item.get(key))
        if value:
            return value
    id_token = item.get("id_token")
    if isinstance(id_token, dict):
        return _coerce_text(id_token.get("chatgpt_account_id") or id_token.get("account_id"))
    return ""


def cpa_headers(management_key: str) -> dict[str, str]:
    """组装 CPA 管理接口请求头。"""
    return {
        "Authorization": f"Bearer {management_key}",
        "X-Management-Key": management_key,
        "Accept": "application/json",
    }


def cpa_management_config(payload: dict[str, Any], *, allow_remote: bool = False) -> tuple[str, str]:
    """把 CPA 管理接口需要的 base_url 和密钥收敛成一组值。"""
    base_url = normalize_cpa_base_url(_coerce_text(payload.get("base_url") or payload.get("baseUrl")) or "http://localhost:8317")
    management_key = _coerce_text(payload.get("management_key") or payload.get("managementKey"))
    if not management_key:
        raise RuntimeError("缺少 CPA 管理密钥")
    validate_cpa_base_url(base_url, allow_remote=allow_remote)
    return base_url, management_key


def cpa_item_type(item: dict[str, Any]) -> str:
    """读取 CPA 条目的类型标记。"""
    return _coerce_text(item.get("type") or item.get("typo")).lower()


def looks_like_openai_auth_file(item: dict[str, Any], auth_file: dict[str, Any] | None = None) -> bool:
    """判断一条 auth 记录是否像 OpenAI / Codex 凭证。"""
    auth_file = auth_file or {}
    parts = [
        item.get("provider"),
        item.get("type"),
        item.get("account_type"),
        item.get("name"),
        item.get("label"),
        auth_file.get("type"),
        auth_file.get("auth_mode"),
    ]
    text = " ".join(_coerce_text(part).lower() for part in parts if part)
    return bool(
        "codex" in text
        or "openai" in text
        or "chatgpt" in text
        or auth_file.get("access_token")
        or auth_file.get("accessToken")
        or (isinstance(auth_file.get("tokens"), dict) and (auth_file["tokens"].get("access_token") or auth_file["tokens"].get("accessToken")))
    )


def infer_auth_email(item: dict[str, Any], auth_file: dict[str, Any] | None = None) -> str:
    """从 CPA 条目或 auth_file 中推断邮箱地址。"""
    auth_file = auth_file or {}
    candidates = [
        item.get("email"),
        item.get("account"),
        auth_file.get("email"),
        auth_file.get("account"),
        auth_file.get("name"),
        item.get("name"),
        item.get("id"),
    ]
    for value in candidates:
        match = re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", _coerce_text(value), flags=re.I)
        if match:
            return match.group(0).lower()
    return ""


def extract_state_from_auth_url(auth_url: str) -> str:
    """从 OAuth 授权链接里提取 state 参数。"""
    try:
        return urllib.parse.parse_qs(urllib.parse.urlparse(auth_url).query).get("state", [""])[0]
    except Exception:
        return ""


def cpa_oauth_value(payload: dict[str, Any], *keys: str) -> str:
    """安全地沿多层 key 读取 OAuth 返回字段。"""
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return _coerce_text(current)


def parse_localhost_oauth_callback(callback_url: str, expected_state: str = "") -> dict[str, str]:
    """解析本机 OAuth 回调地址，提取 code / state。"""
    raw = _coerce_text(callback_url)
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception as exc:
        raise RuntimeError("localhost OAuth 回调地址格式无效") from exc
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"localhost", "127.0.0.1"}:
        raise RuntimeError("只接受真实的 localhost / 127.0.0.1 OAuth 回调地址")
    query = urllib.parse.parse_qs(parsed.query)
    error = _first_text(query.get("error", [""])[0], query.get("error_description", [""])[0])
    if error:
        raise RuntimeError(f"OAuth 授权失败：{error}")
    code = _first_text(query.get("code", [""])[0])
    state = _first_text(query.get("state", [""])[0])
    if not code or not state:
        raise RuntimeError("localhost OAuth 回调地址缺少 code 或 state")
    if expected_state and expected_state != state:
        raise RuntimeError("localhost 回调中的 state 与本轮 CPA 授权链接不一致，请重新生成授权链接")
    return {
        "url": urllib.parse.urlunparse(parsed),
        "code": code,
        "state": state,
    }


def cpa_direct_oauth_start(payload: dict[str, Any], *, allow_remote: bool = False) -> dict[str, Any]:
    """从 CPA 管理接口生成 OAuth 授权链接。"""
    base_url, management_key = cpa_management_config(payload, allow_remote=allow_remote)
    result = http_request_json(
        f"{base_url}/v0/management/codex-auth-url",
        headers=cpa_headers(management_key),
        timeout=30,
    )
    authorize_url = _first_text(
        cpa_oauth_value(result, "url"),
        cpa_oauth_value(result, "auth_url"),
        cpa_oauth_value(result, "authUrl"),
        cpa_oauth_value(result, "data", "url"),
        cpa_oauth_value(result, "data", "auth_url"),
        cpa_oauth_value(result, "data", "authUrl"),
    )
    if not authorize_url.startswith(("http://", "https://")):
        raise RuntimeError("CPA 管理接口没有返回有效的 OAuth 授权链接")
    oauth_state = _first_text(
        cpa_oauth_value(result, "state"),
        cpa_oauth_value(result, "auth_state"),
        cpa_oauth_value(result, "authState"),
        cpa_oauth_value(result, "data", "state"),
        cpa_oauth_value(result, "data", "auth_state"),
        cpa_oauth_value(result, "data", "authState"),
        extract_state_from_auth_url(authorize_url),
    )
    return {
        "success": True,
        "authorize_url": authorize_url,
        "oauth_url": authorize_url,
        "state": oauth_state,
        "cpa_management_origin": base_url,
        "message": "CPA 已生成 OAuth 授权链接",
    }


def cpa_direct_oauth_callback(payload: dict[str, Any], *, allow_remote: bool = False) -> dict[str, Any]:
    """把本机 OAuth 回调转发给 CPA 管理接口。"""
    base_url, management_key = cpa_management_config(payload, allow_remote=allow_remote)
    callback = parse_localhost_oauth_callback(
        _coerce_text(payload.get("callback_url") or payload.get("callbackUrl") or payload.get("redirect_url") or payload.get("redirectUrl")),
        _coerce_text(payload.get("state") or payload.get("oauth_state") or payload.get("oauthState")),
    )
    result = http_request_json(
        f"{base_url}/v0/management/oauth-callback",
        method="POST",
        json_data={
            "provider": "codex",
            "redirect_url": callback["url"],
        },
        headers=cpa_headers(management_key),
        timeout=45,
    )
    return {
        "success": True,
        "callback": callback,
        "result": result,
        "message": "CPA 已接收 OAuth 回调",
    }


def cpa_probe_payload(item: dict[str, Any], *, user_agent: str) -> dict[str, Any]:
    """组装 CPA 探测请求的 body，只做 payload 拼装，不发请求。"""
    call_headers = {
        "Authorization": "Bearer $TOKEN$",
        "Content-Type": "application/json",
        "User-Agent": user_agent,
    }
    account_id = cpa_item_chatgpt_account_id(item)
    if account_id:
        call_headers["Chatgpt-Account-Id"] = account_id
    return {
        "authIndex": item.get("auth_index"),
        "method": "GET",
        "url": "https://chatgpt.com/backend-api/wham/usage",
        "header": call_headers,
    }


def cpa_is_401_item(item: dict[str, Any]) -> bool:
    """判断 CPA 条目是否属于 401 失效项。"""
    status_code = item.get("status_code") or item.get("statusCode")
    if str(status_code) == "401":
        return True
    text = " ".join(_coerce_text(item.get(key)) for key in ("status", "status_message", "error", "message", "action")).lower()
    return bool(re.search(r"\b401\b", text) or "unauthorized" in text)


def cpa_auth_filename(value: str, auth_file: dict[str, Any]) -> str:
    """把 auth 文件名规整成稳定的 json 文件名。"""
    name = _coerce_text(value)
    if not name:
        name = _coerce_text(auth_file.get("name") or auth_file.get("email") or auth_file.get("account_id") or "chatgpt-auth")
    name = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].strip()
    name = re.sub(r"[^A-Za-z0-9._@+-]+", "-", name).strip(".-")
    if not name:
        name = "chatgpt-auth"
    if not name.lower().endswith(".json"):
        name = f"{name}.json"
    return name


def build_cpa_repair_login_payload(base_payload: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """把 CPA 修复登录所需的本地凭证收敛成一个 payload。"""
    email_addr = _coerce_text(row.get("email") or row.get("account"))
    accounts = [item for item in base_payload.get("accounts", []) if isinstance(item, dict) and _coerce_text(item.get("email")).lower() == email_addr.lower()]
    temp_addresses = [item for item in base_payload.get("temp_addresses", []) if isinstance(item, dict) and _coerce_text(item.get("email")).lower() == email_addr.lower()]
    generic_accounts = [item for item in base_payload.get("generic_accounts", []) if isinstance(item, dict) and _coerce_text(item.get("email")).lower() == email_addr.lower()]
    force_email_code = _first_text(
        base_payload.get("force_email_code"),
        base_payload.get("forceEmailCode"),
        base_payload.get("email_code_login"),
        base_payload.get("emailCodeLogin"),
    ).lower() in {"1", "true", "yes", "on"}
    password = "" if force_email_code else _first_text(
        base_payload.get("password"),
        row.get("password"),
        *(item.get("password") for item in accounts),
    )
    if not accounts and not temp_addresses and not generic_accounts:
        raise RuntimeError("本地没有匹配的邮箱取件凭证")
    return {
        **base_payload,
        "login_only": True,
        "email": email_addr,
        "password": password,
        "force_email_code": force_email_code,
        "email_code_login": force_email_code,
        "name": row.get("name") or email_addr,
        "row": row,
        "accounts": accounts,
        "temp_addresses": temp_addresses,
        "generic_accounts": generic_accounts,
    }


def cpa_companion_wait_code(
    payload: dict[str, Any],
    *,
    fetch_code_func: Callable[..., str],
) -> dict[str, Any]:
    """等待 CPA Companion 登录流程需要的邮箱验证码。

    这里不自己依赖登录域的取码实现，而是让上层把“如何去邮箱里轮询验证码”
    作为回调注入进来；CPA 域只负责规整参数、约束轮询范围，并维持既有
    `success/code/error` 返回结构。
    """
    email_addr = _coerce_text(payload.get("email"))
    if not email_addr:
        raise RuntimeError("缺少邮箱地址")
    attempts = max(1, min(int(payload.get("attempts") or 20), 60))
    delay = max(1, min(float(payload.get("delay") or 5), 20))
    since = 0.0
    if payload.get("since"):
        try:
            since = float(payload.get("since"))
        except Exception:
            since = 0.0
    code = fetch_code_func(
        {
            **payload,
            "email": email_addr,
            "limit": max(1, min(int(payload.get("limit") or 20), 50)),
        },
        since=since,
        attempts=attempts,
        delay=delay,
    )
    if not code:
        return {
            "success": False,
            "error": "没有在邮箱里找到 6 位验证码",
        }
    return {
        "success": True,
        "code": code,
    }


__all__ = [
    "build_cpa_repair_login_payload",
    "cpa_companion_wait_code",
    "cpa_headers",
    "cpa_auth_filename",
    "cpa_management_config",
    "cpa_item_type",
    "cpa_is_401_item",
    "cpa_item_chatgpt_account_id",
    "cpa_direct_oauth_callback",
    "cpa_direct_oauth_start",
    "cpa_oauth_value",
    "cpa_probe_payload",
    "cpa_status_message",
    "collect_nested_error_texts",
    "compact_raw_status",
    "extract_state_from_auth_url",
    "infer_auth_email",
    "looks_like_openai_auth_file",
    "normalize_cpa_base_url",
    "parse_localhost_oauth_callback",
    "validate_cpa_base_url",
    "parse_nested_json_value",
]
