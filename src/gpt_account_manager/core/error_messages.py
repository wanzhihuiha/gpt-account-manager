"""用户可见错误文案的统一中文化。"""
from __future__ import annotations

import re
from typing import Any


def _coerce_text(value: Any) -> str:
    return str(value or "").strip()


_EXACT_TRANSLATIONS = {
    "Unauthorized": "未授权，请先登录或检查访问令牌。",
    "MAIL_PICKUP_ADMIN_TOKEN is not set.": "管理员令牌未配置，当前服务暂不可用。",
    "MAIL_PICKUP_ADMIN_TOKEN is required for admin APIs on this server.": "当前服务未配置管理员令牌，管理员接口不可用。",
    "base_url is required": "必须填写 API 地址。",
    "base_url host missing": "API 地址缺少主机名。",
    "base_url must use http or https": "API 地址必须使用 http 或 https 协议。",
    "private or local base_url is blocked": "禁止使用本地或内网 API 地址。",
    "configured temp worker URL host missing": "临时邮箱 Worker 地址缺少主机名。",
    "GPT_ACCOUNT_MANAGER_TEMP_WORKER_URL is required for temp mailbox refresh": "临时邮箱刷新需要配置 GPT_ACCOUNT_MANAGER_TEMP_WORKER_URL。",
    "generic IMAP host missing": "普通邮箱缺少 IMAP 主机地址。",
    "generic POP3 host missing": "普通邮箱缺少 POP3 主机地址。",
    "generic mail password missing": "普通邮箱缺少密码或令牌。",
    "Inbucket mailbox missing": "Inbucket 邮箱地址缺失。",
    "OAuth callback missing authorization code": "OAuth 回调缺少授权码。",
    "invalid email": "邮箱格式不正确。",
    "address id missing": "临时邮箱后台返回的地址 ID 缺失。",
    "jwt missing": "临时邮箱后台未返回 JWT。",
    "not found": "未找到对应记录。",
}

_PATTERN_TRANSLATIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^Line (\d+): expected email----password----client_id----refresh_token$"), r"第\1行：格式错误，应为 email----password----client_id----refresh_token。"),
    (re.compile(r"^Line (\d+): invalid account fields$"), r"第\1行：微软账号字段不完整或格式不正确。"),
    (re.compile(r"^Line (\d+): invalid temp email$"), r"第\1行：临时邮箱格式不正确。"),
    (re.compile(r"^Line (\d+): invalid generic email$"), r"第\1行：普通邮箱格式不正确。"),
    (re.compile(r"^Line (\d+): missing password/token$"), r"第\1行：缺少密码或令牌。"),
    (re.compile(r"^Account (\d+): invalid object$"), r"第\1个微软账号对象格式不正确。"),
    (re.compile(r"^Account (\d+): missing email/client_id/refresh_token$"), r"第\1个微软账号缺少 email、client_id 或 refresh_token。"),
    (re.compile(r"^Temp address (\d+): invalid object$"), r"第\1个临时邮箱对象格式不正确。"),
    (re.compile(r"^Temp address (\d+): invalid email$"), r"第\1个临时邮箱地址格式不正确。"),
    (re.compile(r"^Temp address (\d+): missing jwt$"), r"第\1个临时邮箱缺少 JWT。"),
    (re.compile(r"^Generic account (\d+): invalid object$"), r"第\1个普通邮箱对象格式不正确。"),
    (re.compile(r"^Generic account (\d+): invalid email$"), r"第\1个普通邮箱地址格式不正确。"),
    (re.compile(r"^Generic account (\d+): missing password/token$"), r"第\1个普通邮箱缺少密码或令牌。"),
    (re.compile(r"^(.+?) must start with http:// or https://$"), r"\1 必须以 http:// 或 https:// 开头。"),
    (re.compile(r"^(.+?) host missing$"), r"\1 缺少主机名。"),
    (re.compile(r"^Unsupported provider: (.+)$"), r"不支持的邮箱提供商：\1。"),
    (re.compile(r"^unsupported source: (.+)$"), r"不支持的邮箱来源：\1。"),
    (re.compile(r"^Temp API DNS lookup failed\. Check the Worker URL: (.+)$"), r"临时邮箱 API 的 DNS 解析失败，请检查 Worker 地址：\1"),
    (re.compile(r"^([A-Za-z_][\w.]*)\(\) missing (\d+) required keyword-only arguments?: (.+)$"), r"函数 \1() 调用缺少 \2 个必填关键字参数：\3。"),
    (re.compile(r"^([A-Za-z_][\w.]*)\(\) missing (\d+) required positional arguments?: (.+)$"), r"函数 \1() 调用缺少 \2 个必填位置参数：\3。"),
    (re.compile(r"^([A-Za-z_][\w.]*)\(\) takes (\d+) positional arguments? but (\d+) (?:was|were) given$"), r"函数 \1() 的位置参数数量不匹配：定义接收 \2 个，实际传入 \3 个。"),
    (re.compile(r"^([A-Za-z_][\w.]*)\(\) takes from (\d+) to (\d+) positional arguments? but (\d+) were given$"), r"函数 \1() 的位置参数数量不匹配：定义接收 \2 到 \3 个，实际传入 \4 个。"),
    (re.compile(r"^([A-Za-z_][\w.]*)\(\) got multiple values for argument '(.+)'$"), r"函数 \1() 的参数 \2 被重复传入。"),
    (re.compile(r"^([A-Za-z_][\w.]*)\(\) got an unexpected keyword argument '(.+)'$"), r"函数 \1() 收到了未预期的关键字参数：\2。"),
]


def localize_error_text(value: Any) -> str:
    """把用户可见错误尽量转成中文；已是中文时原样返回。"""
    text = _coerce_text(value)
    if not text:
        return text
    if text in _EXACT_TRANSLATIONS:
        return _EXACT_TRANSLATIONS[text]
    for pattern, replacement in _PATTERN_TRANSLATIONS:
        if pattern.match(text):
            return pattern.sub(replacement, text)

    lowered = text.lower()
    if "temporary failure in name resolution" in lowered or "name or service not known" in lowered or "getaddrinfo failed" in lowered:
        return f"DNS 解析失败，请检查域名、代理或网络配置。原始错误：{text}"
    if "connection refused" in lowered or "connection reset" in lowered or "remote end closed connection" in lowered:
        return f"网络连接失败，请检查服务地址、代理或目标服务状态。原始错误：{text}"
    if "timed out" in lowered or "timeout" in lowered:
        return f"请求超时，请稍后重试或更换代理。原始错误：{text}"
    if lowered == "unauthorized":
        return "未授权，请先登录或检查访问令牌。"
    return text


def localize_error_payload(payload: Any) -> Any:
    """递归中文化 JSON 里的错误字段。"""
    if isinstance(payload, dict):
        localized: dict[str, Any] = {}
        for key, value in payload.items():
            if key in {"error", "error_hint"}:
                localized[key] = localize_error_text(value)
                continue
            if key == "errors" and isinstance(value, list):
                localized[key] = [
                    localize_error_text(item) if isinstance(item, str) else localize_error_payload(item)
                    for item in value
                ]
                continue
            localized[key] = localize_error_payload(value)
        return localized
    if isinstance(payload, list):
        return [localize_error_payload(item) for item in payload]
    return payload


__all__ = [
    "localize_error_payload",
    "localize_error_text",
]
