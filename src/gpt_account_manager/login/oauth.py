"""登录域的纯 token / OAuth 辅助函数。

这里只放不碰网络、不碰 I/O 的纯转换与判定，给登录主流程和 CPA
修复链复用。这样上层在处理 session、JWT 和错误文案时，能有一个
稳定的纯函数落点。
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any


def normal_plan_type(value: str) -> str:
    """把 OpenAI 订阅标记规整成稳定的小写字符串。"""
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "team" in raw:
        return "team"
    if "pro" in raw and "plus" not in raw:
        return "pro"
    if "plus" in raw:
        return "plus"
    if "free" in raw:
        return "free"
    return raw[:40]


def jwt_payload(token: str) -> dict[str, Any]:
    """解析 JWT 的 payload 段，只做本地解码，不做签名校验。"""
    try:
        part = str(token or "").split(".")[1]
        padded = part.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        payload = json.loads(base64.b64decode(padded).decode("utf-8", errors="replace"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def access_token_email(token: str) -> str:
    """从 access token 里提取邮箱，供登录和同步流程兜底使用。"""
    payload = jwt_payload(token)
    profile = payload.get("https://api.openai.com/profile")
    if isinstance(profile, dict):
        return str(profile.get("email") or "").strip().lower()
    return str(payload.get("email") or "").strip().lower()


def access_token_plan_type(token: str) -> str:
    """从 access token 里读取计划类型，保持对旧流程的兼容。"""
    payload = jwt_payload(token)
    auth = payload.get("https://api.openai.com/auth")
    if isinstance(auth, dict):
        return normal_plan_type(auth.get("chatgpt_plan_type"))
    return ""


def access_token_expires_at(token: str) -> str:
    """把 access token 的 exp 转成可读时间戳。"""
    payload = jwt_payload(token)
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        return datetime.fromtimestamp(exp, timezone.utc).isoformat(timespec="seconds")
    return ""


def classify_oauth_error(status: int, data: dict[str, Any], raw: str) -> tuple[str, str]:
    """把 OAuth 错误压成状态码和说明，供上层做统一分支。"""
    err_obj = data.get("error")
    if isinstance(err_obj, dict):
        err = _first_text(err_obj.get("code"), err_obj.get("type"), err_obj.get("error"))
        desc = _first_text(err_obj.get("message"), data.get("error_description"), data.get("message"), data.get("detail"), raw)
    else:
        err = str(err_obj or "").strip()
        desc = _first_text(data.get("error_description"), data.get("message"), data.get("detail"), raw)
    lowered = f"{err} {desc}".lower()
    if err in {"invalid_grant", "invalid_client", "unauthorized_client", "invalid_request", "token_expired"} or status in {400, 401}:
        if any(word in lowered for word in ["deactivated", "disabled", "banned", "suspended", "封禁", "停用"]):
            return "banned", desc or err or f"HTTP {status}"
        return "rt_invalid", desc or err or f"HTTP {status}"
    if status == 403:
        return "risk_blocked", desc or "OpenAI 拒绝刷新请求"
    return "probe_failed", desc or f"HTTP {status}"


def build_synthetic_id_token(email_addr: str, account_id: str, plan_type: str, expires_at: str) -> str:
    """构造一个仅用于本地兼容的 synthetic id_token。"""
    def encode(value: dict[str, Any]) -> str:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    now = int(datetime.now(timezone.utc).timestamp())
    exp = now + 3600
    if expires_at:
        try:
            exp = int(datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp())
        except Exception:
            pass
    return ".".join([
        encode({"alg": "none", "typ": "JWT", "cpa_synthetic": True}),
        encode({
            "iss": "ctgptm-mail-assistant",
            "aud": "chatgpt",
            "email": email_addr,
            "chatgpt_account_id": account_id,
            "account_id": account_id,
            "chatgpt_plan_type": plan_type,
            "iat": now,
            "exp": exp,
        }),
        "synthetic",
    ])


def _first_text(*values: Any) -> str:
    """返回第一个非空文本，保持旧逻辑的优先命中顺序。"""
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


__all__ = [
    "access_token_email",
    "access_token_expires_at",
    "access_token_plan_type",
    "build_synthetic_id_token",
    "classify_oauth_error",
    "jwt_payload",
    "normal_plan_type",
]
