"""工作区管理员同步与公共池推送。

这一层只处理 workspace 级别的管理输入和对外推送，不直接承载 mail
取信主流程；失败时保留原始响应，方便上层继续返回给前端。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from gpt_account_manager.infra import http_request_json, validate_http_base_url


def _coerce_text(value: Any) -> str:
    """统一字符串化，避免管理输入里混入 None 或空白值。"""
    return str(value or "").strip()


def _iso_now() -> str:
    """生成 UTC 时间戳，和其它 workspace 管理响应保持一致。"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_remote_base_url(base_url: str) -> None:
    """校验远程推送地址可解析且协议合法。"""
    validate_http_base_url(base_url)


def public_pool_rows_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """把前端公共池 payload 规整成可推送的行。"""
    rows = payload.get("items") or payload.get("rows") or payload.get("accounts") or []
    if not isinstance(rows, list):
        rows = []
    clean_rows: list[dict[str, Any]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        email_addr = _coerce_text(item.get("email") or item.get("address") or item.get("account"))
        jwt = _coerce_text(item.get("jwt") or item.get("token"))
        if "@" not in email_addr or not jwt:
            continue
        clean_rows.append({
            "email": email_addr,
            "jwt": jwt,
            "source": _coerce_text(item.get("source") or "temp-mail"),
            "category": _coerce_text(item.get("category") or payload.get("category") or "公益池"),
            "note": _coerce_text(item.get("note") or payload.get("note")),
        })
    return clean_rows


def push_public_pool(
    payload: dict[str, Any],
    *,
    default_target_url: str = "",
    default_token: str = "",
) -> dict[str, Any]:
    """把公共池数据推送到远程 API，或在未配置时返回待复制包。"""
    rows = public_pool_rows_from_payload(payload)
    if not rows:
        return {"success": False, "pushed": 0, "error": "没有可推送的账号"}
    target_url = _coerce_text(payload.get("target_url") or payload.get("targetUrl") or default_target_url)
    package = {
        "source": "gpt-account-manager",
        "kind": "temp-mail-jwt",
        "note": _coerce_text(payload.get("note")),
        "items": rows,
        "count": len(rows),
        "created_at": _iso_now(),
    }
    if not target_url:
        return {
            "success": True,
            "mode": "prepared",
            "pushed": 0,
            "count": len(rows),
            "package": package,
            "message": "未配置公益池 API，已生成可复制 JSON",
        }
    validate_remote_base_url(target_url)
    headers = {"Content-Type": "application/json"}
    token = _coerce_text(payload.get("pool_token") or payload.get("poolToken") or default_token)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = http_request_json(target_url, method="POST", json_data=package, headers=headers, timeout=30)
    return {
        "success": True,
        "mode": "pushed",
        "pushed": len(rows),
        "count": len(rows),
        "response": response,
    }
