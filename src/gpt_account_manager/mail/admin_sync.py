"""邮件域的临时地址管理同步。

这一层只处理 temp mailbox 的 JWT 提取与本地同步，不参与取信主流程，
也不负责 workspace 公共池推送，避免管理动作和消息抓取混在一起。
"""
from __future__ import annotations

import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from gpt_account_manager.infra import http_json, network_error_message, validate_http_base_url

from .model.entity.account import TempAddress
from .service import load_temp_addresses, save_temp_addresses


def _coerce_text(value: Any) -> str:
    """把输入统一成字符串，便于复用同一套管理同步规则。"""
    return str(value or "").strip()


def _iso_now() -> str:
    """生成 UTC 时间戳，供新增同步记录使用。"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _usable_secret(value: Any) -> bool:
    """判断 token 是否还是可用值，避免把掩码带回同步结果。"""
    text = _coerce_text(value)
    return bool(text and not (set(text) <= {"*"} or "..." in text))


def admin_worker_headers(admin_password: str, site_password: str = "") -> dict[str, str]:
    """组装 admin worker 请求头，保持和旧接口一致的 header 命名。"""
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; GPTAccountManager/1.0)",
        "x-lang": "zh",
    }
    if admin_password:
        headers["x-admin-auth"] = admin_password
    if site_password:
        headers["x-custom-auth"] = site_password
    return headers


def payload_rows(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    """把 admin worker 返回体里的 rows/count 规整成统一结构。"""
    rows = payload.get("results") or payload.get("data") or payload.get("items") or []
    if not isinstance(rows, list):
        rows = []
    count = payload.get("count") or payload.get("total") or len(rows)
    try:
        count_int = int(count)
    except Exception:
        count_int = len(rows)
    return [row for row in rows if isinstance(row, dict)], count_int


def validate_admin_worker_url(base_url: str) -> None:
    """校验 admin worker 地址可解析且协议合法。"""
    validate_http_base_url(base_url, error_message_builder=network_error_message)


def extract_admin_jwt(base_url: str, headers: dict[str, str], email_addr: str) -> dict[str, Any]:
    """从 admin worker 查询单个邮箱的 JWT。"""
    query_email = email_addr.strip()
    result: dict[str, Any] = {
        "email": query_email,
        "address": "",
        "id": "",
        "jwt": "",
        "ok": False,
        "error": "",
    }
    if "@" not in query_email:
        result["error"] = "invalid email"
        return result
    for page in range(20):
        params = urllib.parse.urlencode({
            "limit": "100",
            "offset": str(page * 100),
            "query": query_email,
            "sort_by": "id",
            "sort_order": "desc",
        })
        payload = http_json(f"{base_url}/admin/address?{params}", headers=headers, timeout=30)
        rows, count = payload_rows(payload)
        exact = None
        for row in rows:
            name = _coerce_text(row.get("name") or row.get("address") or row.get("email"))
            if name.lower() == query_email.lower():
                exact = row
                break
        if exact:
            address_id = _coerce_text(exact.get("id"))
            if not address_id:
                result["error"] = "address id missing"
                return result
            credential = http_json(
                f"{base_url}/admin/show_password/{urllib.parse.quote(address_id)}",
                headers=headers,
                timeout=30,
            )
            result.update({
                "address": _coerce_text(exact.get("name") or exact.get("address") or exact.get("email")),
                "id": address_id,
                "jwt": _coerce_text(credential.get("jwt")),
                "ok": bool(credential.get("jwt")),
                "error": "" if credential.get("jwt") else "jwt missing",
            })
            return result
        if not rows or (page + 1) * 100 >= count:
            break
    result["error"] = "not found"
    return result


def extract_admin_jwts(payload: dict[str, Any]) -> dict[str, Any]:
    """批量提取多个邮箱的 JWT，保留逐个失败的错误信息。"""
    base_url = _coerce_text(payload.get("base_url")).rstrip("/")
    admin_password = _coerce_text(payload.get("admin_password"))
    site_password = _coerce_text(payload.get("site_password"))
    emails_raw = payload.get("emails", [])
    if isinstance(emails_raw, list):
        emails = [str(item).strip() for item in emails_raw if str(item).strip()]
    else:
        emails = [line.strip() for line in str(emails_raw).splitlines() if line.strip()]
    if isinstance(payload.get("email_list"), list):
        emails.extend(str(item).strip() for item in payload["email_list"] if str(item).strip())
    unique_emails = list(dict.fromkeys(email.lower() for email in emails))
    if not base_url:
        raise RuntimeError("base_url is required")
    if not unique_emails:
        return {"results": [], "count": 0}

    validate_admin_worker_url(base_url)
    headers = admin_worker_headers(admin_password, site_password)
    results: list[dict[str, Any]] = []
    for email_addr in unique_emails:
        try:
            results.append(extract_admin_jwt(base_url, headers, email_addr))
        except Exception as exc:
            error = str(exc)[:300]
            if "Temporary failure in name resolution" in error or "Name or service not known" in error:
                error = f"Temp API DNS lookup failed. Check the Worker URL: {error}"
            results.append({
                "email": email_addr,
                "address": "",
                "id": "",
                "jwt": "",
                "ok": False,
                "error": error,
            })
    return {"results": results, "count": len(results)}


def sync_temp_jwts_from_worker(
    payload: dict[str, Any],
    addresses_path: Path,
    *,
    default_base_url: str = "",
    default_site_password: str = "",
    normalize_temp_worker_url_func: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """把 admin worker 查询到的 JWT 同步回本地工作区。"""
    result = extract_admin_jwts(payload)
    normalize_worker = normalize_temp_worker_url_func or (lambda value: value)
    base_url = normalize_worker(_coerce_text(payload.get("base_url")).rstrip("/"))
    site_password = _coerce_text(payload.get("site_password"))
    addresses = load_temp_addresses(
        addresses_path,
        default_base_url=default_base_url,
        normalize_temp_worker_url_func=normalize_worker,
    )
    imported = 0
    updated = 0
    for item in result.get("results", []):
        if not isinstance(item, dict) or not item.get("ok") or not _usable_secret(item.get("jwt")):
            continue
        email_addr = _coerce_text(item.get("address") or item.get("email")).lower()
        if "@" not in email_addr:
            continue
        existing = addresses.get(email_addr)
        addresses[email_addr] = TempAddress(
            email=email_addr,
            jwt=_coerce_text(item.get("jwt")),
            base_url=base_url,
            site_password=site_password,
            label="临时邮箱",
            created_at=existing.created_at if existing else _iso_now(),
            updated_at=existing.updated_at if existing else _iso_now(),
        )
        if existing:
            updated += 1
        else:
            imported += 1
    if imported or updated:
        save_temp_addresses(addresses, addresses_path)
    return {
        **result,
        "success": True,
        "imported": imported,
        "updated": updated,
        "addresses": [addr.public() for addr in addresses.values()],
    }
