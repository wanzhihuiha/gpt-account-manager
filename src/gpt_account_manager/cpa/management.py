"""CPA 域的管理接口和探测流程。

这一层负责和 CPA 管理端点直接交互，只做列表、下载、上传、删除、
探测这类薄请求封装，不向上层混入 login / workspace / web 规则。
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any

from gpt_account_manager.cpa.service import (
    cpa_auth_filename,
    cpa_headers,
    cpa_item_type,
    cpa_management_config,
    cpa_probe_payload,
    cpa_status_message,
    infer_auth_email,
    looks_like_openai_auth_file,
    normalize_cpa_base_url,
    validate_cpa_base_url,
)
from gpt_account_manager.infra.http import http_request_json


def _coerce_text(value: Any) -> str:
    """把任意值压成可比较的文本，保持旧代码的宽松输入语义。"""
    return str(value or "").strip()


def cpa_list_auth_files(base_url: str, management_key: str) -> list[dict[str, Any]]:
    """列出 CPA 管理端点上的 auth 文件，只做网络请求和形态规整。"""
    payload = http_request_json(
        f"{base_url}/v0/management/auth-files",
        headers=cpa_headers(management_key),
        timeout=30,
    )
    files = payload.get("files") or payload.get("data") or payload.get("items") or []
    if not isinstance(files, list):
        return []
    return [item for item in files if isinstance(item, dict)]


def cpa_download_auth_file(base_url: str, management_key: str, name: str) -> dict[str, Any]:
    """下载单个 auth 文件，兼容管理端点返回的多种 JSON 形态。"""
    if not name:
        return {}
    payload = http_request_json(
        f"{base_url}/v0/management/auth-files/download?name={urllib.parse.quote(name, safe='')}",
        headers=cpa_headers(management_key),
        timeout=30,
    )
    if isinstance(payload.get("auth_file"), dict):
        return payload["auth_file"]
    if isinstance(payload.get("authFile"), dict):
        return payload["authFile"]
    if isinstance(payload.get("data"), dict):
        return payload["data"]
    body = payload.get("body")
    if isinstance(body, str) and body.strip():
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return payload if isinstance(payload, dict) else {}


def cpa_probe_status(base_url: str, management_key: str, item: dict[str, Any]) -> dict[str, Any]:
    """探测单个 CPA 条目的可用性，只回传诊断结果，不改其它状态。"""
    auth_index = item.get("auth_index")
    name = _coerce_text(item.get("name") or item.get("id"))
    email_addr = _coerce_text(item.get("email") or item.get("account"))
    result = {
        "name": name,
        "email": email_addr,
        "auth_index": auth_index,
        "type": cpa_item_type(item),
        "provider": item.get("provider"),
        "status_code": None,
        "ok": None,
        "action": "scanned",
        "message": "",
    }
    if not auth_index:
        message, raw_message = cpa_status_message("missing auth_index", action="skipped")
        result.update({"ok": False, "action": "skipped", "message": message, "raw_message": raw_message})
        return result

    try:
        payload = http_request_json(
            f"{base_url}/v0/management/api-call",
            method="POST",
            json_data=cpa_probe_payload(item),
            headers=cpa_headers(management_key),
            timeout=30,
        )
        status_code = payload.get("status_code")
        if status_code is None and isinstance(payload.get("body"), str):
            try:
                status_code = json.loads(payload["body"]).get("status")
            except Exception:
                status_code = None
        result["status_code"] = status_code
        status_code_text = _coerce_text(status_code)
        if status_code_text == "200":
            message, raw_message = cpa_status_message(payload, status_code=status_code, action="ready")
            result.update({"ok": True, "action": "ready", "message": message, "raw_message": raw_message})
        elif status_code_text == "401":
            message, raw_message = cpa_status_message(payload, status_code=status_code, action="401")
            result.update({"ok": False, "action": "401", "message": message, "raw_message": raw_message})
        elif status_code_text == "403":
            message, raw_message = cpa_status_message(payload, status_code=status_code, action="risk_blocked")
            result.update({"ok": False, "action": "risk_blocked", "message": message, "raw_message": raw_message})
        elif status_code_text == "429":
            message, raw_message = cpa_status_message(payload, status_code=status_code, action="usage_limit_reached")
            result.update({"ok": False, "action": "usage_limit_reached", "message": message, "raw_message": raw_message})
        elif status_code_text:
            message, raw_message = cpa_status_message(payload, status_code=status_code, action="http_error")
            result.update({"ok": False, "action": "http_error", "message": message, "raw_message": raw_message})
        else:
            message, raw_message = cpa_status_message(payload, action="probe_failed")
            result.update({"ok": False, "action": "probe_failed", "message": message, "raw_message": raw_message})
    except Exception as exc:
        message, raw_message = cpa_status_message(str(exc), action="probe_failed")
        result.update({"ok": False, "action": "probe_failed", "message": message, "raw_message": raw_message})
    return result


def cpa_delete_auth_file(base_url: str, management_key: str, name: str) -> dict[str, Any]:
    """删除单个 auth 文件，只返回删除结果和原始响应。"""
    if not name:
        return {"deleted": False, "error": "missing name"}
    url = f"{base_url}/v0/management/auth-files?name={urllib.parse.quote(name, safe='')}"
    try:
        payload = http_request_json(url, method="DELETE", headers=cpa_headers(management_key), timeout=30)
        ok = payload.get("status") == "ok" or payload.get("success") is True or payload == {"status": "ok"}
        return {"deleted": ok, "payload": payload, "error": "" if ok else "delete failed"}
    except Exception as exc:
        return {"deleted": False, "error": str(exc)[:240]}


def cpa_upload_auth_file(base_url: str, management_key: str, name: str, auth_file: dict[str, Any]) -> dict[str, Any]:
    """上传或替换单个 auth 文件，保留旧接口的返回字段。"""
    filename = cpa_auth_filename(name, auth_file)
    url = f"{base_url}/v0/management/auth-files?name={urllib.parse.quote(filename, safe='')}"
    payload = http_request_json(
        url,
        method="POST",
        json_data=auth_file,
        headers=cpa_headers(management_key),
        timeout=30,
    )
    ok = payload.get("status") == "ok" or payload.get("success") is True or payload == {"status": "ok"}
    return {
        "uploaded": ok,
        "name": filename,
        "payload": payload,
        "error": "" if ok else "upload failed",
    }


def cpa_candidates(payload: dict[str, Any], *, allow_remote: bool = False) -> tuple[str, str, int, list[dict[str, Any]], int]:
    """把 CPA 管理参数和候选条目收敛成一组，供诊断/修复复用。"""
    base_url, management_key = cpa_management_config(payload, allow_remote=allow_remote)
    max_items = max(1, min(int(payload.get("max_items") or payload.get("maxItems") or 20), 50))
    files = cpa_list_auth_files(base_url, management_key)
    filtered = [
        item for item in files
        if cpa_item_type(item) in {"", "codex", "chatgpt", "openai"}
    ]
    candidates = filtered[:max_items]
    return base_url, management_key, max_items, candidates, len(filtered)


def delete_cpa_items(payload: dict[str, Any], *, allow_remote: bool = False) -> dict[str, Any]:
    """批量删除 CPA auth 文件，只做删除和结果汇总。"""
    base_url, management_key = cpa_management_config(payload, allow_remote=allow_remote)
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    results = []
    deleted = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        name = _coerce_text(item.get("name") or item.get("id"))
        row = dict(item)
        if not name:
            results.append({**row, "ok": False, "action": "delete_failed", "message": "缺少 CPA 凭证名称"})
            continue
        outcome = cpa_delete_auth_file(base_url, management_key, name)
        if outcome.get("deleted"):
            deleted += 1
            results.append({**row, "ok": True, "action": "deleted", "message": "已删除 CPA 凭证"})
        else:
            results.append({**row, "ok": False, "action": "delete_failed", "message": outcome.get("error") or "删除失败"})
    return {
        "success": True,
        "results": results,
        "summary": {
            "total": len(items),
            "candidates": len(items),
            "uploaded": 0,
            "deleted": deleted,
            "failed": len(items) - deleted,
            "skipped": 0,
        },
    }


def replace_cpa_auth_file(payload: dict[str, Any], *, allow_remote: bool = False) -> dict[str, Any]:
    """上传新的 CPA auth 文件，并尝试按名称或邮箱回查一次。"""
    base_url, management_key = cpa_management_config(payload, allow_remote=allow_remote)
    auth_file = payload.get("auth_file") or payload.get("authFile")
    if not isinstance(auth_file, dict):
        raise RuntimeError("新的 CPA auth JSON 不能为空")
    name = _coerce_text(payload.get("name") or payload.get("filename") or payload.get("old_name") or payload.get("oldName"))
    upload = cpa_upload_auth_file(base_url, management_key, name, auth_file)
    if not upload.get("uploaded"):
        return {
            "success": False,
            "error": upload.get("error") or "上传失败",
            "upload": upload,
        }

    files = cpa_list_auth_files(base_url, management_key)
    uploaded_name = _coerce_text(upload.get("name"))
    email_addr = _coerce_text(auth_file.get("email"))
    matched = next((
        item for item in files
        if _coerce_text(item.get("name") or item.get("id")).lower() == uploaded_name.lower()
    ), None)
    if matched is None and email_addr:
        matched = next((
            item for item in files
            if _coerce_text(item.get("email") or item.get("account")).lower() == email_addr.lower()
        ), None)
    probe = cpa_probe_status(base_url, management_key, matched) if matched else {}
    return {
        "success": True,
        "upload": upload,
        "result": {
            "name": uploaded_name,
            "email": email_addr,
            "action": "replaced",
            "message": "已上传并覆盖 auth file",
            "ok": True,
            "probe": probe,
        },
        "summary": {
            "total": 1,
            "candidates": 0 if probe.get("status_code") != 401 else 1,
            "uploaded": 1,
            "deleted": 0,
            "failed": 0,
            "skipped": 0,
        },
    }


__all__ = [
    "cpa_candidates",
    "cpa_delete_auth_file",
    "cpa_download_auth_file",
    "cpa_list_auth_files",
    "cpa_probe_status",
    "delete_cpa_items",
    "replace_cpa_auth_file",
    "cpa_upload_auth_file",
    "normalize_cpa_base_url",
    "validate_cpa_base_url",
]
