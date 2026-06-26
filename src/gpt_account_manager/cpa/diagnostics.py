"""CPA 域的 401 诊断与修复编排。

这一层只负责把管理接口、探测结果和登录回刷流程串起来，不直接
依赖具体的 login 实现，具体登录/会话转换由上层通过回调注入。
"""
from __future__ import annotations

from typing import Any, Callable

from gpt_account_manager.cpa.management import (
    cpa_candidates,
    cpa_delete_auth_file,
    cpa_download_auth_file,
    cpa_probe_status,
    cpa_upload_auth_file,
)
from gpt_account_manager.cpa.service import (
    cpa_is_401_item,
    cpa_management_config,
    cpa_status_message,
    infer_auth_email,
    looks_like_openai_auth_file,
)


def _coerce_text(value: Any) -> str:
    """把任意值压成可比较文本，维持旧代码的宽松输入习惯。"""
    return str(value or "").strip()


def cpa_diagnosis_action_hint(status: str) -> str:
    """把诊断状态映射成可读提示，保持旧接口文案不变。"""
    return {
        "active": "凭证可用，可以跳过刷新",
        "refreshed": "RT 可用，已能刷新 access_token",
        "rt_rotated": "RT 可用且已轮换，建议保存新 auth",
        "rt_invalid": "RT 已失效，需要走邮箱登录重新授权",
        "session_expired": "会话已过期，需要走邮箱登录重新授权",
        "banned": "账号封禁或停用，不建议继续刷新",
        "risk_blocked": "目标站风控或地区受限，请换干净代理出口后再处理",
        "usage_limit_reached": "额度耗尽但凭证有效，暂不需要重新登录",
        "needs_login": "缺少可用 token，需要导入取码邮箱后重新授权",
        "probe_failed": "探测失败，请检查网络、CPA auth_file 或稍后重试",
        "not_openai_auth": "不是 OpenAI/Codex 凭证，已跳过",
    }.get(status, "请查看诊断详情")


def cpa_status_refreshable(status: str) -> bool:
    """判断当前状态是否还值得继续走修复链。"""
    return status in {"rt_invalid", "session_expired", "needs_login", "risk_blocked", "probe_failed"}


def diagnose_cpa_candidate(
    base_url: str,
    management_key: str,
    item: dict[str, Any],
    *,
    refresh_candidate: Callable[[dict[str, Any]], dict[str, Any]],
    status_label_func: Callable[[str], str],
) -> dict[str, Any]:
    """把单个 CPA 条目扩展成诊断结果。

    这里保留下载 auth、判断凭证类型和回刷能力的顺序，但把真正的
    refresh 行为交给上层注入，避免这一层反向依赖 login 实现。
    """
    row = dict(item)
    name = _coerce_text(row.get("name") or row.get("id"))
    auth_file: dict[str, Any] = {}
    if name and not row.get("runtime_only"):
        try:
            auth_file = cpa_download_auth_file(base_url, management_key, name)
        except Exception as exc:
            status = "probe_failed"
            message = f"下载 CPA auth 失败：{str(exc)[:220]}"
            return {
                **row,
                "name": name,
                "email": _coerce_text(row.get("email") or row.get("account")),
                "status": status,
                "status_label": status_label_func(status),
                "diagnosis": status_label_func(status),
                "message": message,
                "action_hint": "请检查 CPA 管理密钥、auth 文件名或 CPA 服务状态",
                "refreshable": False,
                "ok": False,
                "action": "diagnosis_failed",
            }
    if not row.get("runtime_only") and not looks_like_openai_auth_file(row, auth_file):
        status = "not_openai_auth"
        return {
            **row,
            "name": name,
            "email": infer_auth_email(row, auth_file) or _coerce_text(row.get("email") or row.get("account")),
            "status": status,
            "status_label": status_label_func(status),
            "diagnosis": status_label_func(status),
            "message": "不是 OpenAI/Codex 凭证，已跳过",
            "action_hint": cpa_diagnosis_action_hint(status),
            "refreshable": False,
            "ok": False,
            "action": "skipped",
        }
    try:
        diagnosis = refresh_candidate({
            "auth_file": auth_file or row,
            "row": row,
            "name": name or _coerce_text(row.get("email") or row.get("account")),
        })
    except Exception as exc:
        status = "probe_failed"
        diagnosis = {
            "status": status,
            "status_label": status_label_func(status),
            "message": f"OpenAI 深度探测失败：{str(exc)[:220]}",
            "ok": False,
            "email": infer_auth_email(row, auth_file) or _coerce_text(row.get("email") or row.get("account")),
            "name": name,
        }
    status = _coerce_text(diagnosis.get("status") or "probe_failed")
    status_label = _coerce_text(diagnosis.get("status_label") or status_label_func(status))
    return {
        **row,
        "name": name or diagnosis.get("name") or row.get("name"),
        "email": diagnosis.get("email") or infer_auth_email(row, auth_file) or _coerce_text(row.get("email") or row.get("account")),
        "status": status,
        "status_label": status_label,
        "diagnosis": status_label,
        "message": _coerce_text(diagnosis.get("message") or row.get("message") or status_label),
        "action_hint": cpa_diagnosis_action_hint(status),
        "refreshable": cpa_status_refreshable(status),
        "ok": bool(diagnosis.get("ok")),
        "plan_type": _coerce_text(diagnosis.get("plan_type")),
        "expires_at": diagnosis.get("expires_at", ""),
        "action": "diagnosed",
    }


def scan_cpa_401(
    payload: dict[str, Any],
    *,
    allow_remote: bool = False,
    diagnose_candidate: Callable[[str, str, dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """扫描 CPA 候选条目并把 401 条目送入诊断链。"""
    base_url, management_key, max_items, candidates, available_total = cpa_candidates(payload, allow_remote=allow_remote)
    results = []
    for item in candidates:
        if cpa_is_401_item(item):
            status_source = item.get("status_message") or item.get("message") or item.get("error") or "401 未授权"
            message, raw_message = cpa_status_message(status_source, status_code=401, action="401")
            results.append({
                **item,
                "email": infer_auth_email(item),
                "status_code": 401,
                "ok": False,
                "action": "401",
                "message": message,
                "raw_message": raw_message,
            })
        else:
            results.append(cpa_probe_status(base_url, management_key, item))
    diagnosis_targets = [
        item for item in results
        if item.get("action") != "ready" or _coerce_text(item.get("status_code")) in {"401", "403", "429"}
    ]
    diagnosed = [diagnose_candidate(base_url, management_key, item) for item in diagnosis_targets]
    surfaced = [
        item for item in diagnosed
        if item.get("refreshable")
        or item.get("status") in {"active", "refreshed", "rt_rotated", "banned", "risk_blocked", "usage_limit_reached", "rt_invalid", "session_expired", "needs_login", "probe_failed", "not_openai_auth"}
    ]
    refreshable_count = len([item for item in diagnosed if item.get("refreshable")])
    error_count = len([
        item for item in surfaced
        if item.get("status") not in {"active", "refreshed", "rt_rotated", "not_openai_auth"}
    ])
    return {
        "success": True,
        "total": len(candidates),
        "available_total": available_total,
        "max_items": max_items,
        "candidates": surfaced,
        "results": results,
        "diagnostics": diagnosed,
        "summary": {
            "total": len(candidates),
            "available_total": available_total,
            "candidates": len(surfaced),
            "error_accounts": error_count,
            "diagnosed": len(diagnosed),
            "credential_ok": len([item for item in diagnosed if item.get("status") in {"active", "refreshed", "rt_rotated"}]),
            "needs_login": refreshable_count,
            "refreshable": refreshable_count,
            "unscanned": max(0, available_total - len(candidates)),
            "banned": len([item for item in diagnosed if item.get("status") == "banned"]),
            "risk": len([item for item in diagnosed if item.get("status") == "risk_blocked"]),
            "limited": len([item for item in diagnosed if item.get("status") == "usage_limit_reached"]),
            "uploaded": 0,
            "deleted": 0,
            "failed": len([item for item in results if item.get("action") == "probe_failed"]),
            "skipped": len([item for item in results if item.get("action") == "skipped"]),
        },
    }


def repair_cpa_401(
    payload: dict[str, Any],
    *,
    allow_remote: bool = False,
    diagnose_candidate: Callable[[str, str, dict[str, Any]], dict[str, Any]],
    build_login_payload: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    login_runner: Callable[[str, dict[str, Any]], dict[str, Any]],
    session_to_auth: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """重跑 CPA 401 修复链。

    这里把“挑候选、拉 auth、重登、回刷、上传”的编排集中起来，
    具体登录实现和 session 转 auth 通过回调注入。
    """
    if isinstance(payload.get("items"), list) and payload["items"]:
        scanned = {"candidates": payload["items"], "summary": {"total": len(payload["items"])}}
    else:
        scanned = scan_cpa_401(payload, allow_remote=allow_remote, diagnose_candidate=diagnose_candidate)
    base_url, management_key = cpa_management_config(payload, allow_remote=allow_remote)
    results = []
    uploaded = 0
    deleted = 0
    failed = 0
    for item in scanned.get("candidates", []):
        row = dict(item)
        name = _coerce_text(row.get("name") or row.get("id"))
        auth_file: dict[str, Any] = {}
        try:
            if name and not row.get("runtime_only"):
                auth_file = cpa_download_auth_file(base_url, management_key, name)
        except Exception as exc:
            row["download_error"] = str(exc)[:240]
        email_addr = infer_auth_email(row, auth_file)
        row["email"] = email_addr or _coerce_text(row.get("email") or row.get("account"))
        if not row.get("runtime_only") and not looks_like_openai_auth_file(row, auth_file):
            results.append({**row, "ok": False, "action": "skipped", "message": "不是 Codex/OpenAI 凭证，已跳过"})
            continue
        if "@" not in row["email"]:
            results.append({**row, "ok": False, "action": "skipped", "message": "无法从 CPA 凭证识别邮箱"})
            continue
        try:
            login_payload = build_login_payload(payload, row)
            session_payload = login_runner("_warehouse_sync", {**login_payload, "login_strategy": "protocol"})
            new_auth = session_to_auth(
                session_payload,
                {"email": row["email"], "name": name or row["email"], "auth_index": row.get("auth_index")},
                require_refresh_token=True,
            )
            upload = cpa_upload_auth_file(base_url, management_key, name or row["email"], new_auth)
            if not upload.get("uploaded"):
                raise RuntimeError(upload.get("error") or "上传失败")
            uploaded += 1
            results.append({**row, "ok": True, "action": "uploaded", "message": "重登成功，已上传新 CPA 凭证", "auth_file": new_auth, "upload": upload})
        except Exception as exc:
            failed += 1
            message = str(exc)[:500]
            lowered = message.lower()
            if any(word in lowered for word in ["deactivated", "disabled", "banned", "suspended", "账号已停用", "deleted or deactivated"]):
                delete_result = cpa_delete_auth_file(base_url, management_key, name)
                if delete_result.get("deleted"):
                    deleted += 1
                    results.append({**row, "ok": True, "action": "deleted_deactivated", "message": "账号已停用，已删除 CPA 凭证"})
                    continue
            results.append({**row, "ok": False, "action": "login_failed", "message": f"重新登录失败：{message}"})
    return {
        "success": True,
        "results": results,
        "summary": {
            "total": scanned.get("summary", {}).get("total", 0),
            "candidates": len(scanned.get("candidates", [])),
            "uploaded": uploaded,
            "deleted": deleted,
            "failed": failed,
            "skipped": 0,
        },
    }


__all__ = [
    "cpa_diagnosis_action_hint",
    "cpa_status_refreshable",
    "diagnose_cpa_candidate",
    "repair_cpa_401",
    "scan_cpa_401",
]
