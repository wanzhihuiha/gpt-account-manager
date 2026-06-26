"""登录任务的运行时状态。

这里只管任务内存态、日志、取消和手工验证码，不碰协议登录主流程，也不
在这里引入页面编排。这样 `server.py` 里的登录 job 入口可以逐步退成薄壳。
"""
from __future__ import annotations

import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from gpt_account_manager.core.refresh_state import (
    is_terminal_refresh_state,
    normalize_refresh_state,
    refresh_state_from_step,
    refresh_status_for_state,
)
from gpt_account_manager.storage.login_history import append_login_history_entry
from gpt_account_manager.storage.workspace import normalize_workspace_id, workspace_file

from .errors import LoginFlowError


REPO_ROOT = Path(__file__).resolve().parents[3]
WORKSPACES_ROOT = REPO_ROOT / "data" / "workspaces"
LOGIN_DEBUG_DIR = REPO_ROOT / "data" / "login_debug"
LOGIN_JOBS: dict[str, dict[str, Any]] = {}
LOGIN_JOBS_LOCK = threading.Lock()
LOGIN_LOG_LIMIT = 400


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def login_job_public(job: dict[str, Any]) -> dict[str, Any]:
    """给前端和接口返回的登录任务摘要。

    这里刻意只返回稳定字段，避免把内部状态、原始对象和大日志直接暴露给
    调用方。
    """
    return {
        "job_id": job.get("job_id"),
        "status": job.get("status"),
        "state": job.get("state", job.get("status")),
        "email": job.get("email", ""),
        "name": job.get("name", ""),
        "logs": list(job.get("logs", []))[-LOGIN_LOG_LIMIT:],
        "result": job.get("result"),
        "error": job.get("error", ""),
        "error_code": job.get("error_code", ""),
        "error_hint": job.get("error_hint", ""),
        "retryable": job.get("retryable", True),
        "http_status": job.get("http_status"),
        "created_at": job.get("created_at", ""),
        "updated_at": job.get("updated_at", ""),
    }


def append_login_log(job_id: str, message: str, level: str = "info", step: str = "") -> None:
    """给登录任务追加一条日志，并同步更新任务状态时间戳。"""
    entry = {
        "time": _iso_now(),
        "level": level,
        "step": step,
        "message": str(message)[:600],
    }
    with LOGIN_JOBS_LOCK:
        job = LOGIN_JOBS.get(job_id)
        if not job:
            return
        logs = job.setdefault("logs", [])
        logs.append(entry)
        if len(logs) > LOGIN_LOG_LIMIT:
            del logs[:len(logs) - LOGIN_LOG_LIMIT]
        derived_state = refresh_state_from_step(step)
        if derived_state and not is_terminal_refresh_state(derived_state):
            job["state"] = derived_state
        job["updated_at"] = entry["time"]


def set_login_job_status(job_id: str, status: str, **updates: Any) -> None:
    """更新登录任务状态，终态时顺手落历史，失败也不要把主流程卡死。"""
    with LOGIN_JOBS_LOCK:
        job = LOGIN_JOBS.get(job_id)
        if not job:
            return
        requested_state = updates.pop("state", status)
        if status == "failed" and updates.get("error_code") == "login_cancelled":
            requested_state = "cancelled"
        next_state = normalize_refresh_state(requested_state)
        job["state"] = next_state
        job["status"] = refresh_status_for_state(next_state)
        job["updated_at"] = _iso_now()
        job.update(updates)
        if is_terminal_refresh_state(next_state):
            job["finished_at"] = job["updated_at"]
            try:
                append_login_history_entry(
                    job,
                    workspace_file(WORKSPACES_ROOT, job.get("workspace_id", "public"), "login_history.json"),
                )
            except Exception:
                # 历史记录是附加信息，不能反过来影响登录任务的终态落地。
                pass


def login_job_cancel_requested(job_id: str) -> bool:
    """检查登录任务是否收到了取消信号。"""
    if not job_id:
        return False
    with LOGIN_JOBS_LOCK:
        job = LOGIN_JOBS.get(job_id)
        return bool(job and job.get("cancel_requested"))


def raise_if_login_job_cancelled(job_id: str) -> None:
    """在关键等待点中断已取消的登录任务。"""
    if login_job_cancel_requested(job_id):
        raise LoginFlowError(
            "任务已终止",
            code="login_cancelled",
            hint="用户已手动终止这个刷新任务。",
            retryable=False,
        )


def cancel_login_job(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    """标记登录任务取消；工作区不一致时直接拒绝。"""
    job_id = str(payload.get("job_id") or payload.get("jobId") or "").strip()
    if not job_id:
        raise RuntimeError("登录任务不存在")
    expected_workspace = normalize_workspace_id(workspace_id)
    with LOGIN_JOBS_LOCK:
        job = LOGIN_JOBS.get(job_id)
        if not job:
            raise RuntimeError("登录任务不存在")
        job_workspace = normalize_workspace_id(job.get("workspace_id"))
        if expected_workspace and job_workspace != expected_workspace:
            raise RuntimeError("登录任务不属于当前工作区")
        job["cancel_requested"] = True
        job["updated_at"] = _iso_now()
        if job.get("status") in {"queued", "running"}:
            job["status"] = "failed"
            job["state"] = "cancelled"
            job["error"] = "任务已终止"
            job["error_code"] = "login_cancelled"
            job["error_hint"] = "用户已手动终止这个刷新任务。"
            job["retryable"] = False
            job["finished_at"] = job["updated_at"]
    append_login_log(job_id, "任务已终止", "warning", "cancel")
    return {"success": True, "job": login_job_public(LOGIN_JOBS.get(job_id, {}))}


def get_login_job(job_id: str, workspace_id: str = "") -> dict[str, Any]:
    """按工作区读取单个登录任务的公开视图。

    这里仍然只暴露 `login_job_public(...)` 的稳定字段，不把任务内存态原对象
    直接透传给接口层；工作区校验失败时继续沿用旧错误文案，避免前端状态页
    因为本轮结构迁移而改判失败原因。
    """
    normalized_job_id = str(job_id or "").strip()
    with LOGIN_JOBS_LOCK:
        job = LOGIN_JOBS.get(normalized_job_id)
        if not job:
            raise RuntimeError("登录任务不存在")
        expected_workspace = normalize_workspace_id(workspace_id)
        job_workspace = normalize_workspace_id(job.get("workspace_id"))
        if expected_workspace and job_workspace != expected_workspace:
            raise RuntimeError("登录任务不属于当前工作区")
        return {"success": True, "job": login_job_public(job)}


def clean_manual_email_code(value: Any) -> str:
    """把手工输入的验证码压成 4-8 位纯数字。"""
    code = str(value or "").strip()
    return code if re.fullmatch(r"\d{4,8}", code) else ""


def manual_email_code_for_payload(payload: dict[str, Any]) -> str:
    """优先从请求体取邮箱验证码，取不到就回看当前 job。"""
    code = clean_manual_email_code(
        payload.get("manual_email_code")
        or payload.get("email_code")
        or payload.get("verification_code")
    )
    if code:
        return code
    job_id = str(payload.get("job_id") or "").strip()
    if not job_id:
        return ""
    with LOGIN_JOBS_LOCK:
        job = LOGIN_JOBS.get(job_id)
        if not job:
            return ""
        return clean_manual_email_code(job.get("manual_email_code"))


def set_login_manual_email_code(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    """把手工邮箱验证码挂到当前任务上，供后续登录轮询消费。"""
    job_id = str(payload.get("job_id") or payload.get("jobId") or "").strip()
    code = clean_manual_email_code(
        payload.get("manual_email_code")
        or payload.get("email_code")
        or payload.get("verification_code")
    )
    if not job_id:
        raise RuntimeError("登录任务不存在")
    if not code:
        raise RuntimeError("请输入 4-8 位邮箱验证码")
    expected_workspace = normalize_workspace_id(workspace_id)
    with LOGIN_JOBS_LOCK:
        job = LOGIN_JOBS.get(job_id)
        if not job:
            raise RuntimeError("登录任务不存在")
        job_workspace = normalize_workspace_id(job.get("workspace_id"))
        if expected_workspace and job_workspace != expected_workspace:
            raise RuntimeError("登录任务不属于当前工作区")
        job["manual_email_code"] = code
        job["updated_at"] = _iso_now()
    append_login_log(job_id, "已收到手动邮箱验证码", "info", "manual_email_code")
    return {"success": True, "job_id": job_id}


def manual_phone_code_for_payload(payload: dict[str, Any]) -> str:
    """把手机验证码按同样规则规整，保持邮箱/手机入口口径一致。"""
    code = clean_manual_email_code(
        payload.get("manual_phone_code")
        or payload.get("phone_code")
        or payload.get("sms_code")
    )
    if code:
        return code
    job_id = str(payload.get("job_id") or "").strip()
    if not job_id:
        return ""
    with LOGIN_JOBS_LOCK:
        job = LOGIN_JOBS.get(job_id)
        if not job:
            return ""
        return clean_manual_email_code(job.get("manual_phone_code"))


def set_login_manual_phone_code(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    """把手工手机验证码挂到任务上，供后续验证步骤复用。"""
    job_id = str(payload.get("job_id") or payload.get("jobId") or "").strip()
    code = clean_manual_email_code(
        payload.get("manual_phone_code")
        or payload.get("phone_code")
        or payload.get("sms_code")
    )
    if not job_id:
        raise RuntimeError("登录任务不存在")
    if not code:
        raise RuntimeError("请输入 4-8 位手机验证码")
    expected_workspace = normalize_workspace_id(workspace_id)
    with LOGIN_JOBS_LOCK:
        job = LOGIN_JOBS.get(job_id)
        if not job:
            raise RuntimeError("登录任务不存在")
        job_workspace = normalize_workspace_id(job.get("workspace_id"))
        if expected_workspace and job_workspace != expected_workspace:
            raise RuntimeError("登录任务不属于当前工作区")
        job["manual_phone_code"] = code
        job["updated_at"] = _iso_now()
    append_login_log(job_id, "已收到手动手机验证码", "info", "manual_phone_code")
    return {"success": True, "job_id": job_id}


def run_cpa_login_job(
    job_id: str,
    payload: dict[str, Any],
    *,
    resolve_cpa_login_session_payload_func: Callable[..., dict[str, Any]],
    finalize_cpa_login_job_success_func: Callable[..., dict[str, Any]],
    finalize_cpa_login_job_failure_func: Callable[..., None],
    require_login_proxy_url_func: Callable[[dict[str, Any]], str],
    coerce_text_func: Callable[[Any], str],
    probe_egress_trace_func: Callable[[str], dict[str, Any]],
    sleep_func: Callable[[float], None],
    run_chatgpt_login_with_protocol_func: Callable[[str, dict[str, Any]], dict[str, Any]],
    session_to_cpa_auth_func: Callable[..., dict[str, Any]],
    append_refresh_result_func: Callable[..., Any],
    replace_cpa_auth_file_func: Callable[[dict[str, Any]], dict[str, Any]],
    workspace_file_func: Callable[[str, str], Any],
    finalize_cpa_login_success_func: Callable[..., dict[str, Any]],
    classify_login_exception_func: Callable[[Exception], dict[str, Any]],
) -> None:
    """执行 CPA 登录后台任务的状态推进。

    这里仅负责登录 job 的生命周期：设置运行态、追加起始日志、调用应用层
    完成 session 获取和 CPA 成功/失败收口。跨域业务仍通过注入函数交给
    `app.facade`，避免 `login.jobs` 直接依赖 CPA 或旧兼容入口。
    """
    set_login_job_status(job_id, "running")
    append_login_log(job_id, "任务启动", "info", "start")
    try:
        session_payload = resolve_cpa_login_session_payload_func(
            job_id=job_id,
            payload=payload,
            require_login_proxy_url_func=require_login_proxy_url_func,
            coerce_text_func=coerce_text_func,
            append_login_log_func=append_login_log,
            probe_egress_trace_func=probe_egress_trace_func,
            sleep_func=sleep_func,
            run_chatgpt_login_with_protocol_func=run_chatgpt_login_with_protocol_func,
        )
        result = finalize_cpa_login_job_success_func(
            job_id=job_id,
            payload=payload,
            session_payload=session_payload if isinstance(session_payload, dict) else {},
            session_to_cpa_auth_func=session_to_cpa_auth_func,
            append_refresh_result_func=append_refresh_result_func,
            replace_cpa_auth_file_func=replace_cpa_auth_file_func,
            append_login_log_func=append_login_log,
            workspace_file_func=workspace_file_func,
            coerce_text_func=coerce_text_func,
            finalize_cpa_login_success_func=finalize_cpa_login_success_func,
        )
        set_login_job_status(job_id, "success", result=result)
    except Exception as exc:
        finalize_cpa_login_job_failure_func(
            job_id=job_id,
            exc=exc,
            classify_login_exception_func=classify_login_exception_func,
            append_login_log_func=append_login_log,
            set_login_job_status_func=set_login_job_status,
        )


def start_cpa_login_job(
    payload: dict[str, Any],
    workspace_id: str = "public",
    *,
    prepare_cpa_login_job_start_func: Callable[..., dict[str, Any]],
    coerce_text_func: Callable[[Any], str],
    first_text_func: Callable[..., str],
    require_login_proxy_url_func: Callable[[dict[str, Any]], str],
    normalize_workspace_id_func: Callable[[Any], str],
    normalize_cpa_base_url_func: Callable[[str], str],
    generate_job_id_func: Callable[[], str],
    now_func: Callable[[], str],
    hydrate_login_mail_credentials_func: Callable[[dict[str, Any], str], dict[str, int]],
    login_mail_credential_counts_func: Callable[[dict[str, Any]], dict[str, int]],
    default_cpa_base_url: str,
    run_cpa_login_job_func: Callable[[str, dict[str, Any]], None],
    thread_factory: Callable[..., threading.Thread] = threading.Thread,
) -> dict[str, Any]:
    """创建并启动 CPA 登录任务。

    参数准备和跨域校验仍由 `app.facade.prepare_cpa_login_job_start` 完成；
    任务层只负责把 job 放进登录任务表、记录邮箱凭据摘要并启动后台线程。
    """
    prepared = prepare_cpa_login_job_start_func(
        payload,
        workspace_id,
        coerce_text_func=coerce_text_func,
        first_text_func=first_text_func,
        require_login_proxy_url_func=require_login_proxy_url_func,
        normalize_workspace_id_func=normalize_workspace_id_func,
        normalize_cpa_base_url_func=normalize_cpa_base_url_func,
        generate_job_id_func=generate_job_id_func,
        now_func=now_func,
        hydrate_login_mail_credentials_func=hydrate_login_mail_credentials_func,
        login_mail_credential_counts_func=login_mail_credential_counts_func,
        default_cpa_base_url=default_cpa_base_url,
    )
    prepared_payload = prepared["payload"]
    job = prepared["job"]
    job_id = coerce_text_func(job.get("job_id"))
    with LOGIN_JOBS_LOCK:
        LOGIN_JOBS[job_id] = job
    summary = prepared["mail_credential_summary"] if isinstance(prepared.get("mail_credential_summary"), dict) else {}
    if summary.get("added") or summary.get("updated"):
        append_login_log(
            job_id,
            (
                "邮箱取码凭据已从服务端补齐："
                f"Outlook {summary.get('microsoft', 0)}，临时邮箱 {summary.get('temp', 0)}，"
                f"普通邮箱 {summary.get('generic', 0)}"
            ),
            "info",
            "mail_credentials",
        )
    counts = prepared["mail_credential_counts"] if isinstance(prepared.get("mail_credential_counts"), dict) else login_mail_credential_counts_func(prepared_payload)
    append_login_log(
        job_id,
        (
            f"邮箱取码凭据：Outlook {counts.get('microsoft', 0)}，"
            f"临时邮箱 {counts.get('temp', 0)}，普通邮箱 {counts.get('generic', 0)}"
        ),
        "info" if counts.get("total", 0) else "warning",
        "mail_credentials",
    )
    thread = thread_factory(target=run_cpa_login_job_func, args=(job_id, prepared_payload), daemon=True)
    thread.start()
    return {"success": True, "job": login_job_public(job)}


__all__ = [
    "start_cpa_login_job",
    "run_cpa_login_job",
    "LOGIN_DEBUG_DIR",
    "LOGIN_JOBS",
    "LOGIN_JOBS_LOCK",
    "LOGIN_LOG_LIMIT",
    "append_login_log",
    "cancel_login_job",
    "clean_manual_email_code",
    "login_job_cancel_requested",
    "get_login_job",
    "login_job_public",
    "manual_email_code_for_payload",
    "manual_phone_code_for_payload",
    "raise_if_login_job_cancelled",
    "set_login_job_status",
    "set_login_manual_email_code",
    "set_login_manual_phone_code",
]
