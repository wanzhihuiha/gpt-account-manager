"""邮件取信任务的运行时状态。

这里承接前端触发的异步收信 job：只管理内存任务表、后台线程、进度更新和
公开查询视图；真实取信、消息写回和响应瘦身都通过上层注入函数复用现有
邮件 service / web payload 能力，避免 job 层再复制业务规则。
"""
from __future__ import annotations

import secrets
import threading
from datetime import datetime, timezone
from typing import Any, Callable


MAIL_FETCH_JOBS: dict[str, dict[str, Any]] = {}
MAIL_FETCH_JOBS_LOCK = threading.Lock()
MAIL_FETCH_JOB_LIMIT = 120


def _iso_now() -> str:
    """生成任务状态使用的 UTC 时间戳。"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _coerce_text(value: Any) -> str:
    """把任务字段规整成可比较和可展示的文本。"""
    return str(value or "").strip()


def mail_fetch_job_public(job: dict[str, Any]) -> dict[str, Any]:
    """返回前端可见的收信任务摘要，避免暴露完整内部对象。"""
    return {
        "job_id": job.get("job_id"),
        "status": job.get("status"),
        "workspace_id": job.get("workspace_id"),
        "created_at": job.get("created_at", ""),
        "updated_at": job.get("updated_at", ""),
        "finished_at": job.get("finished_at", ""),
        "total": int(job.get("total") or 0),
        "processed": int(job.get("processed") or 0),
        "current_email": _coerce_text(job.get("current_email")),
        "result": job.get("result"),
        "error": job.get("error", ""),
    }


def set_mail_fetch_job(job_id: str, **updates: Any) -> None:
    """更新收信任务状态，并在终态时补 finished_at。"""
    with MAIL_FETCH_JOBS_LOCK:
        job = MAIL_FETCH_JOBS.get(job_id)
        if not job:
            return
        job.update(updates)
        job["updated_at"] = _iso_now()
        if job.get("status") in {"success", "failed"} and not job.get("finished_at"):
            job["finished_at"] = job["updated_at"]


def trim_mail_fetch_jobs() -> None:
    """裁剪过旧的内存任务，避免长期运行时状态无限增长。"""
    with MAIL_FETCH_JOBS_LOCK:
        if len(MAIL_FETCH_JOBS) <= MAIL_FETCH_JOB_LIMIT:
            return
        ordered = sorted(
            MAIL_FETCH_JOBS.values(),
            key=lambda item: _coerce_text(item.get("updated_at") or item.get("created_at")),
        )
        for job in ordered[:max(0, len(MAIL_FETCH_JOBS) - MAIL_FETCH_JOB_LIMIT)]:
            MAIL_FETCH_JOBS.pop(_coerce_text(job.get("job_id")), None)


def run_client_mail_fetch_job(
    job_id: str,
    payload: dict[str, Any],
    workspace_id: str,
    *,
    normalize_workspace_id_func: Callable[[Any], str],
    fetch_transient_client_mail_func: Callable[..., dict[str, Any]],
    upsert_messages_func: Callable[[list[dict[str, Any]], Any], None],
    workspace_file_func: Callable[[str, str], Any],
    lightweight_fetch_result_func: Callable[..., dict[str, Any]],
) -> None:
    """执行后台收信任务并把进度写回任务表。"""
    try:
        workspace = normalize_workspace_id_func(workspace_id)
        result = fetch_transient_client_mail_func(payload, progress_callback=lambda progress: set_mail_fetch_job(job_id, **progress))
        messages = result.get("messages", []) if isinstance(result.get("messages"), list) else []
        upsert_messages_func(messages, workspace_file_func(workspace, "messages.json"))
        set_mail_fetch_job(
            job_id,
            status="success",
            processed=int(result.get("summary", {}).get("total") or 0),
            current_email="",
            result=lightweight_fetch_result_func(result, cached_count=len(messages)),
        )
    except Exception as exc:
        set_mail_fetch_job(job_id, status="failed", error=str(exc)[:500])


def start_client_mail_fetch_job(
    payload: dict[str, Any],
    workspace_id: str = "public",
    *,
    normalize_workspace_id_func: Callable[[Any], str],
    hydrate_login_mail_credentials_func: Callable[[dict[str, Any], str], dict[str, int]],
    transient_mail_accounts_func: Callable[[dict[str, Any]], tuple[list[Any], list[str]]],
    transient_temp_addresses_func: Callable[[dict[str, Any]], tuple[list[Any], list[str]]],
    transient_generic_accounts_func: Callable[[dict[str, Any]], tuple[list[Any], list[str]]],
    run_client_mail_fetch_job_func: Callable[..., None] | None = None,
    thread_factory: Callable[..., threading.Thread] = threading.Thread,
    now_func: Callable[[], str] = _iso_now,
    token_urlsafe_func: Callable[[int], str] = secrets.token_urlsafe,
    **run_kwargs: Any,
) -> dict[str, Any]:
    """创建并启动客户端异步收信任务。"""
    workspace = normalize_workspace_id_func(workspace_id)
    hydrate_login_mail_credentials_func(payload, workspace)
    accounts, account_errors = transient_mail_accounts_func(payload)
    temp_addresses, temp_errors = transient_temp_addresses_func(payload)
    generic_accounts, generic_errors = transient_generic_accounts_func(payload)
    total = len(accounts) + len(temp_addresses) + len(generic_accounts)
    if total <= 0:
        raise RuntimeError("当前筛选下没有可刷新邮箱")
    job_id = token_urlsafe_func(12)
    now = now_func()
    job = {
        "job_id": job_id,
        "status": "running",
        "workspace_id": workspace,
        "created_at": now,
        "updated_at": now,
        "total": total,
        "processed": 0,
        "current_email": "",
        "result": None,
        "error": "",
        "warnings": account_errors + temp_errors + generic_errors,
    }
    with MAIL_FETCH_JOBS_LOCK:
        MAIL_FETCH_JOBS[job_id] = job
    trim_mail_fetch_jobs()
    runner = run_client_mail_fetch_job_func or run_client_mail_fetch_job
    thread = thread_factory(target=runner, args=(job_id, payload, workspace), kwargs=run_kwargs, daemon=True)
    thread.start()
    return {"success": True, "job": mail_fetch_job_public(job)}


def get_client_mail_fetch_job(
    job_id: str,
    workspace_id: str = "public",
    *,
    normalize_workspace_id_func: Callable[[Any], str],
) -> dict[str, Any]:
    """按工作区读取收信任务公开视图。"""
    expected_workspace = normalize_workspace_id_func(workspace_id)
    with MAIL_FETCH_JOBS_LOCK:
        job = MAIL_FETCH_JOBS.get(_coerce_text(job_id))
        if not job:
            raise RuntimeError("收信任务不存在或已过期")
        if normalize_workspace_id_func(job.get("workspace_id")) != expected_workspace:
            raise RuntimeError("收信任务不属于当前工作区")
        return {"success": True, "job": mail_fetch_job_public(job)}
