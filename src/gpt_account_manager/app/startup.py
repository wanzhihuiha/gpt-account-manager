"""应用启动装配。

这里专门承接兼容入口的启动期恢复和 HTTP 服务启动细节，让 `server.py`
继续往“薄兼容壳”收口；它不负责业务规则，只负责把现有依赖拼起来。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable


def restore_login_jobs_from_history(
    *,
    load_login_history_func: Callable[[], list[dict[str, Any]]],
    login_jobs: dict[str, dict[str, Any]],
    login_jobs_lock: Any,
    now_func: Callable[[], str],
    print_func: Callable[..., Any] = print,
) -> None:
    """从历史文件恢复登录任务摘要。

    这里只恢复状态页和排障仍会用到的最小字段，不重新触发任务，也不引入
    新的业务判断；这样启动恢复逻辑可以离开旧脚本，同时保持原有外部语义。
    """
    try:
        history = load_login_history_func()
    except Exception as exc:
        print_func(f"恢复历史登录任务失败：{exc}", flush=True)
        return

    with login_jobs_lock:
        for entry in history:
            job_id = entry.get("job_id")
            if not job_id:
                continue
            login_jobs[job_id] = {
                "job_id": job_id,
                "status": entry.get("status", "success"),
                "email": entry.get("email"),
                "name": entry.get("name") or "",
                "logs": [{
                    "time": entry.get("finished_at") or entry.get("started_at") or now_func(),
                    "level": "info",
                    "message": "从历史记录恢复任务",
                }],
                "result": {
                    "success": True,
                    "login_only": entry.get("login_only"),
                    "site_url": entry.get("site_url"),
                } if entry.get("status") == "success" else None,
                "error": entry.get("error") or "",
                "created_at": entry.get("started_at") or now_func(),
                "updated_at": entry.get("finished_at") or now_func(),
            }


def run_http_service(
    *,
    data_dir: Path,
    load_login_history_func: Callable[[], list[dict[str, Any]]],
    login_jobs: dict[str, dict[str, Any]],
    login_jobs_lock: Any,
    now_func: Callable[[], str],
    server_factory: Callable[[tuple[str, int], Any], Any],
    host: str,
    port: int,
    handler_class: Any,
    admin_token: str,
    print_func: Callable[..., Any] = print,
) -> None:
    """装配并启动现有单进程 HTTP 服务。"""
    data_dir.mkdir(parents=True, exist_ok=True)
    restore_login_jobs_from_history(
        load_login_history_func=load_login_history_func,
        login_jobs=login_jobs,
        login_jobs_lock=login_jobs_lock,
        now_func=now_func,
        print_func=print_func,
    )

    server = server_factory((host, port), handler_class)
    print_func(f"GPT Account Manager running at http://{host}:{port}", flush=True)
    if not admin_token:
        print_func(
            "警告：未设置 MAIL_PICKUP_ADMIN_TOKEN。请绑定到 127.0.0.1 或使用反向代理保护。",
            flush=True,
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print_func("\n服务已停止", flush=True)


__all__ = [
    "restore_login_jobs_from_history",
    "run_http_service",
]
