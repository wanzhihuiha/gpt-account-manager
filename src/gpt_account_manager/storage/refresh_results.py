"""登录刷新结果的本地持久化。

这里只管 `refresh_results.json` 的读取、写回和单条结果追加，不参与登录、CPA 或 Web 路由编排。
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REFRESH_RESULTS_LIMIT = 500


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_refresh_results(path: Path) -> list[dict[str, Any]]:
    """读取刷新结果列表，兼容旧的列表或 `{results: [...]}` 两种文件形态。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return []
    rows = raw.get("results") if isinstance(raw, dict) else raw
    return [item for item in rows if isinstance(item, dict)] if isinstance(rows, list) else []


def save_refresh_results(results: list[dict[str, Any]], path: Path, *, limit: int = REFRESH_RESULTS_LIMIT) -> None:
    """把刷新结果按旧格式裁剪后原子替换写回。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    trimmed = results[-limit:]
    payload = {"updated_at": _iso_now(), "results": trimmed}
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def append_refresh_result(
    auth_file: dict[str, Any],
    *,
    path: Path,
    email: str = "",
    job_id: str = "",
    limit: int = REFRESH_RESULTS_LIMIT,
) -> None:
    """追加一条成功刷新结果，并按邮箱去重保留最新记录。"""
    entry = {
        "email": email or auth_file.get("email", ""),
        "name": auth_file.get("name", ""),
        "job_id": job_id,
        "refreshed_at": _iso_now(),
        "plan_type": auth_file.get("plan_type", ""),
        "auth_file": auth_file,
    }
    results = load_refresh_results(path)
    email_lower = str(entry["email"] or "").lower()
    results = [row for row in results if str(row.get("email", "")).lower() != email_lower]
    results.append(entry)
    save_refresh_results(results, path, limit=limit)


__all__ = [
    "REFRESH_RESULTS_LIMIT",
    "append_refresh_result",
    "load_refresh_results",
    "save_refresh_results",
]
