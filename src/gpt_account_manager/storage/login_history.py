"""登录历史记录的本地持久化。

这里只管 JSON 读写和数量裁剪，不掺登录流程规则，避免把存储层再写成
一团业务逻辑。登录任务结束后，只把必要摘要写到历史文件里，方便启动
恢复和人工排查。
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LOGIN_HISTORY_FILE = Path(__file__).resolve().parents[3] / "data" / "login_history.json"
LOGIN_HISTORY_LIMIT = 300


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_login_history(path: Path = LOGIN_HISTORY_FILE) -> list[dict[str, Any]]:
    """读取登录历史；格式坏了就回退为空，避免启动被历史文件卡死。"""
    # 这里允许 data 目录还没创建，先补目录再读，保证启动恢复路径稳定。
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return []
    rows = raw.get("history") if isinstance(raw, dict) else raw
    return [item for item in rows if isinstance(item, dict)] if isinstance(rows, list) else []


def save_login_history(history: list[dict[str, Any]], path: Path = LOGIN_HISTORY_FILE) -> None:
    """保存登录历史，保留临时文件替换，避免留下半截写入。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    trimmed = history[-LOGIN_HISTORY_LIMIT:]
    payload = {"updated_at": _iso_now(), "history": trimmed}
    tmp = path.with_suffix(".json.tmp")
    # 任务终态写历史时保守一点，用临时文件原子替换，失败就让上层重试。
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def append_login_history_entry(job: dict[str, Any], path: Path = LOGIN_HISTORY_FILE) -> None:
    """追加一条完成态登录摘要，不把完整 job 大对象直接落盘。"""
    entry = {
        "job_id": job.get("job_id"),
        "email": job.get("email"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "status": job.get("status"),
        "error": job.get("error"),
        "login_only": job.get("login_only"),
        "site_url": job.get("site_url"),
    }
    history = load_login_history(path)
    history = [h for h in history if h.get("job_id") != entry["job_id"]]
    history.append(entry)
    save_login_history(history, path)


__all__ = [
    "LOGIN_HISTORY_FILE",
    "LOGIN_HISTORY_LIMIT",
    "append_login_history_entry",
    "load_login_history",
    "save_login_history",
]
