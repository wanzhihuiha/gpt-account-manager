"""存储层阶段性公开入口。

这一层把兼容入口还在用的本地持久化 helper 收敛到稳定模块，避免
`server.py` 继续直接 import `login_history.py`、`messages.py` 这类
实现文件。工作区路径能力仍保留在 `storage.__init__` / `workspace.py`
 里独立演进。
"""
from __future__ import annotations

from .login_history import (
    LOGIN_HISTORY_FILE,
    LOGIN_HISTORY_LIMIT,
    append_login_history_entry,
    load_login_history,
    save_login_history,
)
from .refresh_results import (
    REFRESH_RESULTS_LIMIT,
    append_refresh_result,
    load_refresh_results,
    save_refresh_results,
)
from .messages import (
    load_messages,
    message_key,
    message_sort_value,
    parse_message_datetime,
    save_messages,
    upsert_messages,
)

__all__ = [
    "LOGIN_HISTORY_FILE",
    "LOGIN_HISTORY_LIMIT",
    "save_refresh_results",
    "load_refresh_results",
    "append_refresh_result",
    "REFRESH_RESULTS_LIMIT",
    "append_login_history_entry",
    "load_login_history",
    "load_messages",
    "message_key",
    "message_sort_value",
    "parse_message_datetime",
    "save_login_history",
    "save_messages",
    "upsert_messages",
]
