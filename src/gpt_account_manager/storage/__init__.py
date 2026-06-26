"""本地存储与工作区隔离入口。

这一层只放本地文件、JSON 和工作区路径的轻量封装，
不给业务域塞流程，后续会继续把更细的存储职责拆开。
"""
from __future__ import annotations

from .workspace import (
    file_item_count,
    load_json_file,
    normalize_workspace_id,
    workspace_counts,
    workspace_dir,
    workspace_file,
    write_json_file,
)

__all__ = [
    "file_item_count",
    "load_json_file",
    "normalize_workspace_id",
    "workspace_counts",
    "workspace_dir",
    "workspace_file",
    "write_json_file",
]
