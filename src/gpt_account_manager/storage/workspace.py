"""工作区路径与本地 JSON 存取。

这里专门承接工作区 ID 规整、工作区目录定位和最基础的 JSON 读写，不引入
任何业务判断，避免存储入口再次和 mail/login/cpa 的流程细节缠在一起。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


WORKSPACE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{5,63}$")


def file_item_count(path: Path, key: str) -> int:
    """统计指定 JSON 文件里某个列表字段的数量。"""
    if not path.exists():
        return 0
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return -1
    value = payload.get(key) if isinstance(payload, dict) else None
    return len(value) if isinstance(value, list) else 0


def load_json_file(path: Path, fallback: Any) -> Any:
    """读取本地 JSON；格式损坏时回退到调用方提供的默认值。"""
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return fallback


def write_json_file(path: Path, payload: Any) -> None:
    """写入本地 JSON，并在落盘前确保父目录已经存在。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_workspace_id(value: Any) -> str:
    """把工作区 ID 收敛成安全短字符串；非法值统一回退到 `public`。"""
    text = str(value or "").strip()
    if not text or not WORKSPACE_ID_PATTERN.fullmatch(text):
        return "public"
    return text


def workspace_dir(workspaces_root: Path, workspace_id: Any) -> Path:
    """根据工作区根目录和工作区 ID 计算目标目录。"""
    return workspaces_root / normalize_workspace_id(workspace_id)


def workspace_file(workspaces_root: Path, workspace_id: Any, filename: str) -> Path:
    """定位某个工作区下的具体文件路径。"""
    return workspace_dir(workspaces_root, workspace_id) / filename


def workspace_counts(workspaces_root: Path, workspace_id: Any) -> dict[str, int]:
    """汇总当前工作区几类核心数据文件的条目数。"""
    return {
        "microsoft_accounts": file_item_count(workspace_file(workspaces_root, workspace_id, "accounts.json"), "accounts"),
        "temp_addresses": file_item_count(workspace_file(workspaces_root, workspace_id, "temp_addresses.json"), "addresses"),
        "generic_accounts": file_item_count(workspace_file(workspaces_root, workspace_id, "generic_accounts.json"), "accounts"),
        "messages": file_item_count(workspace_file(workspaces_root, workspace_id, "messages.json"), "messages"),
    }
