"""邮件消息缓存存取。
这里专门处理本地 messages.json 的读写和稳定排序，不承担邮件抓取、
过滤或页面展示逻辑，便于把 I/O 和业务规则分开。
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from .workspace import load_json_file, write_json_file


def _coerce_text(value: Any) -> str:
    """把值统一成字符串，供消息缓存键和排序规则使用。"""
    return str(value or "").strip()


def parse_message_datetime(value: Any) -> datetime | None:
    """把常见邮件时间格式转成 UTC，失败时交给上层按原值处理。"""
    text = _coerce_text(value)
    if not text:
        return None
    try:
        parsed = parsedate_to_datetime(text)
        if parsed:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
    except Exception:
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def message_key(message: dict[str, Any]) -> str:
    """生成消息缓存键，保证同一封邮件在本地缓存里可稳定覆盖。"""
    return "|".join([
        _coerce_text(message.get("source")),
        _coerce_text(message.get("account")),
        _coerce_text(message.get("folder")),
        _coerce_text(message.get("mid")),
        _coerce_text(message.get("subject")),
        _coerce_text(message.get("received_at")),
    ])


def message_sort_value(message: dict[str, Any]) -> str:
    """给消息一个稳定排序值，优先 received_at，其次 cached_at。"""
    value = message.get("received_at") or message.get("cached_at") or ""
    parsed = parse_message_datetime(value)
    return parsed.isoformat() if parsed else _coerce_text(value)


def load_messages(path: Path) -> list[dict[str, Any]]:
    """读取 messages.json。
    storage 层只保留本地缓存的原始消息记录，不在这里做邮件类型归一化或
    展示标签回填，避免存储层直接依赖业务域规则。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = load_json_file(path, [])
    rows = raw.get("messages", []) if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return []
    return [dict(item) for item in rows if isinstance(item, dict)]


def save_messages(messages: list[dict[str, Any]], path: Path) -> None:
    """保存 messages.json，并做稳定排序和数量裁剪。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    trimmed = sorted(messages, key=message_sort_value, reverse=True)[:2000]
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "messages": trimmed,
    }
    write_json_file(path, payload)


def upsert_messages(incoming: list[dict[str, Any]], path: Path) -> None:
    """把新消息合并到本地缓存里，按缓存键去重覆盖。"""
    if not incoming:
        return
    cache = {message_key(message): message for message in load_messages(path)}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for message in incoming:
        message.setdefault("cached_at", now)
        cache[message_key(message)] = message
    save_messages(list(cache.values()), path)
