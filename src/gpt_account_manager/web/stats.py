"""Dashboard 统计响应装配。

这里把 dashboard 的集合统计从旧的 server 入口里拆出，保持现有响应形状不变，数据读取则由调用方注入。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


def coerce_text(value: Any) -> str:
    return str(value or "").strip()


def first_text(*values: Any) -> str:
    for value in values:
        text = coerce_text(value)
        if text:
            return text
    return ""


def is_banned_mail_message(
    message: dict[str, Any],
    normalize_mail_type_func: Callable[[Any, str], str],
) -> bool:
    if coerce_text(message.get("mail_type")).lower() == "banned":
        return True
    haystack = " ".join(coerce_text(message.get(key)) for key in [
        "sender", "subject", "preview", "body", "html_body", "mail_type_label",
    ])
    return normalize_mail_type_func("", haystack) == "banned"


def count_by_value(rows: list[Any], getter: Callable[[Any], str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = coerce_text(getter(row)).lower() or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return counts


def sorted_count_rows(counts: dict[str, int], key_name: str, *, limit: int = 20) -> list[dict[str, Any]]:
    return [
        {key_name: key, "count": count}
        for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def dashboard_message_recipient(message: dict[str, Any]) -> str:
    return first_text(message.get("account"), message.get("recipient"), message.get("to"), message.get("email")).lower()


def dashboard_stats_response(
    workspace_id: str,
    *,
    days: int | str = 30,
    limit: int | str = 300,
    tz_offset_minutes: int | str = 480,
    app_version: str,
    iso_now_func: Callable[[], str],
    workspace_file_func: Callable[[str, str], Path],
    load_accounts_func: Callable[[Path], dict[str, Any]],
    load_temp_addresses_func: Callable[[Path], dict[str, Any]],
    load_generic_accounts_func: Callable[[Path], dict[str, Any]],
    load_refresh_results_func: Callable[[Path], list[dict[str, Any]]],
    load_messages_func: Callable[[Path], list[dict[str, Any]]],
    parse_message_datetime_func: Callable[[Any], datetime | None],
    normalize_mail_type_func: Callable[[Any, str], str],
) -> dict[str, Any]:
    try:
        days = max(1, min(int(days or 30), 365))
    except (TypeError, ValueError):
        days = 30
    try:
        limit = max(1, min(int(limit or 300), 1000))
    except (TypeError, ValueError):
        limit = 300
    try:
        tz_offset_minutes = max(-720, min(int(tz_offset_minutes), 840))
    except (TypeError, ValueError):
        tz_offset_minutes = 480

    tz = timezone(timedelta(minutes=tz_offset_minutes))
    now_local = datetime.now(timezone.utc).astimezone(tz)
    start_date = now_local.date() - timedelta(days=days - 1)
    today_key = now_local.date().isoformat()
    seven_start = now_local.date() - timedelta(days=6)

    accounts = list(load_accounts_func(workspace_file_func(workspace_id, "accounts.json")).values())
    temp_addresses = list(load_temp_addresses_func(workspace_file_func(workspace_id, "temp_addresses.json")).values())
    generic_accounts = list(load_generic_accounts_func(workspace_file_func(workspace_id, "generic_accounts.json")).values())
    refresh_results = load_refresh_results_func(workspace_file_func(workspace_id, "refresh_results.json"))
    messages = load_messages_func(workspace_file_func(workspace_id, "messages.json"))

    all_mailboxes = [
        {"source": "microsoft", "email": item.email, "status": item.last_status, "error_code": item.last_error_code}
        for item in accounts
    ] + [
        {"source": "temp", "email": item.email, "status": item.last_status, "error_code": item.last_error_code}
        for item in temp_addresses
    ] + [
        {"source": "generic", "email": item.email, "status": item.last_status, "error_code": item.last_error_code}
        for item in generic_accounts
    ]
    mailbox_status_counts = count_by_value(all_mailboxes, lambda row: row.get("status") or "idle")
    mailbox_source_counts = count_by_value(all_mailboxes, lambda row: row.get("source") or "unknown")
    mailbox_error_counts = count_by_value(
        [row for row in all_mailboxes if coerce_text(row.get("error_code"))],
        lambda row: row.get("error_code") or "unknown",
    )
    mailbox_error_count = sum(1 for row in all_mailboxes if coerce_text(row.get("status")).lower() in {"error", "failed"} or coerce_text(row.get("error_code")))

    def refresh_plan_type(row: dict[str, Any]) -> str:
        auth_file = row.get("auth_file") if isinstance(row.get("auth_file"), dict) else {}
        return row.get("plan_type") or auth_file.get("plan_type") or auth_file.get("chatgpt_plan_type") or "unknown"

    refresh_plan_counts = count_by_value(refresh_results, refresh_plan_type)
    refreshed_today = 0
    refreshed_week = 0
    for row in refresh_results:
        parsed = parse_message_datetime_func(row.get("refreshed_at"))
        if not parsed:
            continue
        day = parsed.astimezone(tz).date()
        if day.isoformat() == today_key:
            refreshed_today += 1
        if day >= seven_start:
            refreshed_week += 1

    message_type_counts = count_by_value(
        messages,
        lambda row: normalize_mail_type_func(
            row.get("mail_type"),
            " ".join(coerce_text(row.get(key)) for key in ["sender", "subject", "preview", "body", "html_body", "mail_type_label"]),
        ),
    )
    source_counts = count_by_value(messages, lambda row: row.get("source") or row.get("provider") or "unknown")
    message_daily: dict[str, int] = {}
    message_today = 0
    message_week = 0
    latest_message_at = ""
    latest_message_sort = ""
    for message in messages:
        parsed = parse_message_datetime_func(message.get("received_at") or message.get("cached_at"))
        if parsed:
            local_day = parsed.astimezone(tz).date()
            if local_day >= start_date:
                day_key = local_day.isoformat()
                message_daily[day_key] = message_daily.get(day_key, 0) + 1
            if local_day.isoformat() == today_key:
                message_today += 1
            if local_day >= seven_start:
                message_week += 1
            sort_value = parsed.isoformat()
            if sort_value > latest_message_sort:
                latest_message_sort = sort_value
                latest_message_at = parsed.isoformat()

    banned_daily: dict[str, int] = {}
    banned_domains: dict[str, int] = {}
    banned_recipients: dict[str, int] = {}
    banned_messages: list[dict[str, Any]] = []
    unknown_day_count = 0

    for message in messages:
        if not is_banned_mail_message(message, normalize_mail_type_func):
            continue
        parsed = parse_message_datetime_func(message.get("received_at") or message.get("cached_at"))
        local_dt = parsed.astimezone(tz) if parsed else None
        day_key = local_dt.date().isoformat() if local_dt else "unknown"
        if day_key == "unknown":
            unknown_day_count += 1
        elif local_dt and local_dt.date() < start_date:
            continue

        recipient = dashboard_message_recipient(message)
        domain = recipient.split("@", 1)[1].lower() if "@" in recipient else ""
        banned_daily[day_key] = banned_daily.get(day_key, 0) + 1
        if recipient:
            banned_recipients[recipient.lower()] = banned_recipients.get(recipient.lower(), 0) + 1
        if domain:
            banned_domains[domain] = banned_domains.get(domain, 0) + 1
        banned_messages.append({
            "recipient": recipient,
            "subject": coerce_text(message.get("subject")),
            "sender": coerce_text(message.get("sender")),
            "received_at": coerce_text(message.get("received_at") or message.get("cached_at")),
            "local_day": day_key,
            "source": coerce_text(message.get("source") or message.get("provider")),
            "preview": coerce_text(message.get("preview"))[:180],
        })

    banned_messages.sort(key=lambda item: item.get("received_at") or "", reverse=True)
    daily_rows = []
    message_daily_rows = []
    for index in range(days):
        day = start_date + timedelta(days=index)
        day_key = day.isoformat()
        daily_rows.append({"date": day_key, "count": banned_daily.get(day_key, 0)})
        message_daily_rows.append({"date": day_key, "count": message_daily.get(day_key, 0)})

    banned_total = sum(item["count"] for item in daily_rows) + unknown_day_count
    if banned_daily.get(today_key, 0) > 0:
        risk_level = "high"
        risk_reason = "today_banned_mail"
    elif sum(row["count"] for row in daily_rows if datetime.fromisoformat(row["date"]).date() >= seven_start) > 0:
        risk_level = "warning"
        risk_reason = "recent_banned_mail"
    elif mailbox_error_count > 0:
        risk_level = "attention"
        risk_reason = "mailbox_errors"
    elif len(messages) == 0:
        risk_level = "unknown"
        risk_reason = "no_cached_mail"
    else:
        risk_level = "normal"
        risk_reason = "no_recent_risk"
    return {
        "success": True,
        "version": app_version,
        "generated_at": iso_now_func(),
        "workspace_id": workspace_id,
        "timezone_offset_minutes": tz_offset_minutes,
        "days": days,
        "mailboxes": {
            "total": len(all_mailboxes),
            "microsoft": len(accounts),
            "temp": len(temp_addresses),
            "generic": len(generic_accounts),
            "error": mailbox_error_count,
            "status": sorted_count_rows(mailbox_status_counts, "status", limit=12),
            "sources": sorted_count_rows(mailbox_source_counts, "source", limit=12),
            "errors": sorted_count_rows(mailbox_error_counts, "error_code", limit=12),
        },
        "refresh": {
            "saved_total": len(refresh_results),
            "today": refreshed_today,
            "last_7_days": refreshed_week,
            "plans": sorted_count_rows(refresh_plan_counts, "plan_type", limit=12),
        },
        "messages": {
            "cached_total": len(messages),
            "today": message_today,
            "last_7_days": message_week,
            "latest_at": latest_message_at,
            "daily": message_daily_rows,
            "types": sorted_count_rows(message_type_counts, "type", limit=12),
            "sources": sorted_count_rows(source_counts, "source", limit=12),
        },
        "risk": {
            "level": risk_level,
            "reason": risk_reason,
        },
        "banned_mail": {
            "total": banned_total,
            "today": banned_daily.get(today_key, 0),
            "last_7_days": sum(row["count"] for row in daily_rows if datetime.fromisoformat(row["date"]).date() >= seven_start),
            "unique_recipients": len(banned_recipients),
            "unknown_day_count": unknown_day_count,
            "daily": daily_rows,
            "domains": sorted_count_rows(banned_domains, "domain", limit=20),
            "recipients": sorted_count_rows(banned_recipients, "recipient", limit=50),
            "messages": banned_messages[:limit],
        },
    }


__all__ = [
    "dashboard_stats_response",
]
