"""邮件类型分类规则。

这一层只根据邮件文本判断类型，不读取文件、不发网络请求，
用于把验证码、封禁、安全提醒等邮件归到统一分类。
"""
from __future__ import annotations

import re
from typing import Any


MAIL_TYPE_LABELS = {
    "verification": "verification",
    "invite": "invite",
    "security": "security",
    "promotion": "promotion",
    "banned": "banned",
    "other": "other",
}


def _coerce_text(value: Any) -> str:
    return str(value or "").strip()


def normalize_mail_type(value: Any, text: str = "") -> str:
    """根据显式类型和邮件文本归一化邮件分类。

    这里只做文本规则判断，不接触存储和业务流程；失败路径统一回落
    到 `other`，避免上层因为未知邮件类型中断取信。
    """
    raw = _coerce_text(value).strip().lower()
    haystack = f"{raw} {_coerce_text(text)}".lower()
    if any(word in haystack for word in [
        "access deactivated",
        "account deactivated",
        "deleted or deactivated",
        "deactivated",
        "disabled",
        "banned",
        "suspended",
        "封禁",
        "停用",
        "禁用",
    ]):
        return "banned"
    if (
        any(word in haystack for word in [
            "verify",
            "verification",
            "otp",
            "confirm",
            "验证码",
            "安全代码",
            "認証コード",
            "認証番号",
            "検証コード",
            "確認コード",
            "ワンタイム",
            "一時ログインコード",
        ])
        and re.search(r"\b\d{4,8}\b", haystack)
    ):
        return "verification"
    if any(word in haystack for word in ["invite", "invitation", "join", "team", "邀请"]):
        return "invite"
    if any(word in haystack for word in ["security", "alert", "sign-in", "login", "unusual", "安全", "登录", "multi-factor", "mfa"]):
        return "security"
    if any(word in haystack for word in [
        "images",
        "image",
        "reimagine",
        "plus plan",
        "start creating",
        "launch",
        "promo",
        "promotion",
        "newsletter",
        "digest",
        "update",
        "introducing",
        "通知",
        "订阅",
        "推广",
    ]):
        return "promotion"
    if raw == "reset":
        return "security"
    if raw in {"billing", "newsletter"}:
        return "promotion"
    if raw in MAIL_TYPE_LABELS:
        return raw
    return "other"
