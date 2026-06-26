"""邮件业务域入口。

包根只保留少量稳定的邮件域能力，例如消息归一化、验证码提取和邮件类型
判断；更底层的 MIME 解码、HTML 清洗和 provider 细节继续通过子模块引用，
避免把 parser 内部实现都暴露成默认公开面。
"""
from __future__ import annotations

from .classifier import MAIL_TYPE_LABELS, normalize_mail_type
from .parser import (
    extract_codes,
    normalize_message,
    normalize_raw_email,
    parse_raw_email,
)

__all__ = [
    "MAIL_TYPE_LABELS",
    "extract_codes",
    "normalize_mail_type",
    "normalize_message",
    "normalize_raw_email",
    "parse_raw_email",
]
