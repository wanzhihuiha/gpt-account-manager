"""邮件 provider 规则入口。"""
from __future__ import annotations

from .rules import (
    GENERIC_MAIL_HOSTS,
    GENERIC_MAIL_MODES,
    MAIL_FETCH_ERROR_LABELS,
    classify_mail_fetch_error,
    infer_generic_mail_config,
    microsoft_provider_sequence,
    normalize_generic_mail_mode,
    run_mail_fetch_jobs,
)

__all__ = [
    "GENERIC_MAIL_HOSTS",
    "GENERIC_MAIL_MODES",
    "MAIL_FETCH_ERROR_LABELS",
    "classify_mail_fetch_error",
    "infer_generic_mail_config",
    "microsoft_provider_sequence",
    "normalize_generic_mail_mode",
    "run_mail_fetch_jobs",
]
