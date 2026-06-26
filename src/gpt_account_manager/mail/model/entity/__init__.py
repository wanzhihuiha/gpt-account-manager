"""邮件域内部实体。

这里放邮箱账号、临时邮箱等会随业务状态变化的实体，外部模块默认不直接依赖。
"""
from __future__ import annotations

from .account import GenericMailAccount, MailAccount, TempAddress

__all__ = [
    "GenericMailAccount",
    "MailAccount",
    "TempAddress",
]
