"""工作区管理入口。

这里承载 workspace 级别的管理动作，例如公共池推送和后续的管理员同步，
默认不放业务取信主流程，避免和 mail 域混在一起。
"""
from __future__ import annotations

from .api import public_pool_rows_from_payload, push_public_pool

__all__ = [
    "public_pool_rows_from_payload",
    "push_public_pool",
]
