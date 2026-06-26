"""工作区域阶段性公开入口。

这一层把 workspace 级别的管理动作收敛到稳定模块，给 `server.py` 这类
兼容入口和后续路由层使用，避免继续直接引用 `admin_sync` 内部实现文件。
"""
from __future__ import annotations

from .admin_sync import public_pool_rows_from_payload, push_public_pool

__all__ = [
    "public_pool_rows_from_payload",
    "push_public_pool",
]
