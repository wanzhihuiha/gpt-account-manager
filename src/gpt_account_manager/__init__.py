"""正式代码区的包入口。

后续业务模块会继续挂在这个命名空间下，当前只保留统一启动入口。
"""
from __future__ import annotations

from .app.main import main

__all__ = ["main"]
