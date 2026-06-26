"""模块入口只负责转发到统一启动函数。"""
from __future__ import annotations

from .app.main import main

if __name__ == "__main__":
    # 这里只做入口转发，不承载业务装配。
    main()
