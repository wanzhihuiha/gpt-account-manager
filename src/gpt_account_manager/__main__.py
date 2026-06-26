"""统一模块入口，只负责调用 app.main。"""
from __future__ import annotations

from .app.main import main

if __name__ == "__main__":
    # 这里只做入口转发，避免把启动装配继续散落到脚本层。
    main()
