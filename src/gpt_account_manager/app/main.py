"""统一启动入口。

这一层只负责把现有后端主进程收拢到一个模块里，
后续继续补 `app/facade` 时，启动入口仍保持独立，不夹杂业务编排。
"""
from __future__ import annotations

import sys


def main() -> None:
    """启动现有后端主流程。

    这里不做业务判断，只负责根据当前运行方式把请求转给现有 `server.py`
    主流程，保证 `python -m gpt_account_manager` 和 `python server.py`
    都还走同一条进程入口。
    """
    current_module = sys.modules.get("__main__")
    current_file = getattr(current_module, "__file__", "") if current_module else ""
    current_main = getattr(current_module, "main", None) if current_module else None
    if current_file.endswith("server.py") and callable(current_main):
        # 直接复用当前脚本里的 main，避免把同一份服务逻辑再导入一遍。
        current_main()
        return

    # 本地模块入口走这里，统一转给旧主流程，暂时不动业务实现。
    from server import main as legacy_main

    legacy_main()
