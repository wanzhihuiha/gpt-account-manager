"""兼容仓库根目录直接运行的包壳。

这一层只负责把 `src/gpt_account_manager` 挂进包搜索路径，
方便本地在未安装依赖时直接执行 `python -m gpt_account_manager`。
"""
from __future__ import annotations

from pathlib import Path
from pkgutil import extend_path

# 这里只做入口兼容，不放业务逻辑。
__path__ = extend_path(__path__, __name__)
_source_package = Path(__file__).resolve().parent.parent / "src" / "gpt_account_manager"
if _source_package.is_dir():
    _source_package_path = str(_source_package)
    if _source_package_path not in __path__:
        __path__.append(_source_package_path)

from .app.main import main

__all__ = ["main"]
