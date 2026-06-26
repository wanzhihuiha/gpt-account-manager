"""旧邮件 provider 入口的兼容转发层。

真实 provider 规则已迁入 `gpt_account_manager.mail.providers.rules`，
这里仅保留旧 import 路径，避免一次性修改所有调用方。
"""
from __future__ import annotations

from gpt_account_manager.mail.providers.rules import *  # noqa: F401,F403
