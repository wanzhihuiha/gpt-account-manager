"""CPA 业务域入口。

这里先收纳 CPA 域的纯 helper 和 payload 组装，后续再继续拆 service / job。
"""
from __future__ import annotations

from .service import (
    build_cpa_repair_login_payload,
    cpa_auth_filename,
    cpa_companion_wait_code,
    cpa_is_401_item,
    cpa_probe_payload,
    cpa_status_message,
)

__all__ = [
    "build_cpa_repair_login_payload",
    "cpa_auth_filename",
    "cpa_companion_wait_code",
    "cpa_is_401_item",
    "cpa_probe_payload",
    "cpa_status_message",
]
