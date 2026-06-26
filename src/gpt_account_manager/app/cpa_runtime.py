"""CPA 兼容运行时装配。

这里承接旧脚本里仍残留的 CPA 短兼容 wrapper，把 `allow_remote` 和
`user_agent` 之类的兼容语义集中起来，避免 `server.py` 继续散落同类装配。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gpt_account_manager.cpa.api import (
    cpa_candidates as cpa_candidates_impl,
    cpa_direct_oauth_callback as cpa_direct_oauth_callback_impl,
    cpa_direct_oauth_start as cpa_direct_oauth_start_impl,
    cpa_management_config as cpa_management_config_impl,
    cpa_probe_payload as cpa_probe_payload_impl,
    delete_cpa_items as cpa_delete_cpa_items_impl,
    replace_cpa_auth_file as cpa_replace_cpa_auth_file_impl,
    validate_cpa_base_url as cpa_validate_cpa_base_url_impl,
)


@dataclass(frozen=True)
class CompatCpaRuntimeConfig:
    """旧脚本 CPA 兼容壳仍需注入的环境常量。"""

    allow_remote: bool = False
    probe_user_agent: str = ""


class CompatCpaSupport:
    """统一封装 CPA 兼容链路里的短装配 helper。"""

    def __init__(self, config: CompatCpaRuntimeConfig) -> None:
        self.config = config

    def validate_cpa_base_url(self, base_url: str) -> None:
        return cpa_validate_cpa_base_url_impl(
            base_url,
            allow_remote=self.config.allow_remote,
        )

    def cpa_management_config(self, payload: dict[str, Any]) -> tuple[str, str]:
        return cpa_management_config_impl(
            payload,
            allow_remote=self.config.allow_remote,
        )

    def cpa_direct_oauth_start(self, payload: dict[str, Any]) -> dict[str, Any]:
        return cpa_direct_oauth_start_impl(
            payload,
            allow_remote=self.config.allow_remote,
        )

    def cpa_direct_oauth_callback(self, payload: dict[str, Any]) -> dict[str, Any]:
        return cpa_direct_oauth_callback_impl(
            payload,
            allow_remote=self.config.allow_remote,
        )

    def cpa_probe_payload(self, item: dict[str, Any]) -> dict[str, Any]:
        return cpa_probe_payload_impl(
            item,
            user_agent=self.config.probe_user_agent,
        )

    def cpa_candidates(
        self,
        payload: dict[str, Any],
    ) -> tuple[str, str, int, list[dict[str, Any]], int]:
        return cpa_candidates_impl(
            payload,
            allow_remote=self.config.allow_remote,
        )

    def delete_cpa_items(self, payload: dict[str, Any]) -> dict[str, Any]:
        return cpa_delete_cpa_items_impl(
            payload,
            allow_remote=self.config.allow_remote,
        )

    def replace_cpa_auth_file(self, payload: dict[str, Any]) -> dict[str, Any]:
        return cpa_replace_cpa_auth_file_impl(
            payload,
            allow_remote=self.config.allow_remote,
        )


__all__ = [
    "CompatCpaRuntimeConfig",
    "CompatCpaSupport",
]
