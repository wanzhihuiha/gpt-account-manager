"""兼容 Web 运行时装配。

这里承接旧脚本 Web Handler 依赖的跨域拼装，并把工作区/邮件相关的路径绑定
wrapper 收口到一个对象里，避免 `server.py` 继续堆放大段装配代码。
"""
from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from gpt_account_manager.cpa.api import (
    delete_cpa_items as cpa_delete_cpa_items_impl,
    repair_cpa_401 as cpa_repair_cpa_401_impl,
    replace_cpa_auth_file as cpa_replace_cpa_auth_file_impl,
    scan_cpa_401 as cpa_scan_cpa_401_impl,
)
from gpt_account_manager.infra import (
    check_proxy_egress as infra_check_proxy_egress_impl,
    network_health_payload as infra_network_health_payload_impl,
)
from gpt_account_manager.login.api import (
    cancel_login_job as login_cancel_login_job_impl,
    classify_login_exception as login_classify_login_exception_impl,
    get_local_oauth_flow as login_get_local_oauth_flow_impl,
    get_login_job as login_get_login_job_impl,
    poll_phone_code as login_poll_phone_code_impl,
    set_login_manual_email_code as login_set_login_manual_email_code_impl,
    set_login_manual_phone_code as login_set_login_manual_phone_code_impl,
)
from gpt_account_manager.mail.api import (
    MAIL_TYPE_LABELS as mail_MAIL_TYPE_LABELS,
    cached_messages_response as mail_cached_messages_response_impl,
    delete_stored_mail_message as mail_delete_stored_mail_message_impl,
    delete_workspace_mail_credentials as mail_delete_workspace_mail_credentials_impl,
    extract_admin_jwts as mail_extract_admin_jwts_impl,
    fetch_saved_mail as mail_fetch_saved_mail_impl,
    fetch_transient_client_mail as mail_fetch_transient_client_mail_impl,
    filter_messages as mail_filter_messages_impl,
    get_client_mail_fetch_job as mail_get_client_mail_fetch_job_impl,
    import_generic_accounts as mail_import_generic_accounts_impl,
    import_pickup_accounts as mail_import_pickup_accounts_impl,
    import_temp_addresses as mail_import_temp_addresses_impl,
    load_accounts as mail_load_accounts_impl,
    load_generic_accounts as mail_load_generic_accounts_impl,
    load_temp_addresses as mail_load_temp_addresses_impl,
    normalize_generic_account as mail_normalize_generic_account_impl,
    normalize_mail_type as mail_normalize_mail_type_impl,
    parse_account_lines as mail_parse_account_lines_impl,
    parse_generic_account_lines as mail_parse_generic_account_lines_impl,
    parse_temp_address_lines as mail_parse_temp_address_lines_impl,
    run_client_mail_fetch_job as mail_run_client_mail_fetch_job_impl,
    save_accounts as mail_save_accounts_impl,
    save_generic_accounts as mail_save_generic_accounts_impl,
    save_temp_addresses as mail_save_temp_addresses_impl,
    start_client_mail_fetch_job as mail_start_client_mail_fetch_job_impl,
    sync_temp_jwts_from_worker as mail_sync_temp_jwts_from_worker_impl,
    transient_generic_accounts as mail_transient_generic_accounts_impl,
    transient_mail_accounts as mail_transient_mail_accounts_impl,
    transient_temp_addresses as mail_transient_temp_addresses_impl,
)
from gpt_account_manager.storage.api import (
    load_login_history as storage_load_login_history_impl,
    load_messages as storage_load_messages_impl,
    load_refresh_results as storage_load_refresh_results_impl,
    upsert_messages as storage_upsert_messages_impl,
)
from gpt_account_manager.web.api import (
    HandlerRuntime as web_HandlerRuntime_impl,
    build_handler_class as web_build_handler_class_impl,
    create_upgrade_request as web_create_upgrade_request_impl,
    health_payload as web_health_payload_impl,
    lightweight_fetch_result as web_lightweight_fetch_result_impl,
    public_config_payload as web_public_config_payload_impl,
    upgrade_status_payload as web_upgrade_status_payload_impl,
)
from gpt_account_manager.workspace.api import (
    push_public_pool as workspace_push_public_pool_impl,
)

from .version import load_asset_version as app_load_asset_version_impl


@dataclass(frozen=True)
class CompatWebRuntimeConfig:
    """兼容 Web 运行时装配需要的旧脚本配置和剩余 wrapper。"""

    admin_cookie_name: str
    admin_token: str
    app_version: str
    login_debug_dir: Path
    messages_file: Path
    refresh_results_file: Path
    login_history_file: Path
    public_pool_url: str
    public_relay_url: str
    static_dir: Path
    accounts_file: Path
    temp_addresses_file: Path
    generic_accounts_file: Path
    temp_worker_url: str
    temp_site_password: str
    workspace_file_func: Callable[[str, str], Path]
    normalize_workspace_id_func: Callable[[Any], str]
    normalize_temp_worker_url_func: Callable[[str], str]
    hydrate_login_mail_credentials_func: Callable[[dict[str, Any], str], dict[str, int]]
    cpa_direct_oauth_start_func: Callable[[dict[str, Any]], dict[str, Any]]
    cpa_direct_oauth_callback_func: Callable[[dict[str, Any]], dict[str, Any]]
    delete_cpa_items_func: Callable[[dict[str, Any]], dict[str, Any]]
    replace_cpa_auth_file_func: Callable[[dict[str, Any]], dict[str, Any]]
    scan_cpa_401_func: Callable[[dict[str, Any]], dict[str, Any]]
    repair_cpa_401_func: Callable[[dict[str, Any]], dict[str, Any]]
    refresh_lifecycle_func: Callable[[dict[str, Any]], dict[str, Any]]
    refresh_cpa_lifecycle_func: Callable[[dict[str, Any]], dict[str, Any]]
    start_cpa_login_job_func: Callable[[dict[str, Any], str], dict[str, Any]]
    health_payload_func: Callable[[], dict[str, Any]]
    public_config_payload_func: Callable[[], dict[str, Any]]
    network_health_payload_func: Callable[[], dict[str, Any]]
    upgrade_status_payload_func: Callable[[], dict[str, Any]]
    create_upgrade_request_func: Callable[[dict[str, Any] | None], dict[str, Any]]
    push_public_pool_func: Callable[[dict[str, Any]], dict[str, Any]]
    dashboard_stats_response_func: Callable[..., dict[str, Any]]


class CompatWebSupport:
    """封装旧脚本 Web Handler 需要的运行时依赖和路径绑定 helper。"""

    def __init__(self, config: CompatWebRuntimeConfig) -> None:
        self.config = config

    @staticmethod
    def _coerce_text(value: Any) -> str:
        return str(value or "").strip()

    def load_accounts(self, path: Path | None = None) -> dict[str, Any]:
        return mail_load_accounts_impl(path or self.config.accounts_file)

    def save_accounts(self, accounts: dict[str, Any], path: Path | None = None) -> None:
        mail_save_accounts_impl(accounts, path or self.config.accounts_file)

    def load_temp_addresses(self, path: Path | None = None) -> dict[str, Any]:
        return mail_load_temp_addresses_impl(
            path or self.config.temp_addresses_file,
            default_base_url=self.config.temp_worker_url,
            normalize_temp_worker_url_func=self.config.normalize_temp_worker_url_func,
        )

    def save_temp_addresses(self, addresses: dict[str, Any], path: Path | None = None) -> None:
        mail_save_temp_addresses_impl(addresses, path or self.config.temp_addresses_file)

    def load_generic_accounts(self, path: Path | None = None) -> dict[str, Any]:
        return mail_load_generic_accounts_impl(path or self.config.generic_accounts_file)

    def save_generic_accounts(self, accounts: dict[str, Any], path: Path | None = None) -> None:
        mail_save_generic_accounts_impl(accounts, path or self.config.generic_accounts_file)

    def load_messages(self, path: Path | None = None) -> list[dict[str, Any]]:
        return storage_load_messages_impl(path or self.config.messages_file)

    def load_refresh_results(self, path: Path | None = None) -> list[dict[str, Any]]:
        return storage_load_refresh_results_impl(path or self.config.refresh_results_file)

    def load_login_history(self, path: Path | None = None) -> list[dict[str, Any]]:
        return storage_load_login_history_impl(path or self.config.login_history_file)

    def delete_stored_mail_message(
        self,
        payload: dict[str, Any],
        path: Path | None = None,
    ) -> dict[str, Any]:
        return mail_delete_stored_mail_message_impl(payload, path or self.config.messages_file)

    def dashboard_stats_response(
        self,
        workspace_id: str,
        *,
        days: int | str = 30,
        limit: int | str = 300,
        tz_offset_minutes: int | str = 480,
    ) -> dict[str, Any]:
        return self.config.dashboard_stats_response_func(
            workspace_id,
            days=days,
            limit=limit,
            tz_offset_minutes=tz_offset_minutes,
        )

    def fetch_transient_client_mail(
        self,
        payload: dict[str, Any],
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        return mail_fetch_transient_client_mail_impl(
            payload,
            progress_callback=progress_callback,
            default_temp_worker_url=self.config.temp_worker_url,
            default_temp_site_password=self.config.temp_site_password,
            normalize_temp_worker_url_func=self.config.normalize_temp_worker_url_func,
        )

    def fetch_saved_mail(self, payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
        return mail_fetch_saved_mail_impl(
            payload,
            accounts_path=self.config.accounts_file,
            temp_addresses_path=self.config.temp_addresses_file,
            generic_accounts_path=self.config.generic_accounts_file,
            messages_path=self.config.messages_file,
            workspace_messages_path=self.config.workspace_file_func(workspace_id, "messages.json"),
            default_temp_worker_url=self.config.temp_worker_url,
            normalize_temp_worker_url_func=self.config.normalize_temp_worker_url_func,
        )

    def run_client_mail_fetch_job(self, job_id: str, payload: dict[str, Any], workspace_id: str) -> None:
        mail_run_client_mail_fetch_job_impl(
            job_id,
            payload,
            workspace_id,
            normalize_workspace_id_func=self.config.normalize_workspace_id_func,
            fetch_transient_client_mail_func=self.fetch_transient_client_mail,
            upsert_messages_func=storage_upsert_messages_impl,
            workspace_file_func=self.config.workspace_file_func,
            lightweight_fetch_result_func=self.lightweight_fetch_result,
        )

    def lightweight_fetch_result(
        self,
        result: dict[str, Any],
        *,
        cached_count: int = 0,
    ) -> dict[str, Any]:
        return web_lightweight_fetch_result_impl(
            result,
            cached_count=cached_count,
            normalize_mail_type_func=mail_normalize_mail_type_impl,
        )

    def start_client_mail_fetch_job(
        self,
        payload: dict[str, Any],
        workspace_id: str = "public",
    ) -> dict[str, Any]:
        return mail_start_client_mail_fetch_job_impl(
            payload,
            workspace_id,
            normalize_workspace_id_func=self.config.normalize_workspace_id_func,
            hydrate_login_mail_credentials_func=self.config.hydrate_login_mail_credentials_func,
            transient_mail_accounts_func=mail_transient_mail_accounts_impl,
            transient_temp_addresses_func=lambda request_payload: mail_transient_temp_addresses_impl(
                request_payload,
                default_base_url=self.config.temp_worker_url,
                default_site_password=self.config.temp_site_password,
                normalize_temp_worker_url_func=self.config.normalize_temp_worker_url_func,
            ),
            transient_generic_accounts_func=mail_transient_generic_accounts_impl,
            run_client_mail_fetch_job_func=self.run_client_mail_fetch_job,
            thread_factory=threading.Thread,
            token_urlsafe_func=secrets.token_urlsafe,
        )

    def get_client_mail_fetch_job(self, job_id: str, workspace_id: str = "public") -> dict[str, Any]:
        return mail_get_client_mail_fetch_job_impl(
            job_id,
            workspace_id,
            normalize_workspace_id_func=self.config.normalize_workspace_id_func,
        )

    def sync_temp_jwts_from_worker(
        self,
        payload: dict[str, Any],
        workspace_id: str = "public",
    ) -> dict[str, Any]:
        return mail_sync_temp_jwts_from_worker_impl(
            payload,
            self.config.workspace_file_func(workspace_id, "temp_addresses.json"),
            default_base_url=self.config.normalize_temp_worker_url_func(
                self._coerce_text(payload.get("base_url")).rstrip("/")
            ),
            default_site_password=self._coerce_text(payload.get("site_password")),
            normalize_temp_worker_url_func=self.config.normalize_temp_worker_url_func,
        )

    def import_pickup_accounts(self, payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
        return mail_import_pickup_accounts_impl(
            payload,
            self.config.workspace_file_func(workspace_id, "accounts.json"),
        )

    def import_temp_addresses(self, payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
        return mail_import_temp_addresses_impl(
            payload,
            self.config.workspace_file_func(workspace_id, "temp_addresses.json"),
            default_base_url=self.config.temp_worker_url,
            default_site_password=self.config.temp_site_password,
            normalize_temp_worker_url_func=self.config.normalize_temp_worker_url_func,
        )

    def import_generic_accounts(self, payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
        return mail_import_generic_accounts_impl(
            payload,
            self.config.workspace_file_func(workspace_id, "generic_accounts.json"),
        )

    def delete_workspace_mail_credentials(
        self,
        payload: dict[str, Any],
        workspace_id: str = "public",
    ) -> dict[str, Any]:
        return mail_delete_workspace_mail_credentials_impl(
            payload,
            self.config.workspace_file_func(workspace_id, "accounts.json"),
            self.config.workspace_file_func(workspace_id, "temp_addresses.json"),
            self.config.workspace_file_func(workspace_id, "generic_accounts.json"),
        )

    def load_asset_version(self) -> str:
        """适配 Handler 的零参回调口径。"""
        return app_load_asset_version_impl(
            self.config.static_dir,
            self.config.app_version,
        )

    def build_handler_runtime(self) -> web_HandlerRuntime_impl:
        """装配 Web Handler 运行时依赖，保持旧路由行为不变。"""
        return web_HandlerRuntime_impl(
            ADMIN_COOKIE_NAME=self.config.admin_cookie_name,
            ADMIN_TOKEN=self.config.admin_token,
            APP_VERSION=self.config.app_version,
            LOGIN_DEBUG_DIR=self.config.login_debug_dir,
            MAIL_TYPE_LABELS=mail_MAIL_TYPE_LABELS,
            MESSAGES_FILE=self.config.messages_file,
            PUBLIC_POOL_URL=self.config.public_pool_url,
            PUBLIC_RELAY_URL=self.config.public_relay_url,
            STATIC_DIR=self.config.static_dir,
            cached_messages_response=mail_cached_messages_response_impl,
            cancel_login_job=login_cancel_login_job_impl,
            check_proxy_egress=infra_check_proxy_egress_impl,
            classify_login_exception=login_classify_login_exception_impl,
            cpa_direct_oauth_callback=self.config.cpa_direct_oauth_callback_func,
            cpa_direct_oauth_start=self.config.cpa_direct_oauth_start_func,
            create_upgrade_request=self.config.create_upgrade_request_func,
            delete_cpa_items=self.config.delete_cpa_items_func,
            dashboard_stats_response=self.dashboard_stats_response,
            delete_stored_mail_message=self.delete_stored_mail_message,
            fetch_transient_client_mail=self.fetch_transient_client_mail,
            delete_workspace_mail_credentials=self.delete_workspace_mail_credentials,
            extract_admin_jwts=mail_extract_admin_jwts_impl,
            fetch_saved_mail=self.fetch_saved_mail,
            filter_messages=mail_filter_messages_impl,
            get_client_mail_fetch_job=self.get_client_mail_fetch_job,
            get_cpa_login_job=login_get_login_job_impl,
            get_local_oauth_flow=login_get_local_oauth_flow_impl,
            health_payload=self.config.health_payload_func,
            hydrate_login_mail_credentials=self.config.hydrate_login_mail_credentials_func,
            import_generic_accounts=self.import_generic_accounts,
            import_pickup_accounts=self.import_pickup_accounts,
            import_temp_addresses=self.import_temp_addresses,
            lightweight_fetch_result=self.lightweight_fetch_result,
            load_accounts=self.load_accounts,
            load_asset_version=self.load_asset_version,
            load_generic_accounts=self.load_generic_accounts,
            load_login_history=self.load_login_history,
            load_messages=self.load_messages,
            load_refresh_results=self.load_refresh_results,
            load_temp_addresses=self.load_temp_addresses,
            network_health_payload=self.config.network_health_payload_func,
            normalize_generic_account=mail_normalize_generic_account_impl,
            normalize_workspace_id=self.config.normalize_workspace_id_func,
            parse_account_lines=mail_parse_account_lines_impl,
            parse_generic_account_lines=mail_parse_generic_account_lines_impl,
            parse_temp_address_lines=mail_parse_temp_address_lines_impl,
            poll_phone_code=login_poll_phone_code_impl,
            public_config_payload=self.config.public_config_payload_func,
            push_public_pool=self.config.push_public_pool_func,
            refresh_cpa_lifecycle=self.config.refresh_cpa_lifecycle_func,
            refresh_lifecycle=self.config.refresh_lifecycle_func,
            repair_cpa_401=self.config.repair_cpa_401_func,
            replace_cpa_auth_file=self.config.replace_cpa_auth_file_func,
            save_accounts=self.save_accounts,
            save_generic_accounts=self.save_generic_accounts,
            save_temp_addresses=self.save_temp_addresses,
            scan_cpa_401=self.config.scan_cpa_401_func,
            set_login_manual_email_code=login_set_login_manual_email_code_impl,
            set_login_manual_phone_code=login_set_login_manual_phone_code_impl,
            start_client_mail_fetch_job=self.start_client_mail_fetch_job,
            start_cpa_login_job=self.config.start_cpa_login_job_func,
            sync_temp_jwts_from_worker=self.sync_temp_jwts_from_worker,
            upgrade_status_payload=self.config.upgrade_status_payload_func,
            upsert_messages=storage_upsert_messages_impl,
            workspace_file=self.config.workspace_file_func,
        )

    def build_handler_class(self) -> type[Any]:
        return web_build_handler_class_impl(self.build_handler_runtime())


__all__ = [
    "CompatWebRuntimeConfig",
    "CompatWebSupport",
]
