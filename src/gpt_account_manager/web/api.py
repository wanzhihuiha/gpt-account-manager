"""Web 层阶段性公开入口。

这一层把纯响应装配和查询参数规整能力收敛到稳定模块，给 `server.py`
这类兼容入口和后续路由层使用，避免继续把 `web` 包根当成唯一公开面。
"""
from __future__ import annotations

from .handler import (
    Handler,
    HandlerRuntime,
    build_handler_class,
)
from .payloads import (
    account_list_payload,
    build_health_payload,
    build_public_config_payload,
    build_public_top_links,
    build_upgrade_request_record,
    build_upgrade_request_response,
    build_upgrade_status_payload,
    coded_error_payload,
    deleted_account_list_payload,
    deleted_temp_address_list_payload,
    delete_transient_client_mail_message_payload,
    disabled_cpa_refresh_path_payload,
    error_payload,
    imported_account_list_payload,
    imported_temp_address_list_payload,
    lightweight_fetch_result,
    lightweight_mail_fetch_result,
    login_history_payload,
    message_search_payload,
    plain_error_payload,
    refresh_results_payload,
    success_payload,
    temp_address_list_payload,
)
from .queries import (
    build_dashboard_stats_query,
    build_message_query_payload,
    first_query_value,
)
from .routes import (
    handle_api_post_route,
    handle_admin_get_route,
    handle_admin_post_route,
    handle_auth_post_route,
    handle_client_get_route,
    handle_client_post_route,
    handle_public_get_route,
)
from .stats import dashboard_stats_response
from .status import (
    create_upgrade_request,
    health_payload,
    public_config_payload,
    public_top_links,
    upgrade_status_payload,
)

__all__ = [
    "build_handler_class",
    "HandlerRuntime",
    "Handler",
    "account_list_payload",
    "build_dashboard_stats_query",
    "build_health_payload",
    "build_message_query_payload",
    "build_public_config_payload",
    "build_public_top_links",
    "build_upgrade_request_record",
    "build_upgrade_request_response",
    "build_upgrade_status_payload",
    "coded_error_payload",
    "dashboard_stats_response",
    "upgrade_status_payload",
    "public_top_links",
    "public_config_payload",
    "health_payload",
    "create_upgrade_request",
    "deleted_account_list_payload",
    "deleted_temp_address_list_payload",
    "delete_transient_client_mail_message_payload",
    "disabled_cpa_refresh_path_payload",
    "error_payload",
    "first_query_value",
    "handle_api_post_route",
    "handle_admin_get_route",
    "handle_admin_post_route",
    "handle_auth_post_route",
    "handle_client_get_route",
    "handle_client_post_route",
    "handle_public_get_route",
    "imported_account_list_payload",
    "imported_temp_address_list_payload",
    "lightweight_fetch_result",
    "lightweight_mail_fetch_result",
    "login_history_payload",
    "message_search_payload",
    "plain_error_payload",
    "refresh_results_payload",
    "success_payload",
    "temp_address_list_payload",
]
