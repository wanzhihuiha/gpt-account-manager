"""Web 层路由辅助。

这里先承接 `Handler.do_GET` 里低耦合的公开页和静态页路由规则，让旧脚本
保留认证、响应发送这些运行时壳，具体路径判断逐步下沉到 `web` 域。
"""
from __future__ import annotations

import hmac
from http import HTTPStatus
from pathlib import Path
from typing import Any, Callable
import urllib.parse


def _login_debug_target(request_path: str, login_debug_dir: Path) -> Path | None:
    """解析 login-debug 目标文件，并确保目标仍在调试目录内。"""
    rel = urllib.parse.unquote(request_path[len("/login-debug/"):])
    root = login_debug_dir.resolve()
    target = (login_debug_dir / rel).resolve()
    if root not in target.parents and target != root:
        return None
    return target


def handle_public_get_route(
    request_path: str,
    *,
    send_json_func: Callable[[dict[str, Any]], None],
    serve_static_file_func: Callable[[Path], None],
    require_admin_page_auth_func: Callable[[], None],
    require_auth_func: Callable[[], None],
    send_response_func: Callable[[int], None],
    send_header_func: Callable[[str, str], None],
    end_headers_func: Callable[[], None],
    send_error_func: Callable[[int], None],
    public_config_payload_func: Callable[[], dict[str, Any]],
    health_payload_func: Callable[[], dict[str, Any]],
    network_health_payload_func: Callable[[], dict[str, Any]],
    upgrade_status_payload_func: Callable[[], dict[str, Any]],
    static_dir: Path,
    login_debug_dir: Path,
    public_pool_url: str,
    public_relay_url: str,
) -> bool:
    """处理不依赖业务入参解析的公开 GET 路由。"""
    lowered = request_path.lower()
    if request_path == "/public-config":
        send_json_func(public_config_payload_func())
        return True
    if lowered in {"/login", "/login.html"}:
        serve_static_file_func(static_dir / "login.html")
        return True
    if request_path == "/health":
        try:
            require_admin_page_auth_func()
        except ConnectionAbortedError:
            return True
        send_json_func(health_payload_func())
        return True
    if request_path == "/network-health":
        try:
            require_admin_page_auth_func()
        except ConnectionAbortedError:
            return True
        send_json_func(network_health_payload_func())
        return True
    if request_path == "/admin-api/upgrade/status":
        try:
            require_auth_func()
        except ConnectionAbortedError:
            return True
        send_json_func(upgrade_status_payload_func())
        return True
    if lowered == "/health.html":
        try:
            require_admin_page_auth_func()
        except ConnectionAbortedError:
            return True
        serve_static_file_func(static_dir / "health.html")
        return True
    if lowered.startswith("/login-debug/"):
        try:
            require_admin_page_auth_func()
        except ConnectionAbortedError:
            return True
        target = _login_debug_target(request_path, login_debug_dir)
        if target is None:
            send_error_func(HTTPStatus.FORBIDDEN)
            return True
        serve_static_file_func(target)
        return True
    if lowered.startswith("/public-pool"):
        send_response_func(HTTPStatus.FOUND)
        send_header_func("Location", public_pool_url or public_relay_url or "/")
        end_headers_func()
        return True
    if lowered in {"/converter", "/converter/"}:
        serve_static_file_func(static_dir / "converter.html")
        return True
    if lowered in {"/dashboard", "/dashboard/"}:
        serve_static_file_func(static_dir / "dashboard.html")
        return True
    if lowered in {"/refresh", "/refresh/"}:
        serve_static_file_func(static_dir / "refresh.html")
        return True
    if lowered in {"/mailboxes", "/mailboxes/"}:
        serve_static_file_func(static_dir / "mailboxes.html")
        return True
    if lowered in {"/warehouse", "/warehouse/"}:
        serve_static_file_func(static_dir / "warehouse.html")
        return True
    return False


def handle_client_get_route(
    request_path: str,
    query_string: str,
    *,
    send_json_func: Callable[..., None],
    workspace_id_func: Callable[[], str],
    workspace_file_func: Callable[[str, str], Path],
    get_cpa_login_job_func: Callable[[str, str], dict[str, Any]],
    get_local_oauth_flow_func: Callable[[str], dict[str, Any]],
    get_client_mail_fetch_job_func: Callable[[str, str], dict[str, Any]],
    cached_messages_response_func: Callable[..., dict[str, Any]],
    dashboard_stats_response_func: Callable[..., dict[str, Any]],
    load_accounts_func: Callable[[Path], dict[str, Any]],
    load_temp_addresses_func: Callable[[Path], dict[str, Any]],
    load_generic_accounts_func: Callable[[Path], dict[str, Any]],
    load_refresh_results_func: Callable[[Path], list[dict[str, Any]]],
    build_message_query_payload_func: Callable[..., dict[str, str]],
    build_dashboard_stats_query_func: Callable[[dict[str, list[str]]], dict[str, str]],
    first_query_value_func: Callable[[dict[str, list[str]], str, str], str],
    account_list_payload_func: Callable[[list[Any]], dict[str, Any]],
    temp_address_list_payload_func: Callable[[list[Any]], dict[str, Any]],
    refresh_results_payload_func: Callable[[list[dict[str, Any]]], dict[str, Any]],
) -> bool:
    """处理 client 侧只读 GET 路由，并保留旧脚本的错误响应语义。"""
    if request_path not in {
        "/client-api/cpa/login-status",
        "/client-api/cpa/local-oauth-status",
        "/client-api/fetch-status",
        "/client-api/messages",
        "/client-api/dashboard-stats",
        "/client-api/accounts",
        "/client-api/temp-addresses",
        "/client-api/generic-accounts",
        "/client-api/refresh-results",
    }:
        return False
    try:
        params = urllib.parse.parse_qs(query_string)
        workspace_id = workspace_id_func()
        if request_path == "/client-api/cpa/login-status":
            send_json_func(get_cpa_login_job_func(
                first_query_value_func(params, "job_id", ""),
                workspace_id,
            ))
            return True
        if request_path == "/client-api/cpa/local-oauth-status":
            send_json_func(get_local_oauth_flow_func(
                first_query_value_func(params, "state", ""),
            ))
            return True
        if request_path == "/client-api/fetch-status":
            send_json_func(get_client_mail_fetch_job_func(
                first_query_value_func(params, "job_id", ""),
                workspace_id,
            ))
            return True
        if request_path == "/client-api/messages":
            payload = build_message_query_payload_func(params, include_accounts=True)
            send_json_func(cached_messages_response_func(
                workspace_file_func(workspace_id, "messages.json"),
                payload,
                limit=first_query_value_func(params, "limit", "80"),
                offset=first_query_value_func(params, "offset", "0"),
            ))
            return True
        if request_path == "/client-api/dashboard-stats":
            stats_query = build_dashboard_stats_query_func(params)
            send_json_func(dashboard_stats_response_func(
                workspace_id,
                days=stats_query["days"],
                limit=stats_query["limit"],
                tz_offset_minutes=stats_query["tz_offset_minutes"],
            ))
            return True
        if request_path == "/client-api/accounts":
            accounts = load_accounts_func(workspace_file_func(workspace_id, "accounts.json"))
            send_json_func(account_list_payload_func(list(accounts.values())))
            return True
        if request_path == "/client-api/temp-addresses":
            addresses = load_temp_addresses_func(workspace_file_func(workspace_id, "temp_addresses.json"))
            send_json_func(temp_address_list_payload_func(list(addresses.values())))
            return True
        if request_path == "/client-api/generic-accounts":
            accounts = load_generic_accounts_func(workspace_file_func(workspace_id, "generic_accounts.json"))
            send_json_func(account_list_payload_func(list(accounts.values())))
            return True
        results = load_refresh_results_func(workspace_file_func(workspace_id, "refresh_results.json"))
        send_json_func(refresh_results_payload_func(results))
    except Exception as exc:
        send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
    return True


def handle_admin_get_route(
    request_path: str,
    query_string: str,
    *,
    require_auth_func: Callable[[], None],
    send_json_func: Callable[..., None],
    send_error_func: Callable[[int], None],
    load_accounts_func: Callable[[], dict[str, Any]],
    load_temp_addresses_func: Callable[[], dict[str, Any]],
    load_generic_accounts_func: Callable[[], dict[str, Any]],
    load_refresh_results_func: Callable[[], list[dict[str, Any]]],
    load_login_history_func: Callable[[], list[dict[str, Any]]],
    cached_messages_response_func: Callable[..., dict[str, Any]],
    build_message_query_payload_func: Callable[..., dict[str, str]],
    first_query_value_func: Callable[[dict[str, list[str]], str, str], str],
    account_list_payload_func: Callable[[list[Any]], dict[str, Any]],
    temp_address_list_payload_func: Callable[[list[Any]], dict[str, Any]],
    refresh_results_payload_func: Callable[[list[dict[str, Any]]], dict[str, Any]],
    login_history_payload_func: Callable[[list[dict[str, Any]]], dict[str, Any]],
    messages_file: Path,
) -> bool:
    """处理后台管理只读 GET 路由，保留旧脚本的鉴权和错误返回语义。"""
    if not request_path.startswith("/api/"):
        return False
    try:
        require_auth_func()
    except ConnectionAbortedError:
        return True
    if request_path == "/api/accounts":
        accounts = load_accounts_func()
        send_json_func(account_list_payload_func(list(accounts.values())))
        return True
    if request_path == "/api/temp-addresses":
        addresses = load_temp_addresses_func()
        send_json_func(temp_address_list_payload_func(list(addresses.values())))
        return True
    if request_path == "/api/generic-accounts":
        accounts = load_generic_accounts_func()
        send_json_func(account_list_payload_func(list(accounts.values())))
        return True
    if request_path == "/api/refresh-results":
        results = load_refresh_results_func()
        send_json_func(refresh_results_payload_func(results))
        return True
    if request_path == "/api/login-history":
        history = load_login_history_func()
        send_json_func(login_history_payload_func(history))
        return True
    if request_path == "/api/messages":
        params = urllib.parse.parse_qs(query_string)
        payload = build_message_query_payload_func(params)
        send_json_func(cached_messages_response_func(
            messages_file,
            payload,
            limit=first_query_value_func(params, "limit", "80"),
            offset=first_query_value_func(params, "offset", "0"),
        ))
        return True
    send_error_func(HTTPStatus.NOT_FOUND)
    return True


def handle_auth_post_route(
    request_path: str,
    *,
    read_json_func: Callable[[], dict[str, Any]],
    send_json_func: Callable[..., None],
    send_json_with_headers_func: Callable[..., None],
    error_payload_func: Callable[[str], dict[str, Any]],
    success_payload_func: Callable[[], dict[str, Any]],
    admin_token: str,
    admin_cookie_header_func: Callable[[str], str],
    clear_admin_cookie_header_func: Callable[[], str],
) -> bool:
    """处理登录/退出这类最薄的认证 POST 路由。"""
    if request_path == "/auth/login":
        try:
            payload = read_json_func()
            token = str(payload.get("token", "")).strip()
            if not admin_token:
                send_json_func(error_payload_func("MAIL_PICKUP_ADMIN_TOKEN is not set."), status=HTTPStatus.SERVICE_UNAVAILABLE)
                return True
            if not hmac.compare_digest(token, admin_token):
                send_json_func(error_payload_func("Unauthorized"), status=HTTPStatus.UNAUTHORIZED)
                return True
            send_json_with_headers_func(
                success_payload_func(),
                {
                    "Set-Cookie": admin_cookie_header_func(token),
                },
            )
        except Exception as exc:
            send_json_func(error_payload_func(str(exc)[:500]), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/auth/logout":
        send_json_with_headers_func(
            success_payload_func(),
            {
                "Set-Cookie": clear_admin_cookie_header_func(),
            },
        )
        return True
    return False


def handle_client_post_route(
    request_path: str,
    *,
    read_json_func: Callable[[], dict[str, Any]],
    send_json_func: Callable[..., None],
    workspace_id_func: Callable[[], str],
    workspace_file_func: Callable[[str, str], Path],
    hydrate_login_mail_credentials_func: Callable[[dict[str, Any], str], None],
    fetch_transient_client_mail_func: Callable[[dict[str, Any]], dict[str, Any]],
    upsert_messages_func: Callable[..., Any],
    lightweight_fetch_result_func: Callable[[dict[str, Any]], dict[str, Any]],
    start_client_mail_fetch_job_func: Callable[[dict[str, Any], str], dict[str, Any]],
    delete_stored_mail_message_func: Callable[[dict[str, Any], Path], dict[str, Any]],
    scan_cpa_401_func: Callable[[dict[str, Any]], dict[str, Any]],
    repair_cpa_401_func: Callable[[dict[str, Any]], dict[str, Any]],
    delete_cpa_items_func: Callable[[dict[str, Any]], dict[str, Any]],
    replace_cpa_auth_file_func: Callable[[dict[str, Any]], dict[str, Any]],
    refresh_lifecycle_func: Callable[[dict[str, Any]], dict[str, Any]],
    refresh_cpa_lifecycle_func: Callable[[dict[str, Any]], dict[str, Any]],
    check_proxy_egress_func: Callable[[dict[str, Any]], dict[str, Any]],
    classify_login_exception_func: Callable[[Exception], dict[str, Any]],
    coded_error_payload_func: Callable[..., dict[str, Any]],
    plain_error_payload_func: Callable[[str], dict[str, Any]],
    sync_temp_jwts_from_worker_func: Callable[[dict[str, Any], str], dict[str, Any]],
    import_pickup_accounts_func: Callable[[dict[str, Any], str], dict[str, Any]],
    import_temp_addresses_func: Callable[[dict[str, Any], str], dict[str, Any]],
    import_generic_accounts_func: Callable[[dict[str, Any], str], dict[str, Any]],
    delete_workspace_mail_credentials_func: Callable[[dict[str, Any], str], dict[str, Any]],
    poll_phone_code_func: Callable[[dict[str, Any]], dict[str, Any]],
    set_login_manual_email_code_func: Callable[[dict[str, Any], str], dict[str, Any]],
    set_login_manual_phone_code_func: Callable[[dict[str, Any], str], dict[str, Any]],
    cancel_login_job_func: Callable[[dict[str, Any], str], dict[str, Any]],
    start_cpa_login_job_func: Callable[[dict[str, Any], str], dict[str, Any]],
    cpa_direct_oauth_start_func: Callable[[dict[str, Any]], dict[str, Any]],
    cpa_direct_oauth_callback_func: Callable[[dict[str, Any]], dict[str, Any]],
    disabled_cpa_refresh_path_payload_func: Callable[[str], dict[str, Any]],
) -> bool:
    """处理 client 侧 POST 路由，保留旧脚本的请求/错误语义。"""
    if not request_path.startswith("/client-api/"):
        return False
    workspace_id = workspace_id_func()
    if request_path == "/client-api/fetch":
        try:
            payload = read_json_func()
            hydrate_login_mail_credentials_func(payload, workspace_id)
            result = fetch_transient_client_mail_func(payload)
            messages = result.get("messages", []) if isinstance(result.get("messages"), list) else []
            upsert_messages_func(messages, workspace_file_func(workspace_id, "messages.json"))
            send_json_func(lightweight_fetch_result_func(result, cached_count=len(messages)))
        except Exception as exc:
            send_json_func(plain_error_payload_func(str(exc)[:500]), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/fetch-start":
        try:
            send_json_func(start_client_mail_fetch_job_func(read_json_func(), workspace_id))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/messages/delete":
        try:
            send_json_func(delete_stored_mail_message_func(
                read_json_func(),
                workspace_file_func(workspace_id, "messages.json"),
            ))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/scan-401":
        try:
            send_json_func(scan_cpa_401_func(read_json_func()))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/repair-401":
        try:
            send_json_func(repair_cpa_401_func(read_json_func()))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path in {"/client-api/cpa/delete", "/client-api/cpa/delete-selected"}:
        try:
            send_json_func(delete_cpa_items_func(read_json_func()))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/replace-auth":
        try:
            send_json_func(replace_cpa_auth_file_func(read_json_func()))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/accounts/lifecycle-refresh":
        try:
            send_json_func(refresh_lifecycle_func(read_json_func()))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/lifecycle-refresh":
        try:
            send_json_func(refresh_cpa_lifecycle_func(read_json_func()))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/proxy/check":
        try:
            send_json_func(check_proxy_egress_func(read_json_func()))
        except Exception as exc:
            details = classify_login_exception_func(exc)
            send_json_func(coded_error_payload_func(
                details.get("message", str(exc))[:500],
                details.get("code", "proxy_check_failed"),
                error_hint=details.get("hint", ""),
            ), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/temp-addresses/sync-jwts":
        try:
            send_json_func(sync_temp_jwts_from_worker_func(read_json_func(), workspace_id))
        except Exception as exc:
            send_json_func(coded_error_payload_func(str(exc)[:500], "temp_sync_failed"), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/accounts/import-pickup":
        try:
            send_json_func(import_pickup_accounts_func(read_json_func(), workspace_id))
        except Exception as exc:
            send_json_func(coded_error_payload_func(str(exc)[:500], "pickup_import_failed"), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/temp-addresses/import":
        try:
            send_json_func(import_temp_addresses_func(read_json_func(), workspace_id))
        except Exception as exc:
            send_json_func(coded_error_payload_func(str(exc)[:500], "temp_import_failed"), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/generic-accounts/import":
        try:
            send_json_func(import_generic_accounts_func(read_json_func(), workspace_id))
        except Exception as exc:
            send_json_func(coded_error_payload_func(str(exc)[:500], "generic_import_failed"), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/accounts/delete":
        try:
            send_json_func(delete_workspace_mail_credentials_func(read_json_func(), workspace_id))
        except Exception as exc:
            send_json_func(coded_error_payload_func(str(exc)[:500], "delete_failed"), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/phone-code/poll":
        try:
            send_json_func(poll_phone_code_func(read_json_func()))
        except Exception as exc:
            send_json_func(coded_error_payload_func(str(exc)[:500], "phone_code_fetch_failed"), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/login-manual-code":
        try:
            send_json_func(set_login_manual_email_code_func(read_json_func(), workspace_id))
        except Exception as exc:
            send_json_func(coded_error_payload_func(str(exc)[:500], "manual_email_code_failed"), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/login-manual-phone-code":
        try:
            send_json_func(set_login_manual_phone_code_func(read_json_func(), workspace_id))
        except Exception as exc:
            send_json_func(coded_error_payload_func(str(exc)[:500], "manual_phone_code_failed"), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/login-cancel":
        try:
            send_json_func(cancel_login_job_func(read_json_func(), workspace_id))
        except Exception as exc:
            send_json_func(coded_error_payload_func(str(exc)[:500], "login_cancel_failed"), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/login-start":
        try:
            payload = read_json_func()
            if payload.get("use_stored_mail_credentials") or payload.get("useStoredMailCredentials"):
                payload["_allow_stored_mail_credentials"] = True
            send_json_func(start_cpa_login_job_func(payload, workspace_id))
        except Exception as exc:
            details = classify_login_exception_func(exc)
            send_json_func(coded_error_payload_func(
                details.get("message", str(exc))[:500],
                details.get("code", "login_failed"),
                error_hint=details.get("hint", ""),
                retryable=details.get("retryable", True),
            ), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/direct-oauth-start":
        try:
            send_json_func(cpa_direct_oauth_start_func(read_json_func()))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/direct-oauth-callback":
        try:
            send_json_func(cpa_direct_oauth_callback_func(read_json_func()))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/client-api/cpa/companion-wait-code":
        send_json_func(disabled_cpa_refresh_path_payload_func("companion_wait_code"), status=HTTPStatus.GONE)
        return True
    if request_path == "/client-api/cpa/manual-oauth-start":
        send_json_func(disabled_cpa_refresh_path_payload_func("manual_oauth"), status=HTTPStatus.GONE)
        return True
    if request_path == "/client-api/cpa/manual-oauth-complete":
        send_json_func(disabled_cpa_refresh_path_payload_func("manual_oauth"), status=HTTPStatus.GONE)
        return True
    if request_path == "/client-api/cpa/local-oauth-start":
        send_json_func(disabled_cpa_refresh_path_payload_func("local_oauth"), status=HTTPStatus.GONE)
        return True
    return False


def handle_admin_post_route(
    request_path: str,
    *,
    require_auth_func: Callable[[], None],
    read_json_func: Callable[[], dict[str, Any]],
    send_json_func: Callable[..., None],
    send_error_func: Callable[[int], None],
    extract_admin_jwts_func: Callable[[dict[str, Any]], dict[str, Any]],
    push_public_pool_func: Callable[[dict[str, Any]], dict[str, Any]],
    create_upgrade_request_func: Callable[[dict[str, Any]], dict[str, Any]],
    plain_error_payload_func: Callable[[str], dict[str, Any]],
) -> bool:
    """处理后台管理 POST 路由。"""
    if not request_path.startswith("/admin-api/"):
        return False
    try:
        require_auth_func()
    except ConnectionAbortedError:
        return True
    if request_path == "/admin-api/extract-jwts":
        try:
            send_json_func(extract_admin_jwts_func(read_json_func()))
        except Exception as exc:
            send_json_func(plain_error_payload_func(str(exc)[:500]), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/admin-api/public-pool/push":
        try:
            send_json_func(push_public_pool_func(read_json_func()))
        except Exception as exc:
            send_json_func(plain_error_payload_func(str(exc)[:500]), status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/admin-api/upgrade/request":
        try:
            send_json_func(create_upgrade_request_func(read_json_func()))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    send_error_func(HTTPStatus.NOT_FOUND)
    return True


def handle_api_post_route(
    request_path: str,
    *,
    require_auth_func: Callable[[], None],
    read_json_func: Callable[[], dict[str, Any]],
    send_json_func: Callable[..., None],
    send_error_func: Callable[[int], None],
    workspace_id_func: Callable[[], str],
    fetch_saved_mail_func: Callable[[dict[str, Any], str], dict[str, Any]],
    lightweight_fetch_result_func: Callable[..., dict[str, Any]],
    parse_account_lines_func: Callable[[str], tuple[list[Any], list[str]]],
    parse_temp_address_lines_func: Callable[[str], tuple[list[Any], list[str]]],
    parse_generic_account_lines_func: Callable[[str], tuple[list[Any], list[str]]],
    load_accounts_func: Callable[[], dict[str, Any]],
    save_accounts_func: Callable[[dict[str, Any]], None],
    load_temp_addresses_func: Callable[[], dict[str, Any]],
    save_temp_addresses_func: Callable[[dict[str, Any]], None],
    load_generic_accounts_func: Callable[[], dict[str, Any]],
    save_generic_accounts_func: Callable[[dict[str, Any]], None],
    normalize_generic_account_func: Callable[[Any], Any],
    delete_stored_mail_message_func: Callable[[dict[str, Any]], dict[str, Any]],
    imported_account_list_payload_func: Callable[..., dict[str, Any]],
    imported_temp_address_list_payload_func: Callable[..., dict[str, Any]],
    deleted_account_list_payload_func: Callable[[int, list[Any]], dict[str, Any]],
    deleted_temp_address_list_payload_func: Callable[[int, list[Any]], dict[str, Any]],
    load_messages_func: Callable[[], list[dict[str, Any]]],
    filter_messages_func: Callable[[list[dict[str, Any]], dict[str, Any]], list[dict[str, Any]]],
    message_search_payload_func: Callable[[list[dict[str, Any]], dict[str, str]], dict[str, Any]],
    mail_type_labels: dict[str, str],
) -> bool:
    """处理 `/api/*` 里相对薄的删除与搜索 POST 路由。"""
    if not request_path.startswith("/api/"):
        return False
    try:
        require_auth_func()
    except ConnectionAbortedError:
        return True
    if request_path == "/api/fetch":
        result = dict(fetch_saved_mail_func(read_json_func(), workspace_id_func()))
        cached_count = int(result.pop("cached_count", 0) or 0)
        send_json_func(lightweight_fetch_result_func(result, cached_count=cached_count))
        return True
    if request_path == "/api/import":
        payload = read_json_func()
        incoming, errors = parse_account_lines_func(str(payload.get("text", "")))
        accounts = load_accounts_func()
        imported = 0
        skipped = 0
        updated = 0
        replace_existing = bool(payload.get("replace_existing") or payload.get("replaceExisting"))
        for account in incoming:
            key = account.email.lower()
            if key in accounts:
                if not replace_existing:
                    skipped += 1
                    continue
                account.created_at = accounts[key].created_at
                updated += 1
            else:
                imported += 1
            accounts[key] = account
        save_accounts_func(accounts)
        send_json_func(imported_account_list_payload_func(
            imported=imported,
            skipped=skipped,
            updated=updated,
            errors=errors,
            accounts=list(accounts.values()),
        ))
        return True
    if request_path == "/api/temp-addresses/import":
        payload = read_json_func()
        incoming, errors = parse_temp_address_lines_func(str(payload.get("text", "")))
        addresses = load_temp_addresses_func()
        imported = 0
        skipped = 0
        updated = 0
        replace_existing = bool(payload.get("replace_existing") or payload.get("replaceExisting"))
        for address in incoming:
            key = address.email.lower()
            if key in addresses:
                if not replace_existing:
                    skipped += 1
                    continue
                address.created_at = addresses[key].created_at
                updated += 1
            else:
                imported += 1
            addresses[key] = address
        save_temp_addresses_func(addresses)
        send_json_func(imported_temp_address_list_payload_func(
            imported=imported,
            skipped=skipped,
            updated=updated,
            errors=errors,
            addresses=list(addresses.values()),
        ))
        return True
    if request_path == "/api/generic-accounts/import":
        payload = read_json_func()
        incoming, errors = parse_generic_account_lines_func(str(payload.get("text", "")))
        accounts = load_generic_accounts_func()
        imported = 0
        skipped = 0
        updated = 0
        replace_existing = bool(payload.get("replace_existing") or payload.get("replaceExisting"))
        for account in incoming:
            key = account.email.lower()
            if key in accounts:
                if not replace_existing:
                    skipped += 1
                    continue
                account.created_at = accounts[key].created_at
                updated += 1
            else:
                imported += 1
            accounts[key] = normalize_generic_account_func(account)
        save_generic_accounts_func(accounts)
        send_json_func(imported_account_list_payload_func(
            imported=imported,
            skipped=skipped,
            updated=updated,
            errors=errors,
            accounts=list(accounts.values()),
        ))
        return True
    if request_path == "/api/messages/delete":
        try:
            send_json_func(delete_stored_mail_message_func(read_json_func()))
        except Exception as exc:
            send_json_func({"success": False, "error": str(exc)[:500]}, status=HTTPStatus.BAD_REQUEST)
        return True
    if request_path == "/api/delete":
        payload = read_json_func()
        emails = [email.lower() for email in payload.get("emails", []) if isinstance(email, str)]
        accounts = load_accounts_func()
        for email_addr in emails:
            accounts.pop(email_addr, None)
        save_accounts_func(accounts)
        send_json_func(deleted_account_list_payload_func(len(emails), list(accounts.values())))
        return True
    if request_path == "/api/temp-addresses/delete":
        payload = read_json_func()
        emails = [email.lower() for email in payload.get("emails", []) if isinstance(email, str)]
        addresses = load_temp_addresses_func()
        for email_addr in emails:
            addresses.pop(email_addr, None)
        save_temp_addresses_func(addresses)
        send_json_func(deleted_temp_address_list_payload_func(len(emails), list(addresses.values())))
        return True
    if request_path == "/api/generic-accounts/delete":
        payload = read_json_func()
        emails = [email.lower() for email in payload.get("emails", []) if isinstance(email, str)]
        accounts = load_generic_accounts_func()
        for email_addr in emails:
            accounts.pop(email_addr, None)
        save_generic_accounts_func(accounts)
        send_json_func(deleted_account_list_payload_func(len(emails), list(accounts.values())))
        return True
    if request_path == "/api/messages/search":
        payload = read_json_func()
        limit = max(1, min(int(payload.get("limit", 80)), 500))
        messages = filter_messages_func(load_messages_func(), payload)[:limit]
        send_json_func(message_search_payload_func(messages, mail_type_labels))
        return True
    send_error_func(HTTPStatus.NOT_FOUND)
    return True


__all__ = [
    "handle_admin_post_route",
    "handle_admin_get_route",
    "handle_auth_post_route",
    "handle_api_post_route",
    "handle_client_get_route",
    "handle_client_post_route",
    "handle_public_get_route",
]
