"""Web HTTP Handler runtime shell.

The class here owns HTTP request/response mechanics only. Business callbacks and
server-local constants are injected from the compatibility entrypoint so the web
layer does not need to import the legacy script.
"""
from __future__ import annotations

import hmac
import http.cookies
import json
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

from gpt_account_manager.core.error_messages import localize_error_payload

from .payloads import (
    account_list_payload,
    coded_error_payload,
    deleted_account_list_payload,
    deleted_temp_address_list_payload,
    disabled_cpa_refresh_path_payload,
    error_payload,
    imported_account_list_payload,
    imported_temp_address_list_payload,
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


@dataclass(frozen=True)
class HandlerRuntime:
    """Runtime dependencies injected by the compatibility entrypoint."""

    ADMIN_COOKIE_NAME: Any
    ADMIN_TOKEN: Any
    APP_VERSION: Any
    LOGIN_DEBUG_DIR: Any
    MAIL_TYPE_LABELS: Any
    MESSAGES_FILE: Any
    PUBLIC_POOL_URL: Any
    PUBLIC_RELAY_URL: Any
    STATIC_DIR: Any
    cached_messages_response: Any
    cancel_login_job: Any
    check_proxy_egress: Any
    classify_login_exception: Any
    cpa_direct_oauth_callback: Any
    dashboard_stats_response: Any
    cpa_direct_oauth_start: Any
    create_upgrade_request: Any
    delete_cpa_items: Any
    delete_stored_mail_message: Any
    delete_workspace_mail_credentials: Any
    extract_admin_jwts: Any
    fetch_transient_client_mail: Any
    fetch_saved_mail: Any
    filter_messages: Any
    get_client_mail_fetch_job: Any
    get_cpa_login_job: Any
    get_local_oauth_flow: Any
    health_payload: Any
    hydrate_login_mail_credentials: Any
    import_generic_accounts: Any
    import_pickup_accounts: Any
    import_temp_addresses: Any
    lightweight_fetch_result: Any
    load_accounts: Any
    load_asset_version: Any
    load_generic_accounts: Any
    load_login_history: Any
    load_messages: Any
    load_refresh_results: Any
    load_temp_addresses: Any
    network_health_payload: Any
    normalize_generic_account: Any
    normalize_workspace_id: Any
    parse_account_lines: Any
    parse_generic_account_lines: Any
    parse_temp_address_lines: Any
    poll_phone_code: Any
    public_config_payload: Any
    push_public_pool: Any
    refresh_cpa_lifecycle: Any
    refresh_lifecycle: Any
    repair_cpa_401: Any
    replace_cpa_auth_file: Any
    save_accounts: Any
    save_generic_accounts: Any
    save_temp_addresses: Any
    scan_cpa_401: Any
    set_login_manual_email_code: Any
    set_login_manual_phone_code: Any
    start_client_mail_fetch_job: Any
    start_cpa_login_job: Any
    sync_temp_jwts_from_worker: Any
    upgrade_status_payload: Any
    upsert_messages: Any
    workspace_file: Any


class Handler(BaseHTTPRequestHandler):
    runtime: HandlerRuntime
    server_version = "GPTAccountManager"

    def do_GET(self) -> None:
        parsed_request = urllib.parse.urlparse(self.path)
        request_path = parsed_request.path
        if handle_public_get_route(
            request_path,
            send_json_func=self.send_json,
            serve_static_file_func=self.serve_static_file,
            require_admin_page_auth_func=self.require_admin_page_auth,
            require_auth_func=self.require_auth,
            send_response_func=self.send_response,
            send_header_func=self.send_header,
            end_headers_func=self.end_headers,
            send_error_func=self.send_error,
            public_config_payload_func=self.runtime.public_config_payload,
            health_payload_func=self.runtime.health_payload,
            network_health_payload_func=self.runtime.network_health_payload,
            upgrade_status_payload_func=self.runtime.upgrade_status_payload,
            static_dir=self.runtime.STATIC_DIR,
            login_debug_dir=self.runtime.LOGIN_DEBUG_DIR,
            public_pool_url=self.runtime.PUBLIC_POOL_URL,
            public_relay_url=self.runtime.PUBLIC_RELAY_URL,
        ):
            return
        if handle_client_get_route(
            request_path,
            parsed_request.query,
            send_json_func=self.send_json,
            workspace_id_func=self.workspace_id,
            workspace_file_func=self.runtime.workspace_file,
            get_cpa_login_job_func=self.runtime.get_cpa_login_job,
            get_local_oauth_flow_func=self.runtime.get_local_oauth_flow,
            get_client_mail_fetch_job_func=self.runtime.get_client_mail_fetch_job,
            cached_messages_response_func=self.runtime.cached_messages_response,
            dashboard_stats_response_func=self.runtime.dashboard_stats_response,
            load_accounts_func=self.runtime.load_accounts,
            load_temp_addresses_func=self.runtime.load_temp_addresses,
            load_generic_accounts_func=self.runtime.load_generic_accounts,
            load_refresh_results_func=self.runtime.load_refresh_results,
            build_message_query_payload_func=build_message_query_payload,
            build_dashboard_stats_query_func=build_dashboard_stats_query,
            first_query_value_func=first_query_value,
            account_list_payload_func=account_list_payload,
            temp_address_list_payload_func=temp_address_list_payload,
            refresh_results_payload_func=refresh_results_payload,
        ):
            return
        if handle_admin_get_route(
            request_path,
            parsed_request.query,
            require_auth_func=self.require_auth,
            send_json_func=self.send_json,
            send_error_func=self.send_error,
            load_accounts_func=self.runtime.load_accounts,
            load_temp_addresses_func=self.runtime.load_temp_addresses,
            load_generic_accounts_func=self.runtime.load_generic_accounts,
            load_refresh_results_func=self.runtime.load_refresh_results,
            load_login_history_func=self.runtime.load_login_history,
            cached_messages_response_func=self.runtime.cached_messages_response,
            build_message_query_payload_func=build_message_query_payload,
            first_query_value_func=first_query_value,
            account_list_payload_func=account_list_payload,
            temp_address_list_payload_func=temp_address_list_payload,
            refresh_results_payload_func=refresh_results_payload,
            login_history_payload_func=login_history_payload,
            messages_file=self.runtime.MESSAGES_FILE,
        ):
            return
        self.serve_static()

    def do_POST(self) -> None:
        if handle_auth_post_route(
            self.path,
            read_json_func=self.read_json,
            send_json_func=self.send_json,
            send_json_with_headers_func=self.send_json_with_headers,
            error_payload_func=error_payload,
            success_payload_func=success_payload,
            admin_token=self.runtime.ADMIN_TOKEN,
            admin_cookie_header_func=self.admin_cookie_header,
            clear_admin_cookie_header_func=self.clear_admin_cookie_header,
        ):
            return
        if handle_client_post_route(
            self.path,
            read_json_func=self.read_json,
            send_json_func=self.send_json,
            workspace_id_func=self.workspace_id,
            workspace_file_func=self.runtime.workspace_file,
            hydrate_login_mail_credentials_func=self.runtime.hydrate_login_mail_credentials,
            fetch_transient_client_mail_func=self.runtime.fetch_transient_client_mail,
            upsert_messages_func=self.runtime.upsert_messages,
            lightweight_fetch_result_func=self.runtime.lightweight_fetch_result,
            start_client_mail_fetch_job_func=self.runtime.start_client_mail_fetch_job,
            delete_stored_mail_message_func=self.runtime.delete_stored_mail_message,
            scan_cpa_401_func=self.runtime.scan_cpa_401,
            repair_cpa_401_func=self.runtime.repair_cpa_401,
            delete_cpa_items_func=self.runtime.delete_cpa_items,
            replace_cpa_auth_file_func=self.runtime.replace_cpa_auth_file,
            refresh_lifecycle_func=self.runtime.refresh_lifecycle,
            refresh_cpa_lifecycle_func=self.runtime.refresh_cpa_lifecycle,
            check_proxy_egress_func=self.runtime.check_proxy_egress,
            classify_login_exception_func=self.runtime.classify_login_exception,
            coded_error_payload_func=coded_error_payload,
            plain_error_payload_func=plain_error_payload,
            sync_temp_jwts_from_worker_func=self.runtime.sync_temp_jwts_from_worker,
            import_pickup_accounts_func=self.runtime.import_pickup_accounts,
            import_temp_addresses_func=self.runtime.import_temp_addresses,
            import_generic_accounts_func=self.runtime.import_generic_accounts,
            delete_workspace_mail_credentials_func=self.runtime.delete_workspace_mail_credentials,
            poll_phone_code_func=self.runtime.poll_phone_code,
            set_login_manual_email_code_func=self.runtime.set_login_manual_email_code,
            set_login_manual_phone_code_func=self.runtime.set_login_manual_phone_code,
            cancel_login_job_func=self.runtime.cancel_login_job,
            start_cpa_login_job_func=self.runtime.start_cpa_login_job,
            cpa_direct_oauth_start_func=self.runtime.cpa_direct_oauth_start,
            cpa_direct_oauth_callback_func=self.runtime.cpa_direct_oauth_callback,
            disabled_cpa_refresh_path_payload_func=disabled_cpa_refresh_path_payload,
        ):
            return
        if handle_admin_post_route(
            self.path,
            require_auth_func=self.require_auth,
            read_json_func=self.read_json,
            send_json_func=self.send_json,
            send_error_func=self.send_error,
            extract_admin_jwts_func=self.runtime.extract_admin_jwts,
            push_public_pool_func=self.runtime.push_public_pool,
            create_upgrade_request_func=self.runtime.create_upgrade_request,
            plain_error_payload_func=plain_error_payload,
        ):
            return
        if handle_api_post_route(
            self.path,
            require_auth_func=self.require_auth,
            read_json_func=self.read_json,
            send_json_func=self.send_json,
            send_error_func=self.send_error,
            workspace_id_func=self.workspace_id,
            fetch_saved_mail_func=self.runtime.fetch_saved_mail,
            lightweight_fetch_result_func=self.runtime.lightweight_fetch_result,
            parse_account_lines_func=self.runtime.parse_account_lines,
            parse_temp_address_lines_func=self.runtime.parse_temp_address_lines,
            parse_generic_account_lines_func=self.runtime.parse_generic_account_lines,
            load_accounts_func=self.runtime.load_accounts,
            save_accounts_func=self.runtime.save_accounts,
            load_temp_addresses_func=self.runtime.load_temp_addresses,
            save_temp_addresses_func=self.runtime.save_temp_addresses,
            load_generic_accounts_func=self.runtime.load_generic_accounts,
            save_generic_accounts_func=self.runtime.save_generic_accounts,
            normalize_generic_account_func=self.runtime.normalize_generic_account,
            delete_stored_mail_message_func=self.runtime.delete_stored_mail_message,
            imported_account_list_payload_func=imported_account_list_payload,
            imported_temp_address_list_payload_func=imported_temp_address_list_payload,
            deleted_account_list_payload_func=deleted_account_list_payload,
            deleted_temp_address_list_payload_func=deleted_temp_address_list_payload,
            load_messages_func=self.runtime.load_messages,
            filter_messages_func=self.runtime.filter_messages,
            message_search_payload_func=message_search_payload,
            mail_type_labels=self.runtime.MAIL_TYPE_LABELS,
        ):
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def is_local_request(self) -> bool:
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        local_hosts = {"127.0.0.1", "localhost", "::1", "[::1]"}
        return self.client_address[0] in {"127.0.0.1", "::1"} and host in local_hosts

    def require_auth(self) -> None:
        if not self.runtime.ADMIN_TOKEN:
            if self.path.startswith("/admin-api/") and not self.is_local_request():
                self.send_json({
                    "error": "MAIL_PICKUP_ADMIN_TOKEN is required for admin APIs on this server."
                }, status=HTTPStatus.SERVICE_UNAVAILABLE)
                raise ConnectionAbortedError("admin token missing")
            return
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {self.runtime.ADMIN_TOKEN}" and not self.has_admin_cookie():
            self.send_json({"error": "Unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
            raise ConnectionAbortedError("unauthorized")

    def require_admin_page_auth(self) -> None:
        if self.admin_request_authorized():
            return
        if not self.runtime.ADMIN_TOKEN:
            self.send_error(HTTPStatus.FORBIDDEN)
            raise ConnectionAbortedError("admin page local only")
        else:
            self.send_error(HTTPStatus.NOT_FOUND)
            raise ConnectionAbortedError("admin page unauthorized")

    def admin_request_authorized(self) -> bool:
        if not self.runtime.ADMIN_TOKEN:
            return self.is_local_request()
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        token = query.get("token", [""])[0]
        auth = self.headers.get("Authorization", "")
        return token == self.runtime.ADMIN_TOKEN or auth == f"Bearer {self.runtime.ADMIN_TOKEN}" or self.has_admin_cookie()

    def workspace_id(self) -> str:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        header_value = self.headers.get("X-Workspace-Id", "")
        query_value = query.get("workspace_id", [""])[0] or query.get("workspaceId", [""])[0]
        return self.runtime.normalize_workspace_id(header_value or query_value)

    def has_admin_cookie(self) -> bool:
        if not self.runtime.ADMIN_TOKEN:
            return False
        try:
            cookies = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return False
        morsel = cookies.get(self.runtime.ADMIN_COOKIE_NAME)
        return bool(morsel and hmac.compare_digest(urllib.parse.unquote(morsel.value), self.runtime.ADMIN_TOKEN))

    def admin_cookie_header(self, token: str) -> str:
        return f"{self.runtime.ADMIN_COOKIE_NAME}={urllib.parse.quote(token, safe='')}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax"

    def clear_admin_cookie_header(self) -> str:
        return f"{self.runtime.ADMIN_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8-sig"))

    def send_json(self, payload: dict[str, Any], status: int = HTTPStatus.OK) -> None:
        self.send_json_with_headers(payload, status=status)

    def send_json_with_headers(self, payload: dict[str, Any], headers: dict[str, str] | None = None, status: int = HTTPStatus.OK) -> None:
        localized_payload = localize_error_payload(payload)
        body = json.dumps(localized_payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def serve_static(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        if path in {"/admin", "/admin.html"}:
            if not self.admin_request_authorized():
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/login.html?next=/admin.html")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            target = self.runtime.STATIC_DIR / "admin.html"
            self.serve_static_file(target)
            return
        if path in {"", "/"}:
            target = self.runtime.STATIC_DIR / "index.html"
        elif path in {"/converter", "/converter/"}:
            target = self.runtime.STATIC_DIR / "converter.html"
        elif path in {"/dashboard", "/dashboard/"}:
            target = self.runtime.STATIC_DIR / "dashboard.html"
        elif path in {"/refresh", "/refresh/"}:
            target = self.runtime.STATIC_DIR / "refresh.html"
        elif path in {"/mailboxes", "/mailboxes/"}:
            target = self.runtime.STATIC_DIR / "mailboxes.html"
        elif path in {"/warehouse", "/warehouse/"}:
            target = self.runtime.STATIC_DIR / "warehouse.html"
        else:
            target = (self.runtime.STATIC_DIR / path.lstrip("/")).resolve()
            if self.runtime.STATIC_DIR.resolve() not in target.parents and target != self.runtime.STATIC_DIR.resolve():
                self.send_error(HTTPStatus.FORBIDDEN)
                return
        self.serve_static_file(target)

    def serve_static_file(self, target: Path) -> None:
        if not target.exists() or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = "text/plain; charset=utf-8"
        if target.suffix == ".html":
            content_type = "text/html; charset=utf-8"
        elif target.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif target.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        if target.suffix == ".html":
            body = target.read_text(encoding="utf-8").replace("{{APP_VERSION}}", self.runtime.load_asset_version()).encode("utf-8")
        else:
            body = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if target.suffix in {".css", ".js", ".svg"}:
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        else:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {self.address_string()} {fmt % args}", flush=True)



def build_handler_class(runtime: HandlerRuntime) -> type[Handler]:
    """Build a concrete handler class bound to the current server runtime."""
    return type(
        "Handler",
        (Handler,),
        {
            "runtime": runtime,
            "server_version": f"GPTAccountManager/{runtime.APP_VERSION}",
        },
    )
