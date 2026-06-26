from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import email as email_lib
import io
import imaplib
import ipaddress
import json
import os
import poplib
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
import contextlib
import http.client
import http.cookies
import hmac
import inspect
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone, timedelta
from email.header import decode_header
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from gpt_account_manager.mail.providers import (
    classify_mail_fetch_error as provider_classify_mail_fetch_error,
    infer_generic_mail_config as provider_infer_generic_mail_config,
    microsoft_provider_sequence as provider_microsoft_provider_sequence,
    normalize_generic_mail_mode as provider_normalize_generic_mail_mode,
    run_mail_fetch_jobs as provider_run_mail_fetch_jobs,
)
from gpt_account_manager.core import (
    is_terminal_refresh_state,
    normalize_refresh_state,
    refresh_state_from_step,
    refresh_status_for_state,
)
from gpt_account_manager.storage.workspace import (
    file_item_count as storage_file_item_count,
    load_json_file as storage_load_json_file,
    normalize_workspace_id as storage_normalize_workspace_id,
    workspace_counts as storage_workspace_counts,
    workspace_dir as storage_workspace_dir,
    workspace_file as storage_workspace_file,
    write_json_file as storage_write_json_file,
)
from gpt_account_manager.storage.api import (
    LOGIN_HISTORY_FILE as storage_LOGIN_HISTORY_FILE,
    LOGIN_HISTORY_LIMIT as storage_LOGIN_HISTORY_LIMIT,
    REFRESH_RESULTS_LIMIT as storage_REFRESH_RESULTS_LIMIT,
    append_refresh_result as storage_append_refresh_result,
    load_refresh_results as storage_load_refresh_results,
    save_refresh_results as storage_save_refresh_results,
    append_login_history_entry as storage_append_login_history_entry,
    load_login_history as storage_load_login_history,
    load_messages as storage_load_messages,
    message_key as storage_message_key,
    message_sort_value as storage_message_sort_value,
    parse_message_datetime as storage_parse_message_datetime,
    save_login_history as storage_save_login_history,
    save_messages as storage_save_messages,
    upsert_messages as storage_upsert_messages,
)
from gpt_account_manager.infra import (
    HostHeaderHTTPSConnection as infra_HostHeaderHTTPSConnection,
    HostHeaderIMAP4SSL as infra_HostHeaderIMAP4SSL,
    cached_fallback_ips as infra_cached_fallback_ips,
    dns_overrides_for_url as infra_dns_overrides_for_url,
    resolve_host_with_doh as infra_resolve_host_with_doh,
    check_proxy_egress as infra_check_proxy_egress,
    create_ip_connection as infra_create_ip_connection,
    http_get_json_status as infra_http_get_json_status,
    http_json as infra_http_json,
    http_json_via_cached_ip_fallback as infra_http_json_via_cached_ip_fallback,
    http_json_via_ip_fallback as infra_http_json_via_ip_fallback,
    http_request_form_json as infra_http_request_form_json,
    http_request_json as infra_http_request_json,
    http_text as infra_http_text,
    is_dns_error as infra_is_dns_error,
    is_loopback_host as infra_is_loopback_host,
    is_private_host as infra_is_private_host,
    mail_network_probe_hosts as infra_mail_network_probe_hosts,
    network_error_message as infra_network_error_message,
    validate_remote_base_url as infra_validate_remote_base_url,
    network_health_payload as infra_network_health_payload,
    open_with_fast_dns as infra_open_with_fast_dns,
    playwright_proxy_options as infra_playwright_proxy_options,
    probe_egress_trace as infra_probe_egress_trace,
    proxy_opener as infra_proxy_opener,
    request_proxy_url as infra_request_proxy_url,
    require_login_proxy_url as infra_require_login_proxy_url,
    set_dns_fallback_cache as infra_set_dns_fallback_cache,
    socks_dependency_error as infra_socks_dependency_error,
    sticky_proxy_url as infra_sticky_proxy_url,
    temporary_dns_overrides as infra_temporary_dns_overrides,
    temporary_socket_proxy as infra_temporary_socket_proxy,
    urlopen_with_dns_retry as infra_urlopen_with_dns_retry,
)
from gpt_account_manager.infra import (
    normalize_proxy_url as infra_normalize_proxy_url,
)
from gpt_account_manager.mail.api import (
    MAIL_TYPE_LABELS as mail_MAIL_TYPE_LABELS,
    GenericMailAccount,
    MailAccount,
    TempAddress,
    MailProtocolRuntime as mail_MailProtocolRuntime,
    MAIL_FETCH_JOBS as mail_MAIL_FETCH_JOBS,
    MAIL_FETCH_JOBS_LOCK as mail_MAIL_FETCH_JOBS_LOCK,
    MAIL_FETCH_JOB_LIMIT as mail_MAIL_FETCH_JOB_LIMIT,
    get_client_mail_fetch_job as mail_get_client_mail_fetch_job,
    mail_fetch_job_public as mail_mail_fetch_job_public,
    run_client_mail_fetch_job as mail_run_client_mail_fetch_job,
    set_mail_fetch_job as mail_set_mail_fetch_job,
    start_client_mail_fetch_job as mail_start_client_mail_fetch_job,
    trim_mail_fetch_jobs as mail_trim_mail_fetch_jobs,
    append_imap_raw_message as mail_append_imap_raw_message,
    apply_mail_fetch_result_fields as mail_apply_mail_fetch_result_fields,
    classify_mail_fetch_error as mail_classify_mail_fetch_error,
    fetch_cloudmail_messages as mail_fetch_cloudmail_messages,
    fetch_for_account as mail_fetch_for_account,
    fetch_for_generic_account as mail_fetch_for_generic_account,
    fetch_for_temp_address as mail_fetch_for_temp_address,
    fetch_generic_messages as mail_fetch_generic_messages,
    fetch_generic_imap_messages as mail_fetch_generic_imap_messages,
    fetch_generic_pop3_messages as mail_fetch_generic_pop3_messages,
    fetch_imap_messages as mail_fetch_imap_messages,
    fetch_imap_messages_with_connection as mail_fetch_imap_messages_with_connection,
    fetch_inbucket_messages as mail_fetch_inbucket_messages,
    fetch_luckmail_messages as mail_fetch_luckmail_messages,
    fetch_temp_messages as mail_fetch_temp_messages,
    get_imap_token as mail_get_imap_token,
    normalize_cloudmail_messages as mail_normalize_cloudmail_messages,
    normalize_inbucket_messages as mail_normalize_inbucket_messages,
    normalize_luckmail_messages as mail_normalize_luckmail_messages,
    mail_fetch_error_result as mail_mail_fetch_error_result,
    microsoft_provider_sequence as mail_microsoft_provider_sequence,
    open_imap_ssl as mail_open_imap_ssl,
    open_imap_ssl_port as mail_open_imap_ssl_port,
    fetch_graph_messages as mail_fetch_graph_messages,
    fetch_outlook_api_messages as mail_fetch_outlook_api_messages,
    get_graph_token as mail_get_graph_token,
    refresh_microsoft_access_token as mail_refresh_microsoft_access_token,
    run_mail_fetch_jobs as mail_run_mail_fetch_jobs,
    temp_headers as mail_temp_headers,
    decode_bytes as mail_decode_bytes,
    decode_message_part as mail_decode_message_part,
    decode_mime_header as mail_decode_mime_header,
    extract_admin_jwt as mail_extract_admin_jwt,
    extract_admin_jwts as mail_extract_admin_jwts,
    extract_body as mail_extract_body,
    extract_body_parts as mail_extract_body_parts,
    extract_codes as mail_extract_codes,
    extract_links as mail_extract_links,
    cached_messages_response as mail_cached_messages_response,
    delete_cached_mail_message as mail_delete_cached_mail_message,
    delete_cached_mail_messages as mail_delete_cached_mail_messages,
    delete_workspace_mail_credentials as mail_delete_workspace_mail_credentials,
    fetch_saved_mail as mail_fetch_saved_mail,
    delete_stored_mail_message as mail_delete_stored_mail_message,
    fetch_transient_client_mail as mail_fetch_transient_client_mail,
    import_generic_accounts as mail_import_generic_accounts,
    import_pickup_accounts as mail_import_pickup_accounts,
    import_temp_addresses as mail_import_temp_addresses,
    filter_messages as mail_filter_messages,
    load_accounts as mail_load_accounts,
    load_generic_accounts as mail_load_generic_accounts,
    load_temp_addresses as mail_load_temp_addresses,
    normalize_generic_account as mail_normalize_generic_account,
    remove_cached_message as mail_remove_cached_message,
    parse_account_lines as mail_parse_account_lines,
    parse_generic_account_lines as mail_parse_generic_account_lines,
    parse_temp_address_lines as mail_parse_temp_address_lines,
    payload_rows as mail_payload_rows,
    normalize_mail_type as mail_normalize_mail_type,
    normalize_message as mail_normalize_message,
    normalize_raw_email as mail_normalize_raw_email,
    parse_raw_email as mail_parse_raw_email,
    save_accounts as mail_save_accounts,
    save_generic_accounts as mail_save_generic_accounts,
    save_temp_addresses as mail_save_temp_addresses,
    sanitize_email_html as mail_sanitize_email_html,
    strip_html as mail_strip_html,
    sync_temp_jwts_from_worker as mail_sync_temp_jwts_from_worker,
    transient_generic_accounts as mail_transient_generic_accounts,
    transient_mail_accounts as mail_transient_mail_accounts,
    transient_temp_addresses as mail_transient_temp_addresses,
    validate_admin_worker_url as mail_validate_admin_worker_url,
    admin_worker_headers as mail_admin_worker_headers,
)
from gpt_account_manager.workspace.api import (
    public_pool_rows_from_payload as workspace_public_pool_rows_from_payload,
    push_public_pool as workspace_push_public_pool,
)
from gpt_account_manager.cpa.api import (
    build_cpa_repair_login_payload as cpa_build_cpa_repair_login_payload,
    cpa_headers as cpa_headers_impl,
    cpa_auth_filename as cpa_auth_filename_impl,
    cpa_companion_wait_code as cpa_companion_wait_code_impl,
    cpa_is_401_item as cpa_is_401_item_impl,
    cpa_item_chatgpt_account_id as cpa_item_chatgpt_account_id_impl,
    cpa_item_type as cpa_item_type_impl,
    cpa_oauth_value as cpa_oauth_value_impl,
    extract_state_from_auth_url as cpa_extract_state_from_auth_url_impl,
    infer_auth_email as cpa_infer_auth_email_impl,
    looks_like_openai_auth_file as cpa_looks_like_openai_auth_file_impl,
    normalize_cpa_base_url as cpa_normalize_cpa_base_url_impl,
    cpa_status_message as cpa_status_message_impl,
    collect_nested_error_texts as cpa_collect_nested_error_texts_impl,
    compact_raw_status as cpa_compact_raw_status_impl,
    parse_nested_json_value as cpa_parse_nested_json_value_impl,
    cpa_delete_auth_file as cpa_delete_auth_file_impl,
    cpa_download_auth_file as cpa_download_auth_file_impl,
    cpa_list_auth_files as cpa_list_auth_files_impl,
    cpa_probe_status as cpa_probe_status_impl,
    cpa_upload_auth_file as cpa_upload_auth_file_impl,
    cpa_diagnosis_action_hint as cpa_diagnosis_action_hint_impl,
    cpa_status_refreshable as cpa_status_refreshable_impl,
    diagnose_cpa_candidate as cpa_diagnose_cpa_candidate_impl,
    repair_cpa_401 as cpa_repair_cpa_401_impl,
    scan_cpa_401 as cpa_scan_cpa_401_impl,
)
from gpt_account_manager.login.api import (
    access_token_email as login_access_token_email_impl,
    access_token_expires_at as login_access_token_expires_at_impl,
    access_token_plan_type as login_access_token_plan_type_impl,
    build_synthetic_id_token as login_build_synthetic_id_token_impl,
    generate_openai_sentinel_token as login_generate_openai_sentinel_token_impl,
    classify_login_exception as login_classify_login_exception_impl,
    classify_oauth_error as login_classify_oauth_error_impl,
    jwt_payload as login_jwt_payload_impl,
    normal_plan_type as login_normal_plan_type_impl,
    build_chatgpt_login_url as login_build_chatgpt_login_url_impl,
    build_openai_oauth_authorize_url as login_build_openai_oauth_authorize_url_impl,
    generate_openai_code_verifier as login_generate_openai_code_verifier_impl,
    oauth_base64url as login_oauth_base64url_impl,
    openai_code_challenge as login_openai_code_challenge_impl,
    build_playwright_login_url as login_build_playwright_login_url_impl,
    authorize_continue_requires_session_retry as login_authorize_continue_requires_session_retry_impl,
    account_session_next_url as login_account_session_next_url_impl,
    decode_oauth_session_cookie_value as login_decode_oauth_session_cookie_value_impl,
    analyze_oauth_callback_capture_hop as login_analyze_oauth_callback_capture_hop_impl,
    callback_has_code as login_callback_has_code_impl,
    build_protocol_headers as login_build_protocol_headers_impl,
    build_organization_select_payload as login_build_organization_select_payload_impl,
    build_workspace_select_payload as login_build_workspace_select_payload_impl,
    click_first_available as login_click_first_available_impl,
    fill_login_code as login_fill_login_code_impl,
    fetch_openai_oauth_with_playwright as login_fetch_openai_oauth_with_playwright_impl,
    fetch_openai_oauth_from_captured_code as login_fetch_openai_oauth_from_captured_code_impl,
    extract_oauth_authorize_params as login_extract_oauth_authorize_params_impl,
    extract_oauth_callback_url_from_error as login_extract_oauth_callback_url_from_error_impl,
    extract_continue_url as login_extract_continue_url_impl,
    extract_account_session_id_from_html as login_extract_account_session_id_from_html_impl,
    extract_email_verification_mode as login_extract_email_verification_mode_impl,
    extract_page_type as login_extract_page_type_impl,
    extract_query_param as login_extract_query_param_impl,
    first_workspace_id as login_first_workspace_id_impl,
    html_challenge_hint as login_html_challenge_hint_impl,
    first_visible_selector as login_first_visible_selector_impl,
    is_openai_security_verification_text as login_is_openai_security_verification_text_impl,
    is_oauth_chain_url as login_is_oauth_chain_url_impl,
    is_workspace_or_consent_url as login_is_workspace_or_consent_url_impl,
    looks_like_html_challenge as login_looks_like_html_challenge_impl,
    login_page_snapshot as login_login_page_snapshot_impl,
    save_login_debug_snapshot as login_save_login_debug_snapshot_impl,
    append_login_snapshot_log as login_append_login_snapshot_log_impl,
    optional_visible_selector as login_optional_visible_selector_impl,
    next_oauth_authorize_url as login_next_oauth_authorize_url_impl,
    analyze_oauth_authorize_hop as login_analyze_oauth_authorize_hop_impl,
    oauth2_auth_url_from_authorize as login_oauth2_auth_url_from_authorize_impl,
    oauth_response_hint as login_oauth_response_hint_impl,
    needs_add_phone as login_needs_add_phone_impl,
    needs_modern_otp as login_needs_modern_otp_impl,
    needs_phone_channel_selection as login_needs_phone_channel_selection_impl,
    needs_phone_verification as login_needs_phone_verification_impl,
    perform_protocol_request as login_perform_protocol_request_impl,
    playwright_page_hint as login_playwright_page_hint_impl,
    raise_if_playwright_auth_blocked as login_raise_if_playwright_auth_blocked_impl,
    run_chatgpt_login_with_playwright as login_run_chatgpt_login_with_playwright_impl,
    run_chatgpt_login_with_playwright_unlocked as login_run_chatgpt_login_with_playwright_unlocked_impl,
    run_chatgpt_signup_with_playwright as login_run_chatgpt_signup_with_playwright_impl,
    read_playwright_session as login_read_playwright_session_impl,
    ProtocolResponse as login_ProtocolResponse_impl,
    ProtocolLoginRuntime as login_ProtocolLoginRuntime_impl,
    ChatGPTProtocolLogin as login_ChatGPTProtocolLogin_impl,
    run_chatgpt_login_with_protocol as login_run_chatgpt_login_with_protocol_impl,
    payload_has_cpa_config as login_payload_has_cpa_config_impl,
    protocol_compact_error as login_protocol_compact_error_impl,
    format_oauth_authorize_hop_log as login_format_oauth_authorize_hop_log_impl,
    read_response_text as login_read_response_text_impl,
    normalize_auth_url as login_normalize_auth_url_impl,
    parse_oauth_callback_params as login_parse_oauth_callback_params_impl,
    safe_url_for_log as login_safe_url_for_log_impl,
    session_from_cpa_callback_result as login_session_from_cpa_callback_result_impl,
    validate_oauth_exchange_response as login_validate_oauth_exchange_response_impl,
    validate_session_response as login_validate_session_response_impl,
    workspace_select_next_url as login_workspace_select_next_url_impl,
    wait_and_click_first_available as login_wait_and_click_first_available_impl,
    wait_for_openai_login_ready as login_wait_for_openai_login_ready_impl,
    wait_for_chatgpt_logged_in as login_wait_for_chatgpt_logged_in_impl,
    build_lifecycle_access_token_outcome as login_build_lifecycle_access_token_outcome_impl,
    build_lifecycle_auth_probe_result_update as login_build_lifecycle_auth_probe_result_update_impl,
    build_lifecycle_refresh_token_outcome as login_build_lifecycle_refresh_token_outcome_impl,
    build_lifecycle_session_payload_from_session_json as login_build_lifecycle_session_payload_from_session_json_impl,
    build_lifecycle_session_token_outcome as login_build_lifecycle_session_token_outcome_impl,
    build_lifecycle_token_session_payload as login_build_lifecycle_token_session_payload_impl,
    empty_lifecycle_result as login_empty_lifecycle_result_impl,
    exchange_openai_oauth_code as login_exchange_openai_oauth_code_impl,
    lifecycle_summary as login_lifecycle_summary_impl,
    lifecycle_source_auth as login_lifecycle_source_auth_impl,
    lifecycle_status_label as login_lifecycle_status_label_impl,
    merge_session_with_oauth as login_merge_session_with_oauth_impl,
    normalize_lifecycle_item as login_normalize_lifecycle_item_impl,
    openai_error_fields as login_openai_error_fields_impl,
    probe_openai_access_token as login_probe_openai_access_token_impl,
    refresh_openai_with_rt as login_refresh_openai_with_rt_impl,
    refresh_openai_with_session_token as login_refresh_openai_with_session_token_impl,
    usage_limit_message as login_usage_limit_message_impl,
    LoginFlowError as login_LoginFlowError,
    openai_turnstile_error as login_openai_turnstile_error,
    LOGIN_DEBUG_DIR as login_LOGIN_DEBUG_DIR,
    LOGIN_JOBS as login_LOGIN_JOBS,
    LOGIN_JOBS_LOCK as login_LOGIN_JOBS_LOCK,
    LOGIN_LOG_LIMIT as login_LOGIN_LOG_LIMIT,
    append_login_log as login_append_login_log,
    cancel_login_job as login_cancel_login_job,
    clean_manual_email_code as login_clean_manual_email_code,
    get_login_job as login_get_login_job,
    login_job_cancel_requested as login_login_job_cancel_requested,
    login_job_public as login_login_job_public,
    run_cpa_login_job as login_run_cpa_login_job_impl,
    start_cpa_login_job as login_start_cpa_login_job_impl,
    manual_email_code_for_payload as login_manual_email_code_for_payload,
    manual_phone_code_for_payload as login_manual_phone_code_for_payload,
    raise_if_login_job_cancelled as login_raise_if_login_job_cancelled,
    set_login_job_status as login_set_login_job_status,
    set_login_manual_email_code as login_set_login_manual_email_code,
    set_login_manual_phone_code as login_set_login_manual_phone_code,
    LOCAL_OAUTH_FLOWS as login_LOCAL_OAUTH_FLOWS,
    LOCAL_OAUTH_LOCK as login_LOCAL_OAUTH_LOCK,
    LOCAL_OAUTH_PORT as login_LOCAL_OAUTH_PORT,
    LocalOAuthCallbackHandler as login_LocalOAuthCallbackHandler,
    create_local_oauth_flow as login_create_local_oauth_flow_impl,
    get_local_oauth_flow as login_get_local_oauth_flow_impl,
    handle_local_oauth_callback as login_handle_local_oauth_callback_impl,
    parse_localhost_oauth_callback as login_parse_localhost_oauth_callback_impl,
    start_local_oauth_callback_server as login_start_local_oauth_callback_server_impl,
    collect_sms_candidates as login_collect_sms_candidates_impl,
    count_six_digit_codes as login_count_six_digit_codes_impl,
    extract_phone_hint_from_step as login_extract_phone_hint_from_step_impl,
    extract_phone_hint_from_text as login_extract_phone_hint_from_text_impl,
    extract_sms_code_payload as login_extract_sms_code_payload_impl,
    fetch_login_verification_code as login_fetch_login_verification_code_impl,
    fetch_registration_verification_link as login_fetch_registration_verification_link_impl,
    resolve_phone_code_source as login_resolve_phone_code_source_impl,
    find_latest_code as login_find_latest_code_impl,
    message_six_digit_codes as login_message_six_digit_codes_impl,
    normalize_phone_digits as login_normalize_phone_digits_impl,
    normalize_sms_field_name as login_normalize_sms_field_name_impl,
    phone_api_url as login_phone_api_url_impl,
    poll_phone_code as login_poll_phone_code_impl,
    phone_pool_entries_from_payload as login_phone_pool_entries_from_payload_impl,
    phone_pool_match_by_hint as login_phone_pool_match_by_hint_impl,
)
from gpt_account_manager.web.api import (
    account_list_payload,
    build_health_payload,
    build_public_config_payload,
    build_public_top_links,
    build_upgrade_request_record,
    build_upgrade_request_response,
    build_upgrade_status_payload,
    coded_error_payload,
    dashboard_stats_response as web_dashboard_stats_response_impl,
    health_payload as web_health_payload_impl,
    public_top_links as web_public_top_links_impl,
    public_config_payload as web_public_config_payload_impl,
    upgrade_status_payload as web_upgrade_status_payload_impl,
    create_upgrade_request as web_create_upgrade_request_impl,
    deleted_account_list_payload,
    deleted_temp_address_list_payload,
    delete_transient_client_mail_message_payload,
    disabled_cpa_refresh_path_payload,
    error_payload,
    handle_api_post_route,
    handle_admin_get_route,
    handle_admin_post_route,
    handle_auth_post_route,
    handle_client_get_route,
    handle_client_post_route,
    handle_public_get_route,
    imported_account_list_payload,
    imported_temp_address_list_payload,
    login_history_payload,
    message_search_payload,
    plain_error_payload,
    refresh_results_payload,
    success_payload,
    temp_address_list_payload,
    lightweight_fetch_result as web_lightweight_fetch_result,
    lightweight_mail_fetch_result as web_lightweight_mail_fetch_result,
    build_dashboard_stats_query,
    build_message_query_payload,
    first_query_value,
)
from gpt_account_manager.web.handler import (
    HandlerRuntime as web_HandlerRuntime_impl,
    build_handler_class as web_build_handler_class,
)
from gpt_account_manager.app import (
    complete_oauth_code_payload as app_complete_oauth_code_payload_impl,
    CompatCpaRuntimeConfig as app_CompatCpaRuntimeConfig_impl,
    CompatCpaSupport as app_CompatCpaSupport_impl,
    finalize_cpa_login_job_failure as app_finalize_cpa_login_job_failure_impl,
    finalize_cpa_login_job_success as app_finalize_cpa_login_job_success_impl,
    finalize_cpa_login_success as app_finalize_cpa_login_success_impl,
    hydrate_login_mail_credentials as app_hydrate_login_mail_credentials_impl,
    login_mail_credential_counts as app_login_mail_credential_counts_impl,
    load_app_version as app_load_app_version_impl,
    load_asset_version as app_load_asset_version_impl,
    prepare_cpa_login_job_start as app_prepare_cpa_login_job_start_impl,
    refresh_cpa_lifecycle as app_refresh_cpa_lifecycle_impl,
    finalize_refresh_lifecycle_success as app_finalize_refresh_lifecycle_success_impl,
    refresh_lifecycle as app_refresh_lifecycle_impl,
    refresh_lifecycle_item as app_refresh_lifecycle_item_impl,
    resolve_cpa_login_session_payload as app_resolve_cpa_login_session_payload_impl,
    run_http_service as app_run_http_service_impl,
    session_to_cpa_auth as app_session_to_cpa_auth_impl,
    CompatLoginRuntimeConfig as app_CompatLoginRuntimeConfig_impl,
    CompatLoginSupport as app_CompatLoginSupport_impl,
    CompatWebRuntimeConfig as app_CompatWebRuntimeConfig_impl,
    CompatWebSupport as app_CompatWebSupport_impl,
)


def normalize_base_url(value: str) -> str:
    clean = str(value or "").strip()
    if clean and not re.match(r"^https?://", clean, flags=re.I):
        clean = f"https://{clean}"
    return clean.rstrip("/")


def normalize_cpa_base_url(value: str) -> str:
    # 兼容旧调用点，CPA 基础地址规整已迁到 cpa.service。
    return cpa_normalize_cpa_base_url_impl(value)


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
DATA_DIR = ROOT / "data"
WORKSPACES_DIR = DATA_DIR / "workspaces"
ACCOUNTS_FILE = DATA_DIR / "accounts.json"
MESSAGES_FILE = DATA_DIR / "messages.json"
TEMP_ADDRESSES_FILE = DATA_DIR / "temp_addresses.json"
GENERIC_ACCOUNTS_FILE = DATA_DIR / "generic_accounts.json"
REFRESH_RESULTS_FILE = DATA_DIR / "refresh_results.json"
LOGIN_HISTORY_FILE = storage_LOGIN_HISTORY_FILE
LOGIN_DEBUG_DIR = login_LOGIN_DEBUG_DIR
UPGRADE_REQUEST_FILE = DATA_DIR / "upgrade_request.json"
UPGRADE_RESULT_FILE = DATA_DIR / "upgrade_result.json"
PACKAGE_FILE = ROOT / "package.json"


def load_app_version() -> str:
    # ????????????????? app.version?
    return app_load_app_version_impl(PACKAGE_FILE)


APP_VERSION = load_app_version()


def load_asset_version() -> str:
    # ??????????????????? app.version?
    return app_load_asset_version_impl(STATIC_DIR, APP_VERSION)


ASSET_VERSION = load_asset_version()

DEFAULT_HOST = os.environ.get("MAIL_PICKUP_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("MAIL_PICKUP_PORT", "8765"))
ADMIN_TOKEN = os.environ.get("MAIL_PICKUP_ADMIN_TOKEN", "").strip()
ADMIN_COOKIE_NAME = "ctgptm_admin_token"
PUBLIC_STORE_URL = (os.environ.get("GPT_ACCOUNT_MANAGER_STORE_URL") or os.environ.get("CTGPTM_STORE_URL", "")).strip()
PUBLIC_RELAY_URL = (os.environ.get("GPT_ACCOUNT_MANAGER_RELAY_URL") or os.environ.get("CTGPTM_RELAY_URL", "")).strip()
PUBLIC_POOL_URL = (os.environ.get("GPT_ACCOUNT_MANAGER_PUBLIC_POOL_URL") or os.environ.get("CTGPTM_PUBLIC_POOL_URL", "")).strip()
PUBLIC_POOL_API_URL = (os.environ.get("GPT_ACCOUNT_MANAGER_PUBLIC_POOL_API_URL") or os.environ.get("CTGPTM_PUBLIC_POOL_API_URL", "")).strip()
PUBLIC_POOL_TOKEN = (os.environ.get("GPT_ACCOUNT_MANAGER_PUBLIC_POOL_TOKEN") or os.environ.get("CTGPTM_PUBLIC_POOL_TOKEN", "")).strip()
PUBLIC_APP_TITLE = (os.environ.get("GPT_ACCOUNT_MANAGER_APP_TITLE") or os.environ.get("CTGPTM_APP_TITLE", "GPT账号管理助手")).strip()
DEFAULT_TEMP_WORKER_URL = ""
TEMP_WORKER_DNS_FALLBACK_IPS = [
    item.strip()
    for item in os.environ.get("GPT_ACCOUNT_MANAGER_TEMP_WORKER_FALLBACK_IPS", "").split(",")
    if item.strip()
]
TEMP_WORKER_DNS_FALLBACK_HOST = urllib.parse.urlparse(DEFAULT_TEMP_WORKER_URL).hostname or ""
OPENAI_STATIC_FALLBACK_IPS = {
    "chatgpt.com": ["104.18.32.47", "172.64.155.209"],
    "auth.openai.com": ["104.18.41.241", "172.64.146.15"],
    "auth0.openai.com": ["172.65.90.20", "172.65.90.21", "172.65.90.22", "172.65.90.23"],
}
MICROSOFT_DNS_FALLBACK_HOSTS = {
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "outlook.office.com",
    "outlook.live.com",
    "outlook.office365.com",
    "login.live.com",
}
MICROSOFT_STATIC_FALLBACK_IPS: dict[str, list[str]] = {}
STATIC_DNS_FALLBACK_IPS = {
    **({TEMP_WORKER_DNS_FALLBACK_HOST: TEMP_WORKER_DNS_FALLBACK_IPS} if TEMP_WORKER_DNS_FALLBACK_HOST and TEMP_WORKER_DNS_FALLBACK_IPS else {}),
    **OPENAI_STATIC_FALLBACK_IPS,
    **MICROSOFT_STATIC_FALLBACK_IPS,
}
DNS_FALLBACK_HOSTS = set(STATIC_DNS_FALLBACK_IPS) | MICROSOFT_DNS_FALLBACK_HOSTS
DNS_FALLBACK_CACHE: dict[str, list[str]] = {}
DNS_OVERRIDE_LOCK = threading.RLock()
LEGACY_TEMP_WORKER_URLS: set[str] = set()


def sanitize_process_proxy_env() -> None:
    disabled_values = {"", "none", "direct", "off", "false", "0", "no_proxy", "noproxy"}
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        value = os.environ.get(key)
        if value is not None and value.strip().lower() in disabled_values:
            os.environ.pop(key, None)


sanitize_process_proxy_env()


def normalize_temp_worker_url(value: str) -> str:
    clean = normalize_base_url(value or DEFAULT_TEMP_WORKER_URL)
    return DEFAULT_TEMP_WORKER_URL if clean in LEGACY_TEMP_WORKER_URLS else clean


TEMP_WORKER_URL = normalize_temp_worker_url(os.environ.get("GPT_ACCOUNT_MANAGER_TEMP_WORKER_URL") or os.environ.get("CTGPTM_TEMP_WORKER_URL", DEFAULT_TEMP_WORKER_URL))
TEMP_SITE_PASSWORD = (os.environ.get("GPT_ACCOUNT_MANAGER_TEMP_SITE_PASSWORD") or os.environ.get("CTGPTM_TEMP_SITE_PASSWORD", "")).strip()
ALLOW_PRIVATE_URLS = os.environ.get("MAIL_PICKUP_ALLOW_PRIVATE_URLS", "").lower() in {"1", "true", "yes"}
CPA_ALLOW_REMOTE = os.environ.get("MAIL_PICKUP_CPA_ALLOW_REMOTE", "").lower() in {"1", "true", "yes"}
LOGIN_STRATEGY = "protocol"
LOGIN_FALLBACK_PLAYWRIGHT = False
LOGIN_NODE_BIN = os.environ.get("MAIL_PICKUP_NODE_BIN", "node").strip() or "node"
OPENAI_SENTINEL_HELPER = ROOT / "openai_sentinel_token.cjs"
OPENAI_OAUTH_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
OPENAI_OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
OPENAI_CODEX_CLIENT_ID = os.environ.get("OPENAI_CODEX_CLIENT_ID", "app_EMoamEEZ73f0CkXaXp7hrann").strip()
OPENAI_OAUTH_SCOPE = os.environ.get("OPENAI_OAUTH_SCOPE", "openid profile email offline_access").strip()
OPENAI_OAUTH_REFRESH_SCOPE = os.environ.get("OPENAI_OAUTH_REFRESH_SCOPE", "openid profile email").strip()
OPENAI_OAUTH_REDIRECT_URI = os.environ.get(
    "OPENAI_OAUTH_REDIRECT_URI",
    "http://localhost:1455/auth/callback",
).strip() or "http://localhost:1455/auth/callback"
CHATGPT_CHECK_URL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27?timezone_offset_min=-480"
CHATGPT_SESSION_URL = "https://chatgpt.com/api/auth/session"
CHATGPT_LOGIN_URL = os.environ.get("MAIL_PICKUP_CHATGPT_LOGIN_URL", "https://chatgpt.com/auth/login").strip() or "https://chatgpt.com/auth/login"

GRAPH_FOLDERS = ["inbox", "junkemail"]
IMAP_FOLDERS = ["INBOX", "Junk", "Junk Email"]
CODE_PATTERNS = [
    r"(?<!\d)(\d{6})(?!\d)",
    r"(?<![A-Za-z0-9])([A-Z0-9]{6,8})(?![A-Za-z0-9])",
]
MAIL_TYPE_LABELS = {
    "verification": "verification",
    "invite": "invite",
    "security": "security",
    "promotion": "promotion",
    "banned": "banned",
    "other": "other",
}
MAIL_TYPE_LABELS = mail_MAIL_TYPE_LABELS
DEFAULT_HTTP_HEADERS = {
    "Accept": "application/json",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    ),
}
OPENAI_SEC_CH_UA = '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"'
OPENAI_SEC_CH_UA_FULL_VERSION_LIST = '"Chromium";v="145.0.0.0", "Not:A-Brand";v="99.0.0.0", "Google Chrome";v="145.0.0.0"'
CPA_PROBE_USER_AGENT = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
LOGIN_JOBS = login_LOGIN_JOBS
LOGIN_JOBS_LOCK = login_LOGIN_JOBS_LOCK
LOGIN_LOG_LIMIT = login_LOGIN_LOG_LIMIT
MAIL_FETCH_JOBS = mail_MAIL_FETCH_JOBS
MAIL_FETCH_JOBS_LOCK = mail_MAIL_FETCH_JOBS_LOCK
MAIL_FETCH_JOB_LIMIT = mail_MAIL_FETCH_JOB_LIMIT
LOCAL_OAUTH_FLOWS = login_LOCAL_OAUTH_FLOWS
LOCAL_OAUTH_LOCK = login_LOCAL_OAUTH_LOCK
LOCAL_OAUTH_PORT = login_LOCAL_OAUTH_PORT
PLAYWRIGHT_MAX_CONCURRENCY = max(1, min(int(os.environ.get("MAIL_PICKUP_PLAYWRIGHT_MAX_CONCURRENCY", "2") or 2), 2))
PLAYWRIGHT_SEMAPHORE = threading.BoundedSemaphore(PLAYWRIGHT_MAX_CONCURRENCY)
MAIL_FETCH_MAX_CONCURRENCY = max(1, min(int(os.environ.get("MAIL_PICKUP_FETCH_CONCURRENCY", "8") or 8), 16))


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


STARTED_AT = iso_now()


def mask_secret(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"


def is_masked_secret(value: Any) -> bool:
    text = coerce_text(value)
    return bool(text and (set(text) <= {"*"} or "..." in text))


def usable_secret(value: Any) -> bool:
    text = coerce_text(value)
    return bool(text and not is_masked_secret(text))


def coerce_port(value: Any, default: int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 1 <= port <= 65535 else default


def normalize_generic_mail_mode(value: Any) -> str:
    return provider_normalize_generic_mail_mode(value)


def infer_generic_mail_config(email_addr: str) -> dict[str, Any]:
    return provider_infer_generic_mail_config(email_addr)


def normalize_generic_account(account: GenericMailAccount) -> GenericMailAccount:
    # 兼容旧调用点，字段规整已经迁到 mail.service。
    return mail_normalize_generic_account(account)


def file_item_count(path: Path, key: str) -> int:
    return storage_file_item_count(path, key)


def load_json_file(path: Path, fallback: Any) -> Any:
    return storage_load_json_file(path, fallback)


def write_json_file(path: Path, payload: Any) -> None:
    storage_write_json_file(path, payload)


def normalize_workspace_id(value: Any) -> str:
    return storage_normalize_workspace_id(value)


def workspace_dir(workspace_id: str) -> Path:
    return storage_workspace_dir(WORKSPACES_DIR, workspace_id)


def workspace_file(workspace_id: str, filename: str) -> Path:
    return storage_workspace_file(WORKSPACES_DIR, workspace_id, filename)


def workspace_counts(workspace_id: str) -> dict[str, int]:
    return storage_workspace_counts(WORKSPACES_DIR, workspace_id)


def health_payload() -> dict[str, Any]:
    # 兼容旧调用点，health 状态装配已迁到 web.status。
    return web_health_payload_impl(
        app_version=APP_VERSION,
        started_at=STARTED_AT,
        now=iso_now(),
        host=DEFAULT_HOST,
        port=DEFAULT_PORT,
        admin_token_set=bool(ADMIN_TOKEN),
        public_store_url=PUBLIC_STORE_URL,
        public_relay_url=PUBLIC_RELAY_URL,
        public_pool_url=PUBLIC_POOL_URL,
        temp_worker_url=TEMP_WORKER_URL,
        public_pool_api_url=bool(PUBLIC_POOL_API_URL),
        private_urls_allowed=ALLOW_PRIVATE_URLS,
        cpa_private_remote_allowed=CPA_ALLOW_REMOTE,
        login_strategy=LOGIN_STRATEGY,
        playwright_fallback=LOGIN_FALLBACK_PLAYWRIGHT,
        accounts_file=ACCOUNTS_FILE,
        temp_addresses_file=TEMP_ADDRESSES_FILE,
        generic_accounts_file=GENERIC_ACCOUNTS_FILE,
        messages_file=MESSAGES_FILE,
        workspace_root=WORKSPACES_DIR,
        root=ROOT,
        static_dir=STATIC_DIR,
        data_dir=DATA_DIR,
        file_item_count_func=file_item_count,
    )


def public_top_links() -> list[dict[str, str]]:
    # 兼容旧调用点，公开顶部链接装配已迁到 web.status。
    return web_public_top_links_impl(
        public_store_url=PUBLIC_STORE_URL,
        public_relay_url=PUBLIC_RELAY_URL,
        public_pool_url=PUBLIC_POOL_URL,
        normalize_base_url_func=normalize_base_url,
    )


def public_config_payload() -> dict[str, Any]:
    # 兼容旧调用点，公开配置响应已迁到 web.status。
    return web_public_config_payload_impl(
        title=PUBLIC_APP_TITLE,
        version=APP_VERSION,
        store_url=PUBLIC_STORE_URL,
        relay_url=PUBLIC_RELAY_URL,
        public_pool_url=PUBLIC_POOL_URL,
        public_pool_api_configured=bool(PUBLIC_POOL_API_URL),
        top_links=public_top_links(),
    )


def upgrade_status_payload() -> dict[str, Any]:
    # 兼容旧调用点，升级状态读取和装配已迁到 web.status。
    return web_upgrade_status_payload_impl(
        app_version=APP_VERSION,
        request_file=UPGRADE_REQUEST_FILE,
        result_file=UPGRADE_RESULT_FILE,
        load_json_file_func=load_json_file,
    )


def create_upgrade_request(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    # 兼容旧调用点，升级请求幂等逻辑已迁到 web.status。
    return web_create_upgrade_request_impl(
        payload,
        app_version=APP_VERSION,
        request_file=UPGRADE_REQUEST_FILE,
        result_file=UPGRADE_RESULT_FILE,
        now=iso_now(),
        request_id=f"upgrade-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}",
        load_json_file_func=load_json_file,
        write_json_file_func=write_json_file,
    )

def load_accounts(path: Path = ACCOUNTS_FILE) -> dict[str, MailAccount]:
    # 兼容旧调用点，账号 JSON 读取已经迁到 mail.service。
    return mail_load_accounts(path)


def save_accounts(accounts: dict[str, MailAccount], path: Path = ACCOUNTS_FILE) -> None:
    # 兼容旧调用点，账号 JSON 写入已经迁到 mail.service。
    mail_save_accounts(accounts, path)


def load_temp_addresses(path: Path = TEMP_ADDRESSES_FILE) -> dict[str, TempAddress]:
    # 兼容旧调用点，临时邮箱 JSON 读取已经迁到 mail.service。
    return mail_load_temp_addresses(
        path,
        default_base_url=TEMP_WORKER_URL,
        normalize_temp_worker_url_func=normalize_temp_worker_url,
    )


def save_temp_addresses(addresses: dict[str, TempAddress], path: Path = TEMP_ADDRESSES_FILE) -> None:
    # 兼容旧调用点，临时邮箱 JSON 写入已经迁到 mail.service。
    mail_save_temp_addresses(addresses, path)


def load_generic_accounts(path: Path = GENERIC_ACCOUNTS_FILE) -> dict[str, GenericMailAccount]:
    # 兼容旧调用点，普通邮箱 JSON 读取已经迁到 mail.service。
    return mail_load_generic_accounts(path)


def save_generic_accounts(accounts: dict[str, GenericMailAccount], path: Path = GENERIC_ACCOUNTS_FILE) -> None:
    # 兼容旧调用点，普通邮箱 JSON 写入已经迁到 mail.service。
    mail_save_generic_accounts(accounts, path)


def message_key(message: dict[str, Any]) -> str:
    # 兼容旧调用点，消息缓存键已经迁到 storage.messages。
    return storage_message_key(message)


def load_messages(path: Path = MESSAGES_FILE) -> list[dict[str, Any]]:
    # 兼容旧调用点，消息缓存读取已经迁到 storage.messages。
    return storage_load_messages(path)


def save_messages(messages: list[dict[str, Any]], path: Path = MESSAGES_FILE) -> None:
    # 兼容旧调用点，消息缓存写入已经迁到 storage.messages。
    storage_save_messages(messages, path)


def upsert_messages(incoming: list[dict[str, Any]], path: Path = MESSAGES_FILE) -> None:
    # 兼容旧调用点，消息缓存合并已经迁到 storage.messages。
    storage_upsert_messages(incoming, path)


def cached_messages_response(path: Path, payload: dict[str, Any], *, limit: int = 80, offset: int = 0) -> dict[str, Any]:
    # 兼容旧调用点，分页消息读取已经迁到 mail.service。
    return mail_cached_messages_response(path, payload, limit=limit, offset=offset)


def lightweight_fetch_result(result: dict[str, Any], *, cached_count: int = 0) -> dict[str, Any]:
    # 兼容旧调用点，取信结果压缩已经迁到 web.payloads。
    return web_lightweight_fetch_result(
        result,
        cached_count=cached_count,
        normalize_mail_type_func=normalize_mail_type,
    )


def lightweight_mail_fetch_result(result: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，单条取信结果压缩已经迁到 web.payloads。
    return web_lightweight_mail_fetch_result(
        result,
        normalize_mail_type_func=normalize_mail_type,
    )


def parse_message_datetime(value: Any) -> datetime | None:
    # 兼容旧调用点，消息时间解析已经迁到 storage.messages。
    return storage_parse_message_datetime(value)


def message_sort_value(message: dict[str, Any]) -> str:
    # Compatibility wrapper; message sorting now lives in storage.messages.
    return storage_message_sort_value(message)


def dashboard_stats_response(
    workspace_id: str,
    *,
    days: int = 30,
    limit: int = 300,
    tz_offset_minutes: int = 480,
) -> dict[str, Any]:
    # Dashboard 统计已迁到 web.stats；旧入口仅注入运行时依赖。
    return web_dashboard_stats_response_impl(
        workspace_id,
        days=days,
        limit=limit,
        tz_offset_minutes=tz_offset_minutes,
        app_version=APP_VERSION,
        iso_now_func=iso_now,
        workspace_file_func=workspace_file,
        load_accounts_func=load_accounts,
        load_temp_addresses_func=load_temp_addresses,
        load_generic_accounts_func=load_generic_accounts,
        load_refresh_results_func=load_refresh_results,
        load_messages_func=load_messages,
        parse_message_datetime_func=parse_message_datetime,
        normalize_mail_type_func=normalize_mail_type,
    )


REFRESH_RESULTS_LIMIT = storage_REFRESH_RESULTS_LIMIT
LOGIN_HISTORY_LIMIT = storage_LOGIN_HISTORY_LIMIT


def load_refresh_results(path: Path = REFRESH_RESULTS_FILE) -> list[dict[str, Any]]:
    # 兼容旧调用点，刷新结果读取已迁到 storage.refresh_results。
    return storage_load_refresh_results(path)


def save_refresh_results(results: list[dict[str, Any]], path: Path = REFRESH_RESULTS_FILE) -> None:
    # 兼容旧调用点，刷新结果写回已迁到 storage.refresh_results。
    return storage_save_refresh_results(results, path, limit=REFRESH_RESULTS_LIMIT)


def append_refresh_result(auth_file: dict[str, Any], email: str = "", job_id: str = "", path: Path = REFRESH_RESULTS_FILE) -> None:
    # 兼容旧调用点，刷新结果追加和去重已迁到 storage.refresh_results。
    return storage_append_refresh_result(
        auth_file,
        path=path,
        email=email,
        job_id=job_id,
        limit=REFRESH_RESULTS_LIMIT,
    )

def load_login_history(path: Path = LOGIN_HISTORY_FILE) -> list[dict[str, Any]]:
    # 兼容旧调用点，登录历史读写已经迁到 storage.login_history。
    return storage_load_login_history(path)


def save_login_history(history: list[dict[str, Any]], path: Path = LOGIN_HISTORY_FILE) -> None:
    # 兼容旧调用点，登录历史保存细节已经迁到 storage.login_history。
    return storage_save_login_history(history, path)


def append_login_history_entry(job: dict[str, Any], path: Path = LOGIN_HISTORY_FILE) -> None:
    # 兼容旧调用点，登录历史摘要落盘已经迁到 storage.login_history。
    return storage_append_login_history_entry(job, path)


def parse_account_lines(text: str) -> tuple[list[MailAccount], list[str]]:
    # 兼容旧调用点，账号导入解析已经迁到 mail.service。
    return mail_parse_account_lines(text)


def parse_temp_address_lines(text: str) -> tuple[list[TempAddress], list[str]]:
    # 兼容旧调用点，临时邮箱导入解析已经迁到 mail.service。
    return mail_parse_temp_address_lines(text)


def parse_generic_account_lines(text: str) -> tuple[list[GenericMailAccount], list[str]]:
    # 兼容旧调用点，普通邮箱导入解析已经迁到 mail.service。
    return mail_parse_generic_account_lines(text)


def looks_like_provider_token(value: Any) -> bool:
    return normalize_generic_mail_mode(value) in {"cloudmail", "luckmail", "inbucket"}


def http_json(url: str, *, method: str = "GET", data: dict[str, Any] | None = None,
              headers: dict[str, str] | None = None, timeout: int = 30) -> dict[str, Any]:
    # 兼容旧调用点，外部 HTTP 请求细节已经下沉到 infra。
    return infra_http_json(
        url,
        method=method,
        data=data,
        headers=headers,
        timeout=timeout,
        default_headers=DEFAULT_HTTP_HEADERS,
        urlopen_with_dns_retry_func=urlopen_with_dns_retry,
        cached_ip_fallback=http_json_via_cached_ip_fallback,
    )


def http_text(url: str, *, headers: dict[str, str] | None = None, timeout: int = 30) -> tuple[int, str]:
    # 兼容旧调用点，文本请求已经下沉到 infra。
    return infra_http_text(
        url,
        headers=headers,
        timeout=timeout,
        default_headers=DEFAULT_HTTP_HEADERS,
        urlopen_with_dns_retry_func=urlopen_with_dns_retry,
    )


def normalize_sms_field_name(value: str) -> str:
    # 兼容旧调用点，短信字段名规整已迁到 login.verification。
    return login_normalize_sms_field_name_impl(value)


def collect_sms_candidates(value: Any, key: str = "", depth: int = 0) -> list[dict[str, Any]]:
    # 兼容旧调用点，短信候选提取已迁到 login.verification。
    return login_collect_sms_candidates_impl(value, key=key, depth=depth)


def extract_sms_code_payload(raw_payload: Any) -> dict[str, str]:
    # 兼容旧调用点，短信验证码提取已迁到 login.verification。
    return login_extract_sms_code_payload_impl(raw_payload)


def phone_api_url(template: str, *, phone: str, account_email: str, since: str = "") -> str:
    # 兼容旧调用点，接码 URL 组装已迁到 login.verification。
    return login_phone_api_url_impl(
        template,
        phone=phone,
        account_email=account_email,
        since=since,
        validate_base_url_func=validate_remote_base_url,
        now_ts_func=time.time,
    )


def poll_phone_code(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，短信验证码查询已迁到 login.verification。
    return login_poll_phone_code_impl(
        payload,
        validate_base_url_func=validate_remote_base_url,
        http_text_func=http_text,
        now_func=iso_now,
        now_ts_func=time.time,
    )


def normalize_phone_digits(value: Any) -> str:
    # 兼容旧调用点，手机号数字规整已迁到 login.verification。
    return login_normalize_phone_digits_impl(value)


def extract_phone_hint_from_text(value: Any) -> str:
    # 兼容旧调用点，手机号提示文本提取已迁到 login.verification。
    return login_extract_phone_hint_from_text_impl(value)


def extract_phone_hint_from_step(data: Any, continue_url: str = "") -> str:
    # 兼容旧调用点，登录步骤里的手机号提示归纳已迁到 login.verification。
    return login_extract_phone_hint_from_step_impl(data, continue_url=continue_url)


def phone_pool_entries_from_payload(payload: dict[str, Any]) -> list[dict[str, str]]:
    # 兼容旧调用点，phone pool 条目规整已迁到 login.verification。
    return login_phone_pool_entries_from_payload_impl(payload)


def phone_pool_match_by_hint(entries: list[dict[str, str]], hint: str) -> dict[str, str] | None:
    # 兼容旧调用点，phone pool hint 匹配已迁到 login.verification。
    return login_phone_pool_match_by_hint_impl(entries, hint)


def manual_phone_code_for_payload(payload: dict[str, Any]) -> str:
    # 兼容旧调用点，手机验证码优先级和回看逻辑已经迁到 login.jobs。
    return login_manual_phone_code_for_payload(payload)


def set_login_manual_phone_code(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    # 兼容旧调用点，手机验证码挂载逻辑已经迁到 login.jobs。
    return login_set_login_manual_phone_code(payload, workspace_id)


def network_error_message(url: str, exc: BaseException) -> str:
    # 兼容旧调用点，真正的通用提示逻辑已经下沉到 infra。
    return infra_network_error_message(url, exc)


def is_dns_error(exc: BaseException) -> bool:
    # 兼容旧调用点，真正的 DNS 判定逻辑已经下沉到 infra。
    return infra_is_dns_error(exc)


def set_dns_fallback_cache(host: str, addresses: list[str]) -> None:
    # 兼容旧调用点，缓存写入规则已经下沉到 infra。
    return infra_set_dns_fallback_cache(DNS_FALLBACK_CACHE, host, addresses)


def cached_fallback_ips(host: str) -> list[str]:
    # 兼容旧调用点，DNS fallback 选择顺序已迁到 infra.network。
    return infra_cached_fallback_ips(
        host,
        fallback_hosts=DNS_FALLBACK_HOSTS,
        cache=DNS_FALLBACK_CACHE,
        static_fallback_ips=STATIC_DNS_FALLBACK_IPS,
        resolve_func=resolve_host_with_doh,
        set_cache_func=set_dns_fallback_cache,
    )


def resolve_host_with_doh(host: str) -> list[str]:
    # 兼容旧调用点，DoH 解析实现已迁到 infra.network。
    return infra_resolve_host_with_doh(
        host,
        fallback_hosts=DNS_FALLBACK_HOSTS,
        default_headers=DEFAULT_HTTP_HEADERS,
        connection_factory=HostHeaderHTTPSConnection,
    )


def dns_overrides_for_url(url: str) -> dict[str, list[str]]:
    # 兼容旧调用点，URL -> DNS override 装配已迁到 infra.network。
    return infra_dns_overrides_for_url(
        url,
        cached_fallback_ips_func=cached_fallback_ips,
    )


@contextlib.contextmanager
def temporary_dns_overrides(overrides: dict[str, list[str]]):
    # 兼容旧调用点，临时 DNS 覆盖的底层实现已下沉到 infra。
    with infra_temporary_dns_overrides(overrides, lock=DNS_OVERRIDE_LOCK):
        yield


def open_with_fast_dns(open_call: Any, req: urllib.request.Request, *, timeout: int = 30, use_cache: bool = True):
    # 兼容旧调用点，实际的 DNS 重试已下沉到 infra。
    return infra_open_with_fast_dns(
        open_call,
        req,
        timeout=timeout,
        use_cache=use_cache,
        dns_overrides_for_url=dns_overrides_for_url,
    )


def urlopen_with_dns_retry(req: urllib.request.Request, *, timeout: int = 30, retries: int = 1):
    # 兼容旧调用点，重试控制已下沉到 infra。
    return infra_urlopen_with_dns_retry(
        req,
        timeout=timeout,
        retries=retries,
        open_with_fast_dns_func=open_with_fast_dns,
    )


def create_ip_connection(host: str, port: int, timeout: float | None, source_address: tuple[str, int] | None = None):
    # 兼容旧调用点，直接按 IP 建连的实现已下沉到 infra。
    return infra_create_ip_connection(host, port, timeout, source_address)


HostHeaderHTTPSConnection = infra_HostHeaderHTTPSConnection
HostHeaderIMAP4SSL = infra_HostHeaderIMAP4SSL


def http_json_via_ip_fallback(url: str, *, headers: dict[str, str], timeout: int = 30) -> dict[str, Any]:
    # 兼容旧调用点，指定 host 的 IP fallback JSON 请求已迁到 infra.http。
    return infra_http_json_via_ip_fallback(
        url,
        headers=headers,
        fallback_host=TEMP_WORKER_DNS_FALLBACK_HOST,
        fallback_ips=TEMP_WORKER_DNS_FALLBACK_IPS,
        timeout=timeout,
        connection_factory=HostHeaderHTTPSConnection,
    )


def http_json_via_cached_ip_fallback(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    # 兼容旧调用点，基于缓存 IP 的 fallback JSON 请求已迁到 infra.http。
    return infra_http_json_via_cached_ip_fallback(
        url,
        method=method,
        body=body,
        headers=headers,
        timeout=timeout,
        cached_fallback_ips_func=cached_fallback_ips,
        connection_factory=HostHeaderHTTPSConnection,
    )

def mail_network_probe_hosts() -> list[tuple[str, int, str]]:
    # 兼容旧调用点，网络健康探测目标列表已经迁到 infra.network。
    return infra_mail_network_probe_hosts(TEMP_WORKER_URL)


def network_health_payload() -> dict[str, Any]:
    # 兼容旧调用点，网络健康快照已迁到 infra.network。
    return infra_network_health_payload(
        app_version=APP_VERSION,
        now=iso_now(),
        temp_worker_url=TEMP_WORKER_URL,
        dns_fallback_cache=DNS_FALLBACK_CACHE,
    )


def mail_protocol_runtime() -> mail_MailProtocolRuntime:
    # 兼容旧调用点，把 server.py 现有 HTTP / DNS 能力注入邮件协议层。
    return mail_MailProtocolRuntime(
        http_json=http_json,
        http_request_json=http_request_json,
        http_json_via_ip_fallback=http_json_via_ip_fallback,
        default_http_headers=DEFAULT_HTTP_HEADERS,
        normalize_temp_worker_url=normalize_temp_worker_url,
        urlopen_with_dns_retry=urlopen_with_dns_retry,
        network_error_message=network_error_message,
        cached_fallback_ips=cached_fallback_ips,
    )


def get_graph_token(account: MailAccount) -> str:
    # 兼容旧调用点，Graph token 交换已经迁到 mail.protocol。
    return mail_get_graph_token(account, runtime=mail_protocol_runtime())


def refresh_microsoft_access_token(
    account: MailAccount,
    attempts: list[tuple[str, dict[str, str]]],
    label: str,
) -> str:
    # 兼容旧调用点，微软 token 刷新已经迁到 mail.protocol。
    return mail_refresh_microsoft_access_token(account, attempts, label, runtime=mail_protocol_runtime())


def fetch_graph_messages(account: MailAccount, *, limit: int, sender_filter: str = "") -> list[dict[str, Any]]:
    # 兼容旧调用点，Graph 收信已经迁到 mail.protocol。
    return mail_fetch_graph_messages(account, limit=limit, sender_filter=sender_filter, runtime=mail_protocol_runtime())


def fetch_outlook_api_messages(account: MailAccount, *, limit: int, sender_filter: str = "") -> list[dict[str, Any]]:
    # 兼容旧调用点，Outlook API 收信已经迁到 mail.protocol。
    return mail_fetch_outlook_api_messages(account, limit=limit, sender_filter=sender_filter, runtime=mail_protocol_runtime())


def get_imap_token(account: MailAccount) -> tuple[str, str]:
    # 兼容旧调用点，IMAP token 交换已经迁到 mail.protocol。
    return mail_get_imap_token(account, runtime=mail_protocol_runtime())


def open_imap_ssl(server: str):
    # 兼容旧调用点，IMAP SSL 连接构造已经迁到 mail.protocol。
    return mail_open_imap_ssl(server)


def open_imap_ssl_port(server: str, port: int):
    # 兼容旧调用点，IMAP SSL 连接构造已经迁到 mail.protocol。
    return mail_open_imap_ssl_port(server, port)


def append_imap_raw_message(
    messages: list[dict[str, Any]],
    *,
    account_email: str,
    provider: str,
    folder: str,
    mid: str,
    raw: bytes,
) -> None:
    # 兼容旧调用点，IMAP/POP3 原始邮件转消息已经迁到 mail.protocol。
    return mail_append_imap_raw_message(
        messages,
        account_email=account_email,
        provider=provider,
        folder=folder,
        mid=mid,
        raw=raw,
    )


def fetch_imap_messages_with_connection(
    imap: imaplib.IMAP4_SSL,
    account: MailAccount,
    auth: str,
    limit: int,
    sender_filter: str,
) -> list[dict[str, Any]]:
    # 兼容旧调用点，IMAP 连接上的取信流程已经迁到 mail.protocol。
    return mail_fetch_imap_messages_with_connection(imap, account, auth, limit, sender_filter)


def fetch_imap_messages(account: MailAccount, *, limit: int, sender_filter: str = "") -> list[dict[str, Any]]:
    # 兼容旧调用点，微软 IMAP 收信已经迁到 mail.protocol。
    return mail_fetch_imap_messages(account, limit=limit, sender_filter=sender_filter, runtime=mail_protocol_runtime())


def fetch_generic_imap_messages(account: GenericMailAccount, *, limit: int, sender_filter: str = "") -> list[dict[str, Any]]:
    # 兼容旧调用点，普通邮箱 IMAP 收信已经迁到 mail.protocol。
    return mail_fetch_generic_imap_messages(account, limit=limit, sender_filter=sender_filter, runtime=mail_protocol_runtime())


def fetch_generic_pop3_messages(account: GenericMailAccount, *, limit: int, sender_filter: str = "") -> list[dict[str, Any]]:
    # 兼容旧调用点，普通邮箱 POP3 收信已经迁到 mail.protocol。
    return mail_fetch_generic_pop3_messages(account, limit=limit, sender_filter=sender_filter, runtime=mail_protocol_runtime())

def normalize_cloudmail_messages(payload: Any, account: GenericMailAccount, limit: int) -> list[dict[str, Any]]:
    # 兼容旧调用点，CloudMail 响应归一化已经迁到 mail.protocol。
    return mail_normalize_cloudmail_messages(payload, account, limit)


def fetch_cloudmail_messages(account: GenericMailAccount, *, limit: int, sender_filter: str = "") -> list[dict[str, Any]]:
    # 兼容旧调用点，CloudMail API 收信已经迁到 mail.protocol。
    return mail_fetch_cloudmail_messages(account, limit=limit, sender_filter=sender_filter, runtime=mail_protocol_runtime())


def normalize_luckmail_messages(payload: Any, account: GenericMailAccount, limit: int) -> list[dict[str, Any]]:
    # 兼容旧调用点，LuckMail 响应归一化已经迁到 mail.protocol。
    return mail_normalize_luckmail_messages(payload, account, limit)


def fetch_luckmail_messages(account: GenericMailAccount, *, limit: int, sender_filter: str = "") -> list[dict[str, Any]]:
    # 兼容旧调用点，LuckMail API 收信已经迁到 mail.protocol。
    return mail_fetch_luckmail_messages(account, limit=limit, sender_filter=sender_filter, runtime=mail_protocol_runtime())


def normalize_inbucket_messages(payload: Any, account: GenericMailAccount, limit: int) -> list[dict[str, Any]]:
    # 兼容旧调用点，Inbucket 响应归一化已经迁到 mail.protocol。
    return mail_normalize_inbucket_messages(payload, account, limit)


def fetch_inbucket_messages(account: GenericMailAccount, *, limit: int, sender_filter: str = "") -> list[dict[str, Any]]:
    # 兼容旧调用点，Inbucket API 收信已经迁到 mail.protocol。
    return mail_fetch_inbucket_messages(account, limit=limit, sender_filter=sender_filter, runtime=mail_protocol_runtime())


def fetch_generic_messages(account: GenericMailAccount, provider: str, *, limit: int, sender_filter: str = "") -> tuple[list[dict[str, Any]], str]:
    # 兼容旧调用点，通用邮箱 provider 分发已经迁到 mail.protocol。
    return mail_fetch_generic_messages(account, provider, limit=limit, sender_filter=sender_filter, runtime=mail_protocol_runtime())

def decode_mime_header(value: str) -> str:
    # 兼容旧调用点，MIME header 解码已经下沉到邮件域 parser。
    return mail_decode_mime_header(value)


def decode_bytes(payload: bytes, charset: str | None = None) -> str:
    # 兼容旧调用点，字节解码已经下沉到邮件域 parser。
    return mail_decode_bytes(payload, charset)


def decode_message_part(part: email_lib.message.Message) -> str:
    # 兼容旧调用点，MIME part 解码已经下沉到邮件域 parser。
    return mail_decode_message_part(part)


def extract_body_parts(msg: email_lib.message.Message) -> tuple[str, str]:
    # 兼容旧调用点，正文拆分已经下沉到邮件域 parser。
    return mail_extract_body_parts(msg)


def extract_body(msg: email_lib.message.Message) -> str:
    # 兼容旧调用点，正文抽取已经下沉到邮件域 parser。
    return mail_extract_body(msg)


def normalize_raw_email(raw: str) -> str:
    # 兼容旧调用点，原始邮件归一化已经下沉到邮件域 parser。
    return mail_normalize_raw_email(raw)


def parse_raw_email(raw: str) -> tuple[str, str, str, str, str]:
    # 兼容旧调用点，原始邮件解析已经下沉到邮件域 parser。
    return mail_parse_raw_email(raw)


def first_text(*values: Any) -> str:
    for value in values:
        text = coerce_text(value)
        if text:
            return text
    return ""


def normalize_message(**kwargs: Any) -> dict[str, Any]:
    # 兼容旧调用点，消息结构化已经下沉到邮件域 parser。
    return mail_normalize_message(
        mail_type_labels=MAIL_TYPE_LABELS,
        normalize_mail_type=normalize_mail_type,
        coerce_text=coerce_text,
        **kwargs,
    )


def normalize_mail_type(value: Any, text: str = "") -> str:
    # 兼容旧调用点，分类规则已经下沉到邮件域 classifier。
    return mail_normalize_mail_type(value, text)


def sanitize_email_html(value: str) -> str:
    # 兼容旧调用点，HTML 清洗已经下沉到邮件域 parser。
    return mail_sanitize_email_html(value)


def strip_html(text: str) -> str:
    # 兼容旧调用点，HTML 转文本已经下沉到邮件域 parser。
    return mail_strip_html(text)


def extract_links(text: str) -> list[str]:
    # 兼容旧调用点，链接提取已经下沉到邮件域 parser。
    return mail_extract_links(text)


def extract_codes(text: str) -> list[str]:
    # 兼容旧调用点，验证码提取已经下沉到邮件域 parser。
    return mail_extract_codes(text, CODE_PATTERNS)


def classify_mail(text: str) -> str:
    return normalize_mail_type("", text)



def filter_messages(messages: list[dict[str, Any]], payload: dict[str, Any]) -> list[dict[str, Any]]:
    # 兼容旧调用点，消息筛选规则已经迁到 mail.service。
    return mail_filter_messages(messages, payload)


def temp_headers(address: TempAddress) -> dict[str, str]:
    # 兼容旧调用点，临时邮箱请求头已经迁到 mail.protocol。
    return mail_temp_headers(address, runtime=mail_protocol_runtime())


def fetch_temp_messages(address: TempAddress, *, limit: int, sender_filter: str = "") -> list[dict[str, Any]]:
    # 兼容旧调用点，临时邮箱取信已经迁到 mail.protocol。
    return mail_fetch_temp_messages(address, limit=limit, sender_filter=sender_filter, runtime=mail_protocol_runtime())


def classify_mail_fetch_error(raw: str, source: str = "") -> dict[str, Any]:
    # 兼容旧调用点，取信错误分类已经迁到 mail.protocol。
    return mail_classify_mail_fetch_error(raw, source)


def apply_mail_fetch_result_fields(target: MailAccount | TempAddress | GenericMailAccount, result: dict[str, Any]) -> None:
    # 兼容旧调用点，取信结果状态回写已经迁到 mail.protocol。
    return mail_apply_mail_fetch_result_fields(target, result)


def mail_fetch_error_result(kind: str, target: MailAccount | TempAddress | GenericMailAccount, message: str, *, elapsed_ms: int = 0) -> dict[str, Any]:
    # 兼容旧调用点，取信失败结果构造已经迁到 mail.protocol。
    return mail_mail_fetch_error_result(kind, target, message, elapsed_ms=elapsed_ms)


def microsoft_provider_sequence(provider: str) -> list[str]:
    # 兼容旧调用点，微软取信 provider 顺序已经迁到 mail.protocol。
    return mail_microsoft_provider_sequence(provider)


def fetch_for_account(account: MailAccount, provider: str, limit: int, sender_filter: str) -> dict[str, Any]:
    # 兼容旧调用点，微软邮箱单账号取信汇总已经迁到 mail.protocol。
    return mail_fetch_for_account(account, provider, limit, sender_filter, runtime=mail_protocol_runtime())


def fetch_for_temp_address(address: TempAddress, limit: int, sender_filter: str) -> dict[str, Any]:
    # 兼容旧调用点，临时邮箱单账号取信汇总已经迁到 mail.protocol。
    return mail_fetch_for_temp_address(address, limit, sender_filter, runtime=mail_protocol_runtime())


def fetch_for_generic_account(account: GenericMailAccount, provider: str, limit: int, sender_filter: str) -> dict[str, Any]:
    # 兼容旧调用点，通用邮箱单账号取信汇总已经迁到 mail.protocol。
    return mail_fetch_for_generic_account(account, provider, limit, sender_filter, runtime=mail_protocol_runtime())


def run_mail_fetch_jobs(
    jobs: list[tuple[str, MailAccount | TempAddress | GenericMailAccount, str, int, str]],
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    # 兼容旧调用点，多账号取信任务执行已经迁到 mail.protocol。
    return mail_run_mail_fetch_jobs(
        jobs,
        max_workers=MAIL_FETCH_MAX_CONCURRENCY,
        runtime=mail_protocol_runtime(),
        progress_callback=progress_callback,
    )

def coerce_text(value: Any) -> str:
    return str(value or "").strip()


def parse_nested_json_value(value: Any, depth: int = 4) -> Any:
    # 兼容旧调用点，嵌套 JSON 解析已迁到 cpa.service。
    return cpa_parse_nested_json_value_impl(value, depth)


def collect_nested_error_texts(value: Any, texts: list[str] | None = None, depth: int = 0) -> list[str]:
    # 兼容旧调用点，嵌套错误文本收集已迁到 cpa.service。
    return cpa_collect_nested_error_texts_impl(value, texts, depth)


def compact_raw_status(value: Any) -> str:
    # 兼容旧调用点，原始状态压缩已迁到 cpa.service。
    return cpa_compact_raw_status_impl(value)


def cpa_status_message(value: Any, status_code: Any = None, action: str = "") -> tuple[str, str]:
    # 兼容旧调用点，CPA 错误文案归并已迁到 cpa.service。
    return cpa_status_message_impl(value, status_code=status_code, action=action)


def is_private_host(hostname: str) -> bool:
    # 兼容旧调用点，私网/本地地址判定已迁到 infra。
    return infra_is_private_host(hostname)


def is_loopback_host(hostname: str) -> bool:
    # 兼容旧调用点，loopback 地址判定已迁到 infra。
    return infra_is_loopback_host(hostname)


def validate_remote_base_url(base_url: str) -> None:
    # 兼容旧调用点，远程 base_url 校验已迁到 infra。
    return infra_validate_remote_base_url(base_url, allow_private_urls=ALLOW_PRIVATE_URLS)


def validate_configured_base_url(base_url: str) -> None:
    # 兼容旧调用点，配置型 temp worker 地址校验继续复用 infra 的协议/主机名规则。
    return infra_validate_remote_base_url(base_url, allow_private_urls=True, scheme_error="configured temp worker URL must use http or https", host_error="configured temp worker URL host missing")


def validate_cpa_base_url(base_url: str) -> None:
    # 兼容旧调用点，CPA 地址校验已迁到 app.cpa_runtime。
    return COMPAT_CPA_SUPPORT.validate_cpa_base_url(base_url)


def normalize_proxy_url(value: str) -> str:
    # 兼容旧调用点，代理格式校验已经下沉到 infra。
    return infra_normalize_proxy_url(value)


def sticky_proxy_url(proxy_url: str, job_id: str = "") -> str:
    # 兼容旧调用点，代理会话粘性已经下沉到 infra。
    return infra_sticky_proxy_url(proxy_url, job_id)


def socks_dependency_error() -> RuntimeError:
    # 兼容旧调用点，依赖缺失提示已经下沉到 infra。
    return infra_socks_dependency_error()


def request_proxy_url(payload: dict[str, Any] | None = None) -> str:
    # 兼容旧调用点，代理选择规则已经下沉到 infra。
    return infra_request_proxy_url(payload)


def require_login_proxy_url(payload: dict[str, Any]) -> str:
    # 兼容旧调用点，登录代理强制规则已经下沉到 infra。
    return infra_require_login_proxy_url(payload)


def proxy_opener(proxy_url: str) -> urllib.request.OpenerDirector:
    # 兼容旧调用点，urllib opener 构造已经下沉到 infra。
    return infra_proxy_opener(proxy_url)


def playwright_proxy_options(proxy_url: str) -> dict[str, str]:
    # 兼容旧调用点，Playwright 代理转换已经下沉到 infra。
    return infra_playwright_proxy_options(proxy_url)


@contextlib.contextmanager
def temporary_socket_proxy(proxy_url: str):
    # 兼容旧调用点，socket 代理上下文已经下沉到 infra。
    with infra_temporary_socket_proxy(proxy_url):
        yield


def http_request_json(
    url: str,
    *,
    method: str = "GET",
    json_data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    proxy_url: str = "",
) -> dict[str, Any]:
    # 兼容旧调用点，JSON 请求已经下沉到 infra。
    return infra_http_request_json(
        url,
        method=method,
        json_data=json_data,
        headers=headers,
        timeout=timeout,
        proxy_url=proxy_url,
        default_headers=DEFAULT_HTTP_HEADERS,
        open_with_fast_dns_func=open_with_fast_dns,
    )


def probe_egress_trace(proxy_url: str = "") -> dict[str, str]:
    # 兼容旧调用点，代理出口探测已经下沉到 infra。
    return infra_probe_egress_trace(
        proxy_url,
        default_headers=DEFAULT_HTTP_HEADERS,
        open_with_fast_dns_func=open_with_fast_dns,
    )


def check_proxy_egress(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，出口检测已经下沉到 infra。
    return infra_check_proxy_egress(
        payload,
        default_headers=DEFAULT_HTTP_HEADERS,
        open_with_fast_dns_func=open_with_fast_dns,
    )


def http_request_form_json(
    url: str,
    *,
    method: str = "POST",
    form_data: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    proxy_url: str = "",
) -> tuple[int, dict[str, Any], str]:
    # 兼容旧调用点，表单请求已经下沉到 infra。
    return infra_http_request_form_json(
        url,
        method=method,
        form_data=form_data,
        headers=headers,
        timeout=timeout,
        proxy_url=proxy_url,
        default_headers=DEFAULT_HTTP_HEADERS,
        open_with_fast_dns_func=open_with_fast_dns,
    )


def http_get_json_status(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    proxy_url: str = "",
) -> tuple[int, dict[str, Any], str]:
    # 兼容旧调用点，GET 状态请求已经下沉到 infra。
    return infra_http_get_json_status(
        url,
        headers=headers,
        timeout=timeout,
        proxy_url=proxy_url,
        default_headers=DEFAULT_HTTP_HEADERS,
        open_with_fast_dns_func=open_with_fast_dns,
    )


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


LoginFlowError = login_LoginFlowError


def openai_turnstile_error(hint: str = "") -> LoginFlowError:
    # 兼容旧调用点，登录人机验证失败语义已经迁到 login.errors。
    return login_openai_turnstile_error(hint)


def classify_login_exception(exc: Exception) -> dict[str, Any]:
    # 兼容旧调用点，登录异常归类已迁到 login.errors，并由 login.api 注入协议摘要 helper。
    return login_classify_login_exception_impl(exc)


class ChatGPTProtocolLogin(login_ChatGPTProtocolLogin_impl):
    """兼容旧脚本类名，真实协议状态机已下沉到登录域。"""

    def __init__(self, job_id: str, payload: dict[str, Any]):
        super().__init__(job_id, payload, runtime=protocol_login_runtime())


def protocol_login_runtime() -> login_ProtocolLoginRuntime_impl:
    """装配协议登录运行时依赖，避免登录域反向引用 server.py。"""
    return COMPAT_LOGIN_SUPPORT.protocol_login_runtime()


def generate_openai_sentinel_token(device_id: str, flow: str, proxy_url: str = "") -> str:
    return login_generate_openai_sentinel_token_impl(
        device_id,
        flow,
        proxy_url,
        node_bin=LOGIN_NODE_BIN,
        helper_path=OPENAI_SENTINEL_HELPER,
        environ=os.environ,
    )


def run_chatgpt_login_with_protocol(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    return COMPAT_LOGIN_SUPPORT.run_chatgpt_login_with_protocol(job_id, payload)


def cpa_management_config(payload: dict[str, Any]) -> tuple[str, str]:
    # 兼容旧调用点，CPA 管理配置收敛已迁到 app.cpa_runtime。
    return COMPAT_CPA_SUPPORT.cpa_management_config(payload)


def cpa_direct_oauth_start(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA OAuth 起始请求已迁到 app.cpa_runtime。
    return COMPAT_CPA_SUPPORT.cpa_direct_oauth_start(payload)


def parse_localhost_oauth_callback(callback_url: str, expected_state: str = "") -> dict[str, str]:
    # 兼容旧调用点，localhost OAuth 回调解析已迁到 login.local_oauth。
    return login_parse_localhost_oauth_callback_impl(callback_url, expected_state)


def cpa_direct_oauth_callback(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA OAuth 回调转发已迁到 app.cpa_runtime。
    return COMPAT_CPA_SUPPORT.cpa_direct_oauth_callback(payload)


def cpa_item_chatgpt_account_id(item: dict[str, Any]) -> str:
    # 兼容旧调用点，ChatGPT 账号 ID 提取已经迁到 cpa.service。
    return cpa_item_chatgpt_account_id_impl(item)


def cpa_headers(management_key: str) -> dict[str, str]:
    # 兼容旧调用点，CPA 管理接口请求头已迁到 cpa.service。
    return cpa_headers_impl(management_key)


def cpa_item_type(item: dict[str, Any]) -> str:
    # 兼容旧调用点，CPA 条目类型判断已迁到 cpa.service。
    return cpa_item_type_impl(item)


def looks_like_openai_auth_file(item: dict[str, Any], auth_file: dict[str, Any] | None = None) -> bool:
    # 兼容旧调用点，auth 文件类型识别已迁到 cpa.service。
    return cpa_looks_like_openai_auth_file_impl(item, auth_file)


def infer_auth_email(item: dict[str, Any], auth_file: dict[str, Any] | None = None) -> str:
    # 兼容旧调用点，auth 邮箱推断已迁到 cpa.service。
    return cpa_infer_auth_email_impl(item, auth_file)


def extract_state_from_auth_url(auth_url: str) -> str:
    # 兼容旧调用点，OAuth state 提取已迁到 cpa.service。
    return cpa_extract_state_from_auth_url_impl(auth_url)


def cpa_oauth_value(payload: dict[str, Any], *keys: str) -> str:
    # 兼容旧调用点，OAuth 字段读取已迁到 cpa.service。
    return cpa_oauth_value_impl(payload, *keys)


def cpa_list_auth_files(base_url: str, management_key: str) -> list[dict[str, Any]]:
    # 兼容旧调用点，CPA auth 文件列表请求已迁到 cpa.management。
    return cpa_list_auth_files_impl(base_url, management_key)


def cpa_download_auth_file(base_url: str, management_key: str, name: str) -> dict[str, Any]:
    # 兼容旧调用点，CPA auth 文件下载已迁到 cpa.management。
    return cpa_download_auth_file_impl(base_url, management_key, name)


def cpa_probe_payload(item: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA 探测 payload 已迁到 app.cpa_runtime。
    return COMPAT_CPA_SUPPORT.cpa_probe_payload(item)


def cpa_probe_status(base_url: str, management_key: str, item: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA 条目探测已迁到 cpa.management。
    return cpa_probe_status_impl(base_url, management_key, item)


def cpa_is_401_item(item: dict[str, Any]) -> bool:
    # 兼容旧调用点，401 失效项判断已迁到 cpa.service。
    return cpa_is_401_item_impl(item)


def cpa_delete_auth_file(base_url: str, management_key: str, name: str) -> dict[str, Any]:
    # 兼容旧调用点，CPA auth 删除已迁到 cpa.management。
    return cpa_delete_auth_file_impl(base_url, management_key, name)


def cpa_auth_filename(value: str, auth_file: dict[str, Any]) -> str:
    # 兼容旧调用点，auth 文件名规整已迁到 cpa.service。
    return cpa_auth_filename_impl(value, auth_file)


def cpa_upload_auth_file(base_url: str, management_key: str, name: str, auth_file: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA auth 上传已迁到 cpa.management。
    return cpa_upload_auth_file_impl(base_url, management_key, name, auth_file)


def cpa_candidates(payload: dict[str, Any]) -> tuple[str, str, int, list[dict[str, Any]], int]:
    # 兼容旧调用点，CPA 候选条目收敛已迁到 app.cpa_runtime。
    return COMPAT_CPA_SUPPORT.cpa_candidates(payload)


def cpa_diagnosis_action_hint(status: str) -> str:
    # 兼容旧调用点，CPA 诊断文案映射已迁到 cpa.diagnostics。
    return cpa_diagnosis_action_hint_impl(status)


def cpa_status_refreshable(status: str) -> bool:
    # 兼容旧调用点，CPA 可回刷状态判断已迁到 cpa.diagnostics。
    return cpa_status_refreshable_impl(status)


def diagnose_cpa_candidate(base_url: str, management_key: str, item: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA 单条诊断编排已迁到 cpa.diagnostics。
    return cpa_diagnose_cpa_candidate_impl(
        base_url,
        management_key,
        item,
        refresh_candidate=refresh_lifecycle_item,
        status_label_func=lifecycle_status_label,
    )

def scan_cpa_401(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA 401 扫描编排已迁到 app.login_runtime。
    return COMPAT_LOGIN_SUPPORT.scan_cpa_401(payload)


def repair_cpa_401(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA 401 修复编排已迁到 app.login_runtime。
    return COMPAT_LOGIN_SUPPORT.repair_cpa_401(payload)


def delete_cpa_items(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA 批量删除已迁到 app.cpa_runtime。
    return COMPAT_CPA_SUPPORT.delete_cpa_items(payload)


def build_cpa_repair_login_payload(base_payload: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA 修复登录 payload 组装已迁到 cpa.service。
    return cpa_build_cpa_repair_login_payload(base_payload, row)


def replace_cpa_auth_file(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA auth 替换已迁到 app.cpa_runtime。
    return COMPAT_CPA_SUPPORT.replace_cpa_auth_file(payload)


def normal_plan_type(value: str) -> str:
    # 兼容旧调用点，计划类型规整已迁到 login.oauth。
    return login_normal_plan_type_impl(value)


def access_token_email(token: str) -> str:
    # 兼容旧调用点，access token 邮箱提取已迁到 login.oauth。
    return login_access_token_email_impl(token)


def access_token_plan_type(token: str) -> str:
    # 兼容旧调用点，access token 计划类型提取已迁到 login.oauth。
    return login_access_token_plan_type_impl(token)


def access_token_expires_at(token: str) -> str:
    # 兼容旧调用点，access token 过期时间提取已迁到 login.oauth。
    return login_access_token_expires_at_impl(token)


def openai_error_fields(data: dict[str, Any], raw: str) -> dict[str, Any]:
    # 兼容旧调用点，OpenAI 错误字段整形已迁到 login.service。
    return login_openai_error_fields_impl(data, raw)


def usage_limit_message(fields: dict[str, Any]) -> str:
    # 兼容旧调用点，额度耗尽提示文案已迁到 login.service。
    return login_usage_limit_message_impl(fields)


def refresh_openai_with_rt(refresh_token: str) -> tuple[int, dict[str, Any], str]:
    # 兼容旧调用点，refresh_token 刷新 helper 已迁到 login.service。
    return login_refresh_openai_with_rt_impl(
        refresh_token,
        token_url=OPENAI_OAUTH_TOKEN_URL,
        client_id=OPENAI_CODEX_CLIENT_ID,
        refresh_scope=OPENAI_OAUTH_REFRESH_SCOPE,
        http_request_form_json_func=http_request_form_json,
    )


def oauth_base64url(data: bytes) -> str:
    # 兼容旧调用点，OAuth base64url 编码已迁到 login.oauth_flow。
    return login_oauth_base64url_impl(data)


def generate_openai_code_verifier() -> str:
    # 兼容旧调用点，OpenAI code_verifier 生成已迁到 login.oauth_flow。
    return login_generate_openai_code_verifier_impl()


def openai_code_challenge(code_verifier: str) -> str:
    # 兼容旧调用点，OpenAI PKCE challenge 生成已迁到 login.oauth_flow。
    return login_openai_code_challenge_impl(code_verifier)


def build_openai_oauth_authorize_url(state: str, code_challenge: str) -> str:
    # 兼容旧调用点，OpenAI 授权链接拼装已迁到 login.oauth_flow。
    return login_build_openai_oauth_authorize_url_impl(
        state,
        code_challenge,
        client_id=OPENAI_CODEX_CLIENT_ID,
        redirect_uri=OPENAI_OAUTH_REDIRECT_URI,
        scope=OPENAI_OAUTH_SCOPE,
        authorize_base_url=OPENAI_OAUTH_AUTHORIZE_URL,
    )


def build_chatgpt_login_url(email_addr: str = "") -> str:
    # 兼容旧调用点，ChatGPT 登录 URL 拼装已迁到 login.oauth_flow。
    return login_build_chatgpt_login_url_impl(email_addr, login_url=CHATGPT_LOGIN_URL)


def complete_oauth_code_payload(payload: dict[str, Any], code: str, code_verifier: str) -> dict[str, Any]:
    # 兼容旧调用点，OAuth code -> CPA auth 的跨域编排已迁到 app.facade。
    return app_complete_oauth_code_payload_impl(
        payload,
        code,
        code_verifier,
        request_proxy_url_func=request_proxy_url,
        exchange_openai_oauth_code_func=exchange_openai_oauth_code,
        protocol_compact_error_func=login_protocol_compact_error_impl,
        session_to_cpa_auth_func=session_to_cpa_auth,
        append_refresh_result_func=append_refresh_result,
        replace_cpa_auth_file_func=replace_cpa_auth_file,
    )


def create_local_oauth_flow(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，本机 OAuth 流程状态和 callback server 已迁到 login.local_oauth。
    return login_create_local_oauth_flow_impl(
        payload,
        now_func=iso_now,
        complete_oauth_code_payload_func=complete_oauth_code_payload,
        build_authorize_url_func=lambda state, code_verifier: build_openai_oauth_authorize_url(
            state,
            openai_code_challenge(code_verifier),
        ),
        redirect_uri=OPENAI_OAUTH_REDIRECT_URI,
    )


def get_local_oauth_flow(state: str) -> dict[str, Any]:
    # 兼容旧调用点，本机 OAuth 流程查询已迁到 login.local_oauth。
    return login_get_local_oauth_flow_impl(state)


def handle_local_oauth_callback(path: str) -> tuple[int, str]:
    # 兼容旧调用点，本机 OAuth 回调处理已迁到 login.local_oauth。
    return login_handle_local_oauth_callback_impl(path)


LocalOAuthCallbackHandler = login_LocalOAuthCallbackHandler


def start_local_oauth_callback_server() -> None:
    # 兼容旧调用点，本机 OAuth callback server 已迁到 login.local_oauth。
    return login_start_local_oauth_callback_server_impl(
        now_func=iso_now,
        complete_oauth_code_payload_func=complete_oauth_code_payload,
    )


def exchange_openai_oauth_code(
    code: str,
    code_verifier: str,
    *,
    proxy_url: str = "",
) -> tuple[int, dict[str, Any], str]:
    # 兼容旧调用点，OAuth code 兑换 helper 已迁到 login.service。
    return login_exchange_openai_oauth_code_impl(
        code,
        code_verifier,
        token_url=OPENAI_OAUTH_TOKEN_URL,
        client_id=OPENAI_CODEX_CLIENT_ID,
        redirect_uri=OPENAI_OAUTH_REDIRECT_URI,
        user_agent=CPA_PROBE_USER_AGENT,
        proxy_url=proxy_url,
        http_request_form_json_func=http_request_form_json,
    )


def refresh_openai_with_session_token(session_token: str) -> tuple[int, dict[str, Any], str]:
    # 兼容旧调用点，session_token 刷新 helper 已迁到 login.service。
    return login_refresh_openai_with_session_token_impl(
        session_token,
        session_url=CHATGPT_SESSION_URL,
        http_get_json_status_func=http_get_json_status,
    )


def probe_openai_access_token(access_token: str) -> dict[str, Any]:
    # 兼容旧调用点，access_token 探测 helper 已迁到 login.service。
    return login_probe_openai_access_token_impl(
        access_token,
        check_url=CHATGPT_CHECK_URL,
        http_get_json_status_func=http_get_json_status,
    )


def lifecycle_status_label(status: str) -> str:
    # 兼容旧调用点，生命周期状态标签已迁到 login.service。
    return login_lifecycle_status_label_impl(status)


def classify_oauth_error(status: int, data: dict[str, Any], raw: str) -> tuple[str, str]:
    # 兼容旧调用点，OAuth 错误归类已迁到 login.oauth。
    return login_classify_oauth_error_impl(status, data, raw)


def lifecycle_source_auth(source: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，生命周期 auth 入口规整已迁到 login.service。
    return login_lifecycle_source_auth_impl(source)


def normalize_lifecycle_item(item: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，生命周期候选规整已迁到 login.service。
    return login_normalize_lifecycle_item_impl(item)


def refresh_lifecycle_item(item: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，生命周期刷新主流程已迁到 app.login_runtime。
    return COMPAT_LOGIN_SUPPORT.refresh_lifecycle_item(item)


def lifecycle_summary(results: list[dict[str, Any]], uploaded: int = 0) -> dict[str, Any]:
    # 兼容旧调用点，生命周期汇总已迁到 login.service。
    return login_lifecycle_summary_impl(results, uploaded=uploaded)


def refresh_lifecycle(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，生命周期批量包装已迁到 app.login_runtime。
    return COMPAT_LOGIN_SUPPORT.refresh_lifecycle(payload)


def refresh_cpa_lifecycle(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA 生命周期批量编排已迁到 app.login_runtime。
    return COMPAT_LOGIN_SUPPORT.refresh_cpa_lifecycle(payload)


def login_job_public(job: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，登录任务公开视图已经迁到 login.jobs。
    return login_login_job_public(job)


def append_login_log(job_id: str, message: str, level: str = "info", step: str = "") -> None:
    # 兼容旧调用点，登录日志写入已经迁到 login.jobs。
    return login_append_login_log(job_id, message, level, step)


def set_login_job_status(job_id: str, status: str, **updates: Any) -> None:
    # 兼容旧调用点，登录任务状态流转已经迁到 login.jobs。
    return login_set_login_job_status(job_id, status, **updates)


def login_job_cancel_requested(job_id: str) -> bool:
    # 兼容旧调用点，登录取消标记检查已经迁到 login.jobs。
    return login_login_job_cancel_requested(job_id)


def raise_if_login_job_cancelled(job_id: str) -> None:
    # 兼容旧调用点，登录取消中断逻辑已经迁到 login.jobs。
    return login_raise_if_login_job_cancelled(job_id)


def cancel_login_job(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    # 兼容旧调用点，登录任务取消接口已经迁到 login.jobs。
    return login_cancel_login_job(payload, workspace_id)


def clean_manual_email_code(value: Any) -> str:
    # 兼容旧调用点，验证码清洗逻辑已经迁到 login.jobs。
    return login_clean_manual_email_code(value)


def manual_email_code_for_payload(payload: dict[str, Any]) -> str:
    # 兼容旧调用点，邮箱验证码优先级和回看逻辑已经迁到 login.jobs。
    return login_manual_email_code_for_payload(payload)


def set_login_manual_email_code(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    # 兼容旧调用点，邮箱验证码挂载逻辑已经迁到 login.jobs。
    return login_set_login_manual_email_code(payload, workspace_id)


def message_six_digit_codes(message: dict[str, Any]) -> list[str]:
    # 兼容旧调用点，邮件验证码提取已经迁到 login.verification。
    return login_message_six_digit_codes_impl(message)


def count_six_digit_codes(messages: list[dict[str, Any]]) -> int:
    # 兼容旧调用点，邮件验证码计数已经迁到 login.verification。
    return login_count_six_digit_codes_impl(messages)


def find_latest_code(messages: list[dict[str, Any]], *, after_ts: float = 0, skew_seconds: int = 30) -> str:
    # 兼容旧调用点，最新验证码定位已经迁到 login.verification。
    return login_find_latest_code_impl(messages, after_ts=after_ts, skew_seconds=skew_seconds)


def fetch_login_verification_code(payload: dict[str, Any], *, since: float = 0, attempts: int = 12, delay: float = 5) -> str:
    # 兼容旧调用点，邮件验证码轮询已经迁到 login.verification。
    return login_fetch_login_verification_code_impl(
        payload,
        since=since,
        attempts=attempts,
        delay=delay,
        fetch_mail_func=mail_fetch_transient_client,
    )


def cpa_companion_wait_code(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，CPA Companion 验证码等待已迁到 cpa.service。
    return cpa_companion_wait_code_impl(
        payload,
        fetch_code_func=fetch_login_verification_code,
    )


def session_to_cpa_auth(
    session: dict[str, Any],
    fallback: dict[str, Any] | None = None,
    *,
    require_refresh_token: bool = False,
) -> dict[str, Any]:
    # 兼容旧调用点，ChatGPT session -> CPA auth 的跨域转换已迁到 app.facade。
    return app_session_to_cpa_auth_impl(
        session,
        fallback,
        require_refresh_token=require_refresh_token,
    )


def jwt_payload(token: str) -> dict[str, Any]:
    # 兼容旧调用点，JWT payload 解析已迁到 login.oauth。
    return login_jwt_payload_impl(token)


def build_synthetic_id_token(email_addr: str, account_id: str, plan_type: str, expires_at: str) -> str:
    # 兼容旧调用点，synthetic id_token 生成已迁到 login.oauth。
    return login_build_synthetic_id_token_impl(email_addr, account_id, plan_type, expires_at)


def run_chatgpt_login_with_playwright(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，Playwright 外层队列和依赖导入已迁到 login.playwright。
    return login_run_chatgpt_login_with_playwright_impl(
        job_id,
        payload,
        playwright_semaphore=PLAYWRIGHT_SEMAPHORE,
        playwright_max_concurrency=PLAYWRIGHT_MAX_CONCURRENCY,
        request_proxy_url_func=request_proxy_url,
        append_login_log_func=append_login_log,
        unlocked_login_func=run_chatgpt_login_with_playwright_unlocked,
    )

def run_chatgpt_login_with_playwright_unlocked(
    job_id: str,
    payload: dict[str, Any],
    sync_playwright: Any,
    PlaywrightTimeoutError: Any,
    *,
    email_addr: str,
    headless: bool,
    proxy_url: str,
    code_since: float,
) -> dict[str, Any]:
    # Playwright 主登录流程已迁到 login.playwright；旧入口只负责注入运行时依赖。
    return login_run_chatgpt_login_with_playwright_unlocked_impl(
        job_id,
        payload,
        sync_playwright,
        PlaywrightTimeoutError,
        email_addr=email_addr,
        headless=headless,
        proxy_url=proxy_url,
        code_since=code_since,
        build_chatgpt_login_url_func=build_chatgpt_login_url,
        generate_openai_code_verifier_func=generate_openai_code_verifier,
        build_openai_oauth_authorize_url_func=build_openai_oauth_authorize_url,
        openai_code_challenge_func=openai_code_challenge,
        playwright_proxy_options_func=playwright_proxy_options,
        append_login_log_func=append_login_log,
        append_login_snapshot_log_func=append_login_snapshot_log,
        fetch_login_verification_code_func=fetch_login_verification_code,
        fetch_openai_oauth_from_captured_code_func=fetch_openai_oauth_from_captured_code,
        read_playwright_session_func=read_playwright_session,
        merge_session_with_oauth_func=merge_session_with_oauth,
        first_text_func=first_text,
        redirect_uri=OPENAI_OAUTH_REDIRECT_URI,
    )


def first_visible_selector(page: Any, selectors: list[str], *, timeout: int = 30000) -> str:
    # 兼容旧调用点，Playwright 首个可见输入框查找已迁到 login.playwright。
    return login_first_visible_selector_impl(page, selectors, timeout=timeout)


def optional_visible_selector(page: Any, selectors: list[str], *, timeout: int = 30000) -> str:
    # 兼容旧调用点，可选 Playwright 可见输入框查找已迁到 login.playwright。
    return login_optional_visible_selector_impl(page, selectors, timeout=timeout)


def playwright_page_hint(page: Any) -> str:
    # 兼容旧调用点，Playwright 页面提示提取已迁到 login.playwright。
    return login_playwright_page_hint_impl(page)


def login_page_snapshot(page: Any) -> dict[str, Any]:
    # 兼容旧调用点，登录页状态采集已迁到 login.playwright。
    return login_login_page_snapshot_impl(page)


def save_login_debug_snapshot(page: Any, job_id: str, label: str) -> dict[str, str]:
    # 兼容旧调用点，Playwright 登录页调试快照已迁到 login.playwright。
    return login_save_login_debug_snapshot_impl(
        page,
        job_id,
        label,
        login_debug_dir=LOGIN_DEBUG_DIR,
        page_snapshot_func=login_page_snapshot,
    )


def append_login_snapshot_log(job_id: str, page: Any, label: str, level: str = "info") -> None:
    # 兼容旧调用点，页面快照日志归档已迁到 login.playwright。
    return login_append_login_snapshot_log_impl(
        job_id,
        page,
        label,
        level,
        login_debug_dir=LOGIN_DEBUG_DIR,
        login_jobs=LOGIN_JOBS,
        login_jobs_lock=LOGIN_JOBS_LOCK,
        append_login_log_func=append_login_log,
    )


def is_openai_security_verification_text(value: str) -> bool:
    # 兼容旧调用点，人机验证提示识别已迁到 login.playwright。
    return login_is_openai_security_verification_text_impl(value)


def openai_security_verification_message(hint: str) -> str:
    raise openai_turnstile_error(hint)


def wait_for_openai_login_ready(
    page: Any,
    selectors: list[str],
    *,
    timeout: int = 90000,
    job_id: str = "",
) -> None:
    # 兼容旧调用点，登录页就绪等待逻辑已迁到 login.playwright，日志和快照仍通过回调注入。
    return login_wait_for_openai_login_ready_impl(
        page,
        selectors,
        timeout=timeout,
        job_id=job_id,
        append_log_func=append_login_log,
        append_snapshot_log_func=append_login_snapshot_log,
    )


def fill_login_code(page: Any, selector: str, code: str) -> None:
    # 兼容旧调用点，Playwright 验证码填写已迁到 login.playwright。
    return login_fill_login_code_impl(page, selector, code)


def wait_for_chatgpt_logged_in(page: Any, *, timeout: int = 90000) -> bool:
    # 兼容旧调用点，ChatGPT 已登录等待判断已迁到 login.playwright。
    return login_wait_for_chatgpt_logged_in_impl(page, timeout=timeout)


def build_playwright_login_url() -> str:
    # 兼容旧调用点，Playwright 登录入口 URL 已迁到 login.playwright。
    return login_build_playwright_login_url_impl(login_url=CHATGPT_LOGIN_URL)


def raise_if_playwright_auth_blocked(page: Any) -> None:
    # 兼容旧调用点，Playwright 风控/挑战页判断已迁到 login.playwright。
    return login_raise_if_playwright_auth_blocked_impl(page)


def read_playwright_session(context: Any) -> dict[str, Any]:
    # 兼容旧调用点，Playwright session 读取已迁到 login.playwright。
    return login_read_playwright_session_impl(
        context,
        session_url="https://chatgpt.com/api/auth/session",
        html_challenge_hint_func=login_html_challenge_hint_impl,
        strip_html_func=strip_html,
        first_text_func=first_text,
    )


def fetch_openai_oauth_with_playwright(page: Any, *, proxy_url: str = "") -> dict[str, Any]:
    # 兼容旧调用点，已登录页内的 OAuth code 监听和 token 兑换已迁到 login.playwright。
    return login_fetch_openai_oauth_with_playwright_impl(
        page,
        proxy_url=proxy_url,
        generate_openai_code_verifier_func=generate_openai_code_verifier,
        build_openai_oauth_authorize_url_func=build_openai_oauth_authorize_url,
        openai_code_challenge_func=openai_code_challenge,
        exchange_openai_oauth_code_func=exchange_openai_oauth_code,
        protocol_compact_error_func=login_protocol_compact_error_impl,
    )


def fetch_openai_oauth_from_captured_code(
    captured: dict[str, str],
    code_verifier: str,
    page: Any,
    *,
    proxy_url: str = "",
) -> dict[str, Any]:
    # 兼容旧调用点，Playwright OAuth code 轮询和 token 兑换已迁到 login.playwright。
    return login_fetch_openai_oauth_from_captured_code_impl(
        captured,
        code_verifier,
        page,
        proxy_url=proxy_url,
        exchange_openai_oauth_code_func=exchange_openai_oauth_code,
        protocol_compact_error_func=login_protocol_compact_error_impl,
    )


def merge_session_with_oauth(session: dict[str, Any], oauth_payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，session 与 OAuth token 的合并规则已迁到 login.service。
    return login_merge_session_with_oauth_impl(session, oauth_payload)


def click_first_available(page: Any, selectors: list[str], *, fallback_enter: bool = True) -> bool:
    # 兼容旧调用点，Playwright 首个可用按钮点击已迁到 login.playwright。
    return login_click_first_available_impl(page, selectors, fallback_enter=fallback_enter)


def wait_and_click_first_available(page: Any, selectors: list[str], *, timeout: int = 10000, fallback_enter: bool = False) -> bool:
    # 兼容旧调用点，Playwright 等待后点击动作已迁到 login.playwright。
    return login_wait_and_click_first_available_impl(
        page,
        selectors,
        timeout=timeout,
        fallback_enter=fallback_enter,
    )


def fetch_registration_verification_link(payload: dict[str, Any], *, since: float = 0, attempts: int = 15, delay: float = 6) -> str:
    # 兼容旧调用点，注册验证链接提取已迁到 login.verification。
    return login_fetch_registration_verification_link_impl(
        payload,
        since=since,
        attempts=attempts,
        delay=delay,
        fetch_transient_client_mail_func=fetch_transient_client_mail,
    )


def run_chatgpt_signup_with_playwright(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点；Playwright 注册入口和依赖导入已迁到 login.playwright。
    return login_run_chatgpt_signup_with_playwright_impl(
        job_id,
        payload,
        request_proxy_url_func=request_proxy_url,
        user_agent=DEFAULT_HTTP_HEADERS["User-Agent"],
        playwright_proxy_options_func=playwright_proxy_options,
        append_login_log_func=append_login_log,
        fetch_registration_verification_link_func=fetch_registration_verification_link,
        fetch_openai_oauth_with_playwright_func=fetch_openai_oauth_with_playwright,
        merge_session_with_oauth_func=merge_session_with_oauth,
    )


def run_cpa_login_job(job_id: str, payload: dict[str, Any]) -> None:
    COMPAT_LOGIN_SUPPORT.run_cpa_login_job(job_id, payload)


def start_cpa_login_job(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    return COMPAT_LOGIN_SUPPORT.start_cpa_login_job(payload, workspace_id)


def get_cpa_login_job(job_id: str, workspace_id: str = "") -> dict[str, Any]:
    # 兼容旧调用点，登录任务状态查询已经迁到 login.jobs。
    return login_get_login_job(job_id, workspace_id)


def login_mail_credential_counts(payload: dict[str, Any]) -> dict[str, int]:
    # 兼容旧调用点，请求内邮箱取码凭据统计已迁到 app.facade。
    return app_login_mail_credential_counts_impl(payload, usable_secret_func=usable_secret)


def hydrate_login_mail_credentials(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, int]:
    # 兼容旧调用点，登录/取信请求的邮箱凭据注水已迁到 app.facade。
    return app_hydrate_login_mail_credentials_impl(
        payload,
        workspace_id,
        coerce_text_func=coerce_text,
        usable_secret_func=usable_secret,
        workspace_file_func=workspace_file,
        load_accounts_func=load_accounts,
        load_temp_addresses_func=load_temp_addresses,
        load_generic_accounts_func=load_generic_accounts,
        login_mail_credential_counts_func=login_mail_credential_counts,
        default_temp_worker_url=TEMP_WORKER_URL,
    )


def transient_mail_accounts(payload: dict[str, Any]) -> tuple[list[MailAccount], list[str]]:
    # 兼容旧调用点，payload -> Microsoft 账号实体整理已经迁到 mail.service。
    return mail_transient_mail_accounts(payload)


def transient_temp_addresses(payload: dict[str, Any]) -> tuple[list[TempAddress], list[str]]:
    # 兼容旧调用点，payload -> 临时邮箱实体整理已经迁到 mail.service。
    return mail_transient_temp_addresses(
        payload,
        default_base_url=TEMP_WORKER_URL,
        default_site_password=TEMP_SITE_PASSWORD,
        normalize_temp_worker_url_func=normalize_temp_worker_url,
    )


def transient_generic_accounts(payload: dict[str, Any]) -> tuple[list[GenericMailAccount], list[str]]:
    # 兼容旧调用点，payload -> 普通邮箱实体整理已经迁到 mail.service。
    return mail_transient_generic_accounts(payload)


def fetch_transient_client_mail(
    payload: dict[str, Any],
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """兼容旧调用点；邮件取信主流程已收口到 app.web_runtime。"""
    return COMPAT_WEB_SUPPORT.fetch_transient_client_mail(payload, progress_callback=progress_callback)


def fetch_saved_mail(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    """兼容旧调用点；已保存账号的批量取信主流程已收口到 app.web_runtime。"""
    return COMPAT_WEB_SUPPORT.fetch_saved_mail(payload, workspace_id)


def mail_fetch_job_public(job: dict[str, Any]) -> dict[str, Any]:
    return mail_mail_fetch_job_public(job)

def set_mail_fetch_job(job_id: str, **updates: Any) -> None:
    mail_set_mail_fetch_job(job_id, **updates)

def trim_mail_fetch_jobs() -> None:
    mail_trim_mail_fetch_jobs()

def run_client_mail_fetch_job(job_id: str, payload: dict[str, Any], workspace_id: str) -> None:
    COMPAT_WEB_SUPPORT.run_client_mail_fetch_job(job_id, payload, workspace_id)

def start_client_mail_fetch_job(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    return COMPAT_WEB_SUPPORT.start_client_mail_fetch_job(payload, workspace_id)

def get_client_mail_fetch_job(job_id: str, workspace_id: str = "public") -> dict[str, Any]:
    return COMPAT_WEB_SUPPORT.get_client_mail_fetch_job(job_id, workspace_id)

def admin_worker_headers(admin_password: str, site_password: str = "") -> dict[str, str]:
    # 兼容旧调用点，admin worker header 组合已经迁到 mail.admin_sync。
    return mail_admin_worker_headers(admin_password, site_password)


def payload_rows(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    # 兼容旧调用点，payload 行规整已经迁到 mail.admin_sync。
    return mail_payload_rows(payload)


def extract_admin_jwt(base_url: str, headers: dict[str, str], email_addr: str) -> dict[str, Any]:
    # 兼容旧调用点，admin worker 单邮箱提取已经迁到 mail.admin_sync。
    return mail_extract_admin_jwt(base_url, headers, email_addr)


def validate_admin_worker_url(base_url: str) -> None:
    # 兼容旧调用点，admin worker URL 校验已经迁到 mail.admin_sync。
    return mail_validate_admin_worker_url(base_url)


def extract_admin_jwts(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，admin worker JWT 批量提取已经迁到 mail.admin_sync。
    return mail_extract_admin_jwts(payload)


def sync_temp_jwts_from_worker(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    # 兼容旧调用点，临时邮箱 JWT 同步已经迁到 app.web_runtime。
    return COMPAT_WEB_SUPPORT.sync_temp_jwts_from_worker(payload, workspace_id)


def import_pickup_accounts(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    # 兼容旧调用点，工作区微软账号导入已经迁到 app.web_runtime。
    return COMPAT_WEB_SUPPORT.import_pickup_accounts(payload, workspace_id)


def import_temp_addresses(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    # 兼容旧调用点，工作区临时邮箱导入已经迁到 app.web_runtime。
    return COMPAT_WEB_SUPPORT.import_temp_addresses(payload, workspace_id)


def import_generic_accounts(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    # 兼容旧调用点，工作区普通邮箱导入已经迁到 app.web_runtime。
    return COMPAT_WEB_SUPPORT.import_generic_accounts(payload, workspace_id)


def delete_workspace_mail_credentials(payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
    # 兼容旧调用点，工作区凭据批量删除已经迁到 app.web_runtime。
    return COMPAT_WEB_SUPPORT.delete_workspace_mail_credentials(payload, workspace_id)


def public_pool_rows_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    # 兼容旧调用点，公共池行规整已经迁到 workspace.admin_sync。
    return workspace_public_pool_rows_from_payload(payload)


def push_public_pool(payload: dict[str, Any]) -> dict[str, Any]:
    # 兼容旧调用点，公共池推送已经迁到 workspace.admin_sync。
    return workspace_push_public_pool(
        payload,
        default_target_url=PUBLIC_POOL_API_URL,
        default_token=PUBLIC_POOL_TOKEN,
    )


COMPAT_CPA_SUPPORT = app_CompatCpaSupport_impl(
    app_CompatCpaRuntimeConfig_impl(
        allow_remote=CPA_ALLOW_REMOTE,
        probe_user_agent=CPA_PROBE_USER_AGENT,
    )
)

COMPAT_LOGIN_SUPPORT = app_CompatLoginSupport_impl(
    app_CompatLoginRuntimeConfig_impl(
        default_http_headers=DEFAULT_HTTP_HEADERS,
        openai_sec_ch_ua=OPENAI_SEC_CH_UA,
        openai_sec_ch_ua_full_version_list=OPENAI_SEC_CH_UA_FULL_VERSION_LIST,
        openai_oauth_redirect_uri=OPENAI_OAUTH_REDIRECT_URI,
        openai_codex_client_id=OPENAI_CODEX_CLIENT_ID,
        login_node_bin=LOGIN_NODE_BIN,
        openai_sentinel_helper=OPENAI_SENTINEL_HELPER,
        environ=os.environ,
        cpa_direct_oauth_start_func=COMPAT_CPA_SUPPORT.cpa_direct_oauth_start,
        cpa_direct_oauth_callback_func=COMPAT_CPA_SUPPORT.cpa_direct_oauth_callback,
        append_refresh_result_func=append_refresh_result,
        replace_cpa_auth_file_func=COMPAT_CPA_SUPPORT.replace_cpa_auth_file,
        workspace_file_func=workspace_file,
        hydrate_login_mail_credentials_func=hydrate_login_mail_credentials,
        login_mail_credential_counts_func=login_mail_credential_counts,
        cpa_allow_remote=CPA_ALLOW_REMOTE,
    )
)

COMPAT_WEB_SUPPORT = app_CompatWebSupport_impl(
    app_CompatWebRuntimeConfig_impl(
        admin_cookie_name=ADMIN_COOKIE_NAME,
        admin_token=ADMIN_TOKEN,
        app_version=APP_VERSION,
        login_debug_dir=LOGIN_DEBUG_DIR,
        messages_file=MESSAGES_FILE,
        refresh_results_file=REFRESH_RESULTS_FILE,
        login_history_file=LOGIN_HISTORY_FILE,
        public_pool_url=PUBLIC_POOL_URL,
        public_relay_url=PUBLIC_RELAY_URL,
        static_dir=STATIC_DIR,
        accounts_file=ACCOUNTS_FILE,
        temp_addresses_file=TEMP_ADDRESSES_FILE,
        generic_accounts_file=GENERIC_ACCOUNTS_FILE,
        temp_worker_url=TEMP_WORKER_URL,
        temp_site_password=TEMP_SITE_PASSWORD,
        workspace_file_func=workspace_file,
        normalize_workspace_id_func=normalize_workspace_id,
        normalize_temp_worker_url_func=normalize_temp_worker_url,
        hydrate_login_mail_credentials_func=hydrate_login_mail_credentials,
        cpa_direct_oauth_start_func=COMPAT_CPA_SUPPORT.cpa_direct_oauth_start,
        cpa_direct_oauth_callback_func=COMPAT_CPA_SUPPORT.cpa_direct_oauth_callback,
        delete_cpa_items_func=COMPAT_CPA_SUPPORT.delete_cpa_items,
        replace_cpa_auth_file_func=COMPAT_CPA_SUPPORT.replace_cpa_auth_file,
        scan_cpa_401_func=COMPAT_LOGIN_SUPPORT.scan_cpa_401,
        repair_cpa_401_func=COMPAT_LOGIN_SUPPORT.repair_cpa_401,
        refresh_lifecycle_func=COMPAT_LOGIN_SUPPORT.refresh_lifecycle,
        refresh_cpa_lifecycle_func=COMPAT_LOGIN_SUPPORT.refresh_cpa_lifecycle,
        start_cpa_login_job_func=COMPAT_LOGIN_SUPPORT.start_cpa_login_job,
        health_payload_func=health_payload,
        public_config_payload_func=public_config_payload,
        network_health_payload_func=network_health_payload,
        upgrade_status_payload_func=upgrade_status_payload,
        create_upgrade_request_func=create_upgrade_request,
        push_public_pool_func=push_public_pool,
        dashboard_stats_response_func=dashboard_stats_response,
    )
)


Handler = COMPAT_WEB_SUPPORT.build_handler_class()
def main() -> None:
    # 兼容旧脚本入口；启动期装配已迁到 app.startup。
    app_run_http_service_impl(
        data_dir=DATA_DIR,
        load_login_history_func=load_login_history,
        login_jobs=LOGIN_JOBS,
        login_jobs_lock=LOGIN_JOBS_LOCK,
        now_func=iso_now,
        server_factory=ThreadingHTTPServer,
        host=DEFAULT_HOST,
        port=DEFAULT_PORT,
        handler_class=Handler,
        admin_token=ADMIN_TOKEN,
        print_func=print,
    )

if __name__ == "__main__":
    # 兼容旧的脚本启动方式，但实际入口已经收拢到模块层。
    from gpt_account_manager import main as entry_main

    entry_main()
