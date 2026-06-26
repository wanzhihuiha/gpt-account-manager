"""登录业务域入口。

这里优先只暴露登录域里相对稳定的高层入口，例如本机 OAuth、验证码轮询、
登录状态查询和少量协议/OAuth 辅助能力。任务全局状态、页面级 Playwright
动作和更细的运行时 helper 继续留在各自子模块，避免包根再次变成杂物堆。
"""
from __future__ import annotations

from .errors import (
    LoginFlowError,
    openai_turnstile_error,
)
from .jobs import (
    cancel_login_job,
    get_login_job,
    set_login_manual_email_code,
    set_login_manual_phone_code,
)
from .local_oauth import (
    create_local_oauth_flow,
    get_local_oauth_flow,
    handle_local_oauth_callback,
    parse_localhost_oauth_callback,
    start_local_oauth_callback_server,
)
from .oauth import (
    access_token_email,
    access_token_expires_at,
    access_token_plan_type,
    build_synthetic_id_token,
    classify_oauth_error,
    jwt_payload,
    normal_plan_type,
)
from .oauth_flow import (
    build_chatgpt_login_url,
    build_openai_oauth_authorize_url,
    generate_openai_code_verifier,
    oauth_base64url,
    openai_code_challenge,
)
from .playwright import (
    build_playwright_login_url,
    fetch_openai_oauth_with_playwright,
)
from .service import (
    lifecycle_summary,
    lifecycle_source_auth,
    lifecycle_status_label,
    merge_session_with_oauth,
    normalize_lifecycle_item,
)
from .verification import (
    collect_sms_candidates,
    count_six_digit_codes,
    extract_phone_hint_from_step,
    extract_phone_hint_from_text,
    extract_sms_code_payload,
    fetch_login_verification_code,
    find_latest_code,
    message_six_digit_codes,
    normalize_phone_digits,
    normalize_sms_field_name,
    phone_api_url,
    poll_phone_code,
    phone_pool_entries_from_payload,
    phone_pool_match_by_hint,
)

__all__ = [
    "access_token_email",
    "access_token_expires_at",
    "access_token_plan_type",
    "build_chatgpt_login_url",
    "build_openai_oauth_authorize_url",
    "build_playwright_login_url",
    "cancel_login_job",
    "classify_oauth_error",
    "collect_sms_candidates",
    "count_six_digit_codes",
    "create_local_oauth_flow",
    "build_synthetic_id_token",
    "extract_phone_hint_from_step",
    "extract_phone_hint_from_text",
    "extract_sms_code_payload",
    "fetch_login_verification_code",
    "fetch_openai_oauth_with_playwright",
    "find_latest_code",
    "generate_openai_code_verifier",
    "get_local_oauth_flow",
    "get_login_job",
    "handle_local_oauth_callback",
    "jwt_payload",
    "get_local_oauth_flow",
    "lifecycle_summary",
    "lifecycle_source_auth",
    "lifecycle_status_label",
    "merge_session_with_oauth",
    "message_six_digit_codes",
    "normal_plan_type",
    "normalize_lifecycle_item",
    "normalize_phone_digits",
    "normalize_sms_field_name",
    "oauth_base64url",
    "openai_code_challenge",
    "openai_turnstile_error",
    "parse_localhost_oauth_callback",
    "phone_api_url",
    "poll_phone_code",
    "phone_pool_entries_from_payload",
    "phone_pool_match_by_hint",
    "set_login_manual_email_code",
    "set_login_manual_phone_code",
    "start_local_oauth_callback_server",
    "LoginFlowError",
]
