"""CPA 域阶段性公开入口。

这一层给兼容入口和后续路由层提供统一的 CPA 域导入面，把 service /
management / diagnostics 的公开能力收拢到一起，避免继续直接依赖多个
内部模块文件。
"""
from __future__ import annotations

from .diagnostics import (
    cpa_diagnosis_action_hint,
    cpa_status_refreshable,
    diagnose_cpa_candidate,
    repair_cpa_401,
    scan_cpa_401,
)
from .management import (
    cpa_candidates,
    cpa_delete_auth_file,
    cpa_download_auth_file,
    cpa_list_auth_files,
    cpa_probe_status,
    cpa_upload_auth_file,
    delete_cpa_items,
    replace_cpa_auth_file,
)
from .service import (
    build_cpa_repair_login_payload,
    collect_nested_error_texts,
    compact_raw_status,
    cpa_auth_filename,
    cpa_companion_wait_code,
    cpa_direct_oauth_callback,
    cpa_direct_oauth_start,
    cpa_headers,
    cpa_is_401_item,
    cpa_item_chatgpt_account_id,
    cpa_item_type,
    cpa_management_config,
    cpa_oauth_value,
    cpa_probe_payload,
    cpa_status_message,
    extract_state_from_auth_url,
    infer_auth_email,
    looks_like_openai_auth_file,
    normalize_cpa_base_url,
    parse_nested_json_value,
    validate_cpa_base_url,
)

__all__ = [
    "build_cpa_repair_login_payload",
    "collect_nested_error_texts",
    "compact_raw_status",
    "cpa_auth_filename",
    "cpa_candidates",
    "cpa_companion_wait_code",
    "cpa_delete_auth_file",
    "cpa_diagnosis_action_hint",
    "cpa_direct_oauth_callback",
    "cpa_direct_oauth_start",
    "cpa_download_auth_file",
    "cpa_headers",
    "cpa_is_401_item",
    "cpa_item_chatgpt_account_id",
    "cpa_item_type",
    "cpa_list_auth_files",
    "cpa_management_config",
    "cpa_oauth_value",
    "cpa_probe_payload",
    "cpa_probe_status",
    "cpa_status_message",
    "cpa_status_refreshable",
    "cpa_upload_auth_file",
    "delete_cpa_items",
    "diagnose_cpa_candidate",
    "extract_state_from_auth_url",
    "infer_auth_email",
    "looks_like_openai_auth_file",
    "normalize_cpa_base_url",
    "parse_nested_json_value",
    "repair_cpa_401",
    "replace_cpa_auth_file",
    "scan_cpa_401",
    "validate_cpa_base_url",
]
