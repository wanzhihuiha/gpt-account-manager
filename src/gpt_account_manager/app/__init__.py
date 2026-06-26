"""应用层入口。

这里承接跨业务域的编排入口，只负责把多个域 service 的结果串起来，
不放业务规则，也不直接做文件或网络 I/O。
"""
from __future__ import annotations

from .main import main
from .startup import (
    restore_login_jobs_from_history,
    run_http_service,
)
from .login_runtime import (
    CompatLoginRuntimeConfig,
    CompatLoginSupport,
)
from .cpa_runtime import (
    CompatCpaRuntimeConfig,
    CompatCpaSupport,
)
from .web_runtime import (
    CompatWebRuntimeConfig,
    CompatWebSupport,
)
from .version import load_app_version, load_asset_version
from .facade import (
    complete_oauth_code_payload,
    finalize_cpa_login_job_failure,
    finalize_cpa_login_job_success,
    finalize_cpa_login_success,
    finalize_refresh_lifecycle_success,
    hydrate_login_mail_credentials,
    login_mail_credential_counts,
    prepare_cpa_login_job_start,
    refresh_cpa_lifecycle,
    refresh_lifecycle,
    refresh_lifecycle_item,
    resolve_cpa_login_session_payload,
    session_to_cpa_auth,
)

__all__ = [
    "CompatCpaRuntimeConfig",
    "CompatCpaSupport",
    "CompatLoginRuntimeConfig",
    "CompatLoginSupport",
    "CompatWebRuntimeConfig",
    "CompatWebSupport",
    "complete_oauth_code_payload",
    "finalize_cpa_login_job_failure",
    "finalize_cpa_login_job_success",
    "finalize_cpa_login_success",
    "finalize_refresh_lifecycle_success",
    "hydrate_login_mail_credentials",
    "login_mail_credential_counts",
    "load_app_version",
    "load_asset_version",
    "prepare_cpa_login_job_start",
    "refresh_cpa_lifecycle",
    "refresh_lifecycle",
    "refresh_lifecycle_item",
    "resolve_cpa_login_session_payload",
    "restore_login_jobs_from_history",
    "run_http_service",
    "session_to_cpa_auth",
    "main",
]
