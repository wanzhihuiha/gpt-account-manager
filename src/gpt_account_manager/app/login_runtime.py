"""登录兼容运行时装配。

这里承接旧脚本里协议登录、生命周期刷新和 CPA 登录 job 的依赖拼装，
让 `server.py` 继续往“薄兼容壳”收口，同时保持原有接口和任务语义不变。
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from gpt_account_manager.cpa.api import (
    build_cpa_repair_login_payload as cpa_build_cpa_repair_login_payload_impl,
    cpa_candidates as cpa_candidates_impl,
    cpa_download_auth_file as cpa_download_auth_file_impl,
    cpa_probe_status as cpa_probe_status_impl,
    cpa_upload_auth_file as cpa_upload_auth_file_impl,
    diagnose_cpa_candidate as cpa_diagnose_cpa_candidate_impl,
    normalize_cpa_base_url as cpa_normalize_cpa_base_url_impl,
    repair_cpa_401 as cpa_repair_cpa_401_impl,
    scan_cpa_401 as cpa_scan_cpa_401_impl,
)
from gpt_account_manager.infra import (
    probe_egress_trace as infra_probe_egress_trace_impl,
    require_login_proxy_url as infra_require_login_proxy_url_impl,
)
from gpt_account_manager.login.api import (
    ProtocolLoginRuntime as login_ProtocolLoginRuntime_impl,
    append_login_log as login_append_login_log_impl,
    build_lifecycle_access_token_outcome as login_build_lifecycle_access_token_outcome_impl,
    build_lifecycle_auth_probe_result_update as login_build_lifecycle_auth_probe_result_update_impl,
    build_lifecycle_refresh_token_outcome as login_build_lifecycle_refresh_token_outcome_impl,
    build_lifecycle_session_token_outcome as login_build_lifecycle_session_token_outcome_impl,
    classify_login_exception as login_classify_login_exception_impl,
    empty_lifecycle_result as login_empty_lifecycle_result_impl,
    lifecycle_status_label as login_lifecycle_status_label_impl,
    lifecycle_summary as login_lifecycle_summary_impl,
    normalize_lifecycle_item as login_normalize_lifecycle_item_impl,
    probe_openai_access_token as login_probe_openai_access_token_impl,
    refresh_openai_with_rt as login_refresh_openai_with_rt_impl,
    refresh_openai_with_session_token as login_refresh_openai_with_session_token_impl,
    run_chatgpt_login_with_protocol as login_run_chatgpt_login_with_protocol_impl,
    run_cpa_login_job as login_run_cpa_login_job_impl,
    set_login_job_status as login_set_login_job_status_impl,
    start_cpa_login_job as login_start_cpa_login_job_impl,
    access_token_expires_at as login_access_token_expires_at_impl,
)
from gpt_account_manager.storage import (
    normalize_workspace_id as storage_normalize_workspace_id_impl,
)

from .facade import (
    finalize_cpa_login_job_failure as app_finalize_cpa_login_job_failure_impl,
    finalize_cpa_login_job_success as app_finalize_cpa_login_job_success_impl,
    finalize_cpa_login_success as app_finalize_cpa_login_success_impl,
    finalize_refresh_lifecycle_success as app_finalize_refresh_lifecycle_success_impl,
    prepare_cpa_login_job_start as app_prepare_cpa_login_job_start_impl,
    refresh_cpa_lifecycle as app_refresh_cpa_lifecycle_impl,
    refresh_lifecycle as app_refresh_lifecycle_impl,
    refresh_lifecycle_item as app_refresh_lifecycle_item_impl,
    resolve_cpa_login_session_payload as app_resolve_cpa_login_session_payload_impl,
    session_to_cpa_auth as app_session_to_cpa_auth_impl,
)


def _coerce_text(value: Any) -> str:
    return str(value or "").strip()


def _first_text(*values: Any) -> str:
    for value in values:
        text = _coerce_text(value)
        if text:
            return text
    return ""


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class CompatLoginRuntimeConfig:
    """旧脚本登录兼容壳仍需注入的环境常量和路径绑定。"""

    default_http_headers: dict[str, str]
    openai_sec_ch_ua: str
    openai_sec_ch_ua_full_version_list: str
    openai_oauth_redirect_uri: str
    openai_codex_client_id: str
    login_node_bin: str
    openai_sentinel_helper: Path
    environ: Mapping[str, str]
    cpa_direct_oauth_start_func: Callable[[dict[str, Any]], dict[str, Any]]
    cpa_direct_oauth_callback_func: Callable[[dict[str, Any]], dict[str, Any]]
    append_refresh_result_func: Callable[..., Any]
    replace_cpa_auth_file_func: Callable[[dict[str, Any]], dict[str, Any]]
    workspace_file_func: Callable[[str, str], Any]
    hydrate_login_mail_credentials_func: Callable[[dict[str, Any], str], dict[str, int]]
    login_mail_credential_counts_func: Callable[[dict[str, Any]], dict[str, int]]
    cpa_allow_remote: bool = False
    default_cpa_base_url: str = "http://localhost:8317"


class CompatLoginSupport:
    """统一封装登录兼容链路里的运行时装配。"""

    def __init__(self, config: CompatLoginRuntimeConfig) -> None:
        self.config = config

    def protocol_login_runtime(self) -> login_ProtocolLoginRuntime_impl:
        """装配协议登录运行时依赖，避免登录域反向引用旧脚本。"""
        return login_ProtocolLoginRuntime_impl(
            default_http_headers=self.config.default_http_headers,
            openai_sec_ch_ua=self.config.openai_sec_ch_ua,
            openai_sec_ch_ua_full_version_list=self.config.openai_sec_ch_ua_full_version_list,
            openai_oauth_redirect_uri=self.config.openai_oauth_redirect_uri,
            openai_codex_client_id=self.config.openai_codex_client_id,
            login_node_bin=self.config.login_node_bin,
            openai_sentinel_helper=self.config.openai_sentinel_helper,
            environ=self.config.environ,
            cpa_direct_oauth_start=self.config.cpa_direct_oauth_start_func,
            cpa_direct_oauth_callback=self.config.cpa_direct_oauth_callback_func,
        )

    def run_chatgpt_login_with_protocol(self, job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return login_run_chatgpt_login_with_protocol_impl(
            job_id,
            payload,
            runtime=self.protocol_login_runtime(),
        )

    def refresh_lifecycle_item(self, item: dict[str, Any]) -> dict[str, Any]:
        """执行单条生命周期刷新，并保持既有成功/失败语义。"""
        return app_refresh_lifecycle_item_impl(
            item,
            normalize_lifecycle_item_func=login_normalize_lifecycle_item_impl,
            empty_lifecycle_result_func=login_empty_lifecycle_result_impl,
            refresh_openai_with_rt_func=login_refresh_openai_with_rt_impl,
            build_lifecycle_refresh_token_outcome_func=login_build_lifecycle_refresh_token_outcome_impl,
            refresh_openai_with_session_token_func=login_refresh_openai_with_session_token_impl,
            build_lifecycle_session_token_outcome_func=login_build_lifecycle_session_token_outcome_impl,
            probe_openai_access_token_func=login_probe_openai_access_token_impl,
            build_lifecycle_access_token_outcome_func=login_build_lifecycle_access_token_outcome_impl,
            access_token_expires_at_func=login_access_token_expires_at_impl,
            finalize_refresh_lifecycle_success_func=lambda **kwargs: app_finalize_refresh_lifecycle_success_impl(
                **kwargs,
                session_to_cpa_auth_func=app_session_to_cpa_auth_impl,
                probe_openai_access_token_func=login_probe_openai_access_token_impl,
                build_lifecycle_auth_probe_result_update_func=login_build_lifecycle_auth_probe_result_update_impl,
            ),
            lifecycle_status_label_func=login_lifecycle_status_label_impl,
        )

    def refresh_lifecycle(self, payload: dict[str, Any]) -> dict[str, Any]:
        return app_refresh_lifecycle_impl(
            payload,
            refresh_lifecycle_item_func=self.refresh_lifecycle_item,
            lifecycle_summary_func=lambda results, uploaded=0: login_lifecycle_summary_impl(
                results,
                uploaded=uploaded,
            ),
        )

    def refresh_cpa_lifecycle(self, payload: dict[str, Any]) -> dict[str, Any]:
        return app_refresh_cpa_lifecycle_impl(
            payload,
            cpa_candidates_func=cpa_candidates_impl,
            cpa_probe_status_func=cpa_probe_status_impl,
            cpa_download_auth_file_func=cpa_download_auth_file_impl,
            refresh_lifecycle_item_func=self.refresh_lifecycle_item,
            cpa_upload_auth_file_func=cpa_upload_auth_file_impl,
            lifecycle_summary_func=lambda results, uploaded=0: login_lifecycle_summary_impl(
                results,
                uploaded=uploaded,
            ),
            lifecycle_status_label_func=login_lifecycle_status_label_impl,
        )

    def diagnose_cpa_candidate(
        self,
        base_url: str,
        management_key: str,
        item: dict[str, Any],
    ) -> dict[str, Any]:
        return cpa_diagnose_cpa_candidate_impl(
            base_url,
            management_key,
            item,
            refresh_candidate=self.refresh_lifecycle_item,
            status_label_func=login_lifecycle_status_label_impl,
        )

    def scan_cpa_401(self, payload: dict[str, Any]) -> dict[str, Any]:
        return cpa_scan_cpa_401_impl(
            payload,
            allow_remote=self.config.cpa_allow_remote,
            diagnose_candidate=self.diagnose_cpa_candidate,
        )

    def repair_cpa_401(self, payload: dict[str, Any]) -> dict[str, Any]:
        return cpa_repair_cpa_401_impl(
            payload,
            allow_remote=self.config.cpa_allow_remote,
            diagnose_candidate=self.diagnose_cpa_candidate,
            build_login_payload=cpa_build_cpa_repair_login_payload_impl,
            login_runner=self.run_chatgpt_login_with_protocol,
            session_to_auth=app_session_to_cpa_auth_impl,
        )

    def run_cpa_login_job(self, job_id: str, payload: dict[str, Any]) -> None:
        login_run_cpa_login_job_impl(
            job_id,
            payload,
            resolve_cpa_login_session_payload_func=app_resolve_cpa_login_session_payload_impl,
            finalize_cpa_login_job_success_func=app_finalize_cpa_login_job_success_impl,
            finalize_cpa_login_job_failure_func=app_finalize_cpa_login_job_failure_impl,
            require_login_proxy_url_func=infra_require_login_proxy_url_impl,
            coerce_text_func=_coerce_text,
            probe_egress_trace_func=infra_probe_egress_trace_impl,
            sleep_func=time.sleep,
            run_chatgpt_login_with_protocol_func=self.run_chatgpt_login_with_protocol,
            session_to_cpa_auth_func=app_session_to_cpa_auth_impl,
            append_refresh_result_func=self.config.append_refresh_result_func,
            replace_cpa_auth_file_func=self.config.replace_cpa_auth_file_func,
            workspace_file_func=self.config.workspace_file_func,
            finalize_cpa_login_success_func=app_finalize_cpa_login_success_impl,
            classify_login_exception_func=login_classify_login_exception_impl,
        )

    def start_cpa_login_job(self, payload: dict[str, Any], workspace_id: str = "public") -> dict[str, Any]:
        return login_start_cpa_login_job_impl(
            payload,
            workspace_id,
            prepare_cpa_login_job_start_func=app_prepare_cpa_login_job_start_impl,
            coerce_text_func=_coerce_text,
            first_text_func=_first_text,
            require_login_proxy_url_func=infra_require_login_proxy_url_impl,
            normalize_workspace_id_func=storage_normalize_workspace_id_impl,
            normalize_cpa_base_url_func=cpa_normalize_cpa_base_url_impl,
            generate_job_id_func=lambda: uuid.uuid4().hex,
            now_func=_iso_now,
            hydrate_login_mail_credentials_func=self.config.hydrate_login_mail_credentials_func,
            login_mail_credential_counts_func=self.config.login_mail_credential_counts_func,
            default_cpa_base_url=self.config.default_cpa_base_url,
            run_cpa_login_job_func=self.run_cpa_login_job,
            thread_factory=threading.Thread,
        )


__all__ = [
    "CompatLoginRuntimeConfig",
    "CompatLoginSupport",
]
