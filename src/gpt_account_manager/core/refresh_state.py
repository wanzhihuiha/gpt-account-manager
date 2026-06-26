"""刷新任务状态的纯映射规则。

这一层只负责状态规范化、状态到展示状态的映射，以及步骤到状态的推导，
不接触文件、网络、线程或任何外部副作用，方便后续被多个业务域复用。
"""
from __future__ import annotations

from typing import Any


REFRESH_STATES = {
    "pending",
    "queued",
    "running",
    "checking_mail",
    "checking_proxy",
    "establishing_session",
    "waiting_code",
    "submitting_code",
    "building_auth",
    "syncing_cpa",
    "persisting",
    "success",
    "failed",
    "cancelled",
}

TERMINAL_REFRESH_STATES = {"success", "failed", "cancelled"}

REFRESH_STATE_STATUS = {
    "pending": "queued",
    "queued": "queued",
    "running": "running",
    "checking_mail": "running",
    "checking_proxy": "running",
    "establishing_session": "running",
    "waiting_code": "running",
    "submitting_code": "running",
    "building_auth": "running",
    "syncing_cpa": "running",
    "persisting": "running",
    "success": "success",
    "failed": "failed",
    "cancelled": "failed",
}

STEP_STATE = {
    "start": "running",
    "mail_credentials": "checking_mail",
    "proxy": "checking_proxy",
    "proxy_check": "checking_proxy",
    "egress": "checking_proxy",
    "browser_queue": "establishing_session",
    "prepare": "establishing_session",
    "auth_session": "establishing_session",
    "sentinel": "establishing_session",
    "submit_email": "establishing_session",
    "strategy": "establishing_session",
    "identifier": "establishing_session",
    "password": "establishing_session",
    "login_ready": "establishing_session",
    "login_loading": "establishing_session",
    "security_check": "establishing_session",
    "signup_start": "establishing_session",
    "email_input": "establishing_session",
    "password_input": "establishing_session",
    "send_code": "waiting_code",
    "waiting_code": "waiting_code",
    "waiting_email": "waiting_code",
    "mail_code_poll": "waiting_code",
    "mail_code_missing": "waiting_code",
    "manual_email_code": "waiting_code",
    "phone_otp": "waiting_code",
    "phone_code": "waiting_code",
    "submit_code": "submitting_code",
    "verify_code": "submitting_code",
    "email_verified": "submitting_code",
    "oauth_callback": "building_auth",
    "token_exchange": "building_auth",
    "oauth": "building_auth",
    "session": "building_auth",
    "fetch_session": "building_auth",
    "convert": "building_auth",
    "upload": "syncing_cpa",
    "uploading": "syncing_cpa",
    "persist_success": "persisting",
    "persist_failed": "persisting",
    "done": "success",
    "success": "success",
    "failed": "failed",
    "cancel": "cancelled",
}

STATE_ALIASES = {
    "idle": "pending",
    "wait": "pending",
    "waiting": "pending",
    "start": "queued",
    "started": "running",
    "in_progress": "running",
    "mail": "checking_mail",
    "mail_check": "checking_mail",
    "mail_credentials": "checking_mail",
    "proxy": "checking_proxy",
    "proxy_check": "checking_proxy",
    "auth": "establishing_session",
    "auth_session": "establishing_session",
    "oauth": "establishing_session",
    "code": "waiting_code",
    "wait_code": "waiting_code",
    "email_code": "waiting_code",
    "phone_code": "waiting_code",
    "submit": "submitting_code",
    "submit_code": "submitting_code",
    "callback": "building_auth",
    "token": "building_auth",
    "convert": "building_auth",
    "cpa": "syncing_cpa",
    "upload": "syncing_cpa",
    "persist": "persisting",
    "saved": "persisting",
    "done": "success",
    "ok": "success",
    "error": "failed",
    "cancel": "cancelled",
    "canceled": "cancelled",
    "login_cancelled": "cancelled",
}


def normalize_refresh_state(value: Any, fallback: str = "pending") -> str:
    """把外部传入的状态值收敛成统一状态名。

    这里允许旧别名和大小写差异，避免上层在迁移期被状态写法卡住；
    如果给出的值不认识，就回落到 `pending`，保证任务仍可继续流转。
    """
    text = str(value or "").strip().lower().replace("-", "_")
    normalized = STATE_ALIASES.get(text, text)
    if normalized in REFRESH_STATES:
        return normalized
    if fallback and fallback != text:
        return normalize_refresh_state(fallback, "pending")
    return "pending"


def refresh_status_for_state(state: Any) -> str:
    """把内部状态映射成前端和日志更容易消费的粗粒度状态。"""
    normalized = normalize_refresh_state(state)
    return REFRESH_STATE_STATUS.get(normalized, "queued")


def is_terminal_refresh_state(state: Any) -> bool:
    """判断任务是否已经进入不可继续推进的终态。"""
    return normalize_refresh_state(state) in TERMINAL_REFRESH_STATES


def refresh_state_from_step(step: Any) -> str:
    """根据执行步骤推导出刷新状态，用于任务流转时统一口径。"""
    normalized = str(step or "").strip().lower().replace("-", "_")
    return STEP_STATE.get(normalized, "")


def terminal_refresh_states() -> set[str]:
    """返回终态集合的副本，避免调用方直接改全局常量。"""
    return set(TERMINAL_REFRESH_STATES)
