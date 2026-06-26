"""登录域的协议登录运行器。

这里承接旧 `server.py` 里的 `ChatGPTProtocolLogin` 状态机。运行器只负责
OpenAI/Auth0 协议登录链路本身；CPA callback、Sentinel helper 路径和
HTTP 运行时常量由兼容入口注入，避免登录域直接反向依赖旧脚本。
"""
from __future__ import annotations

import http.cookiejar
import re
import secrets
import time
import urllib.parse
import urllib.request
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from gpt_account_manager.infra import (
    network_error_message,
    open_with_fast_dns,
    request_proxy_url,
    temporary_socket_proxy,
)

from .errors import LoginFlowError
from .jobs import (
    append_login_log,
    manual_email_code_for_payload,
    manual_phone_code_for_payload,
    raise_if_login_job_cancelled,
)
from .oauth import access_token_email
from .oauth_flow import (
    build_openai_oauth_authorize_url,
    generate_openai_code_verifier,
    openai_code_challenge,
)
from .protocol import (
    ProtocolResponse,
    account_session_next_url,
    analyze_oauth_authorize_hop,
    analyze_oauth_callback_capture_hop,
    authorize_continue_requires_session_retry,
    build_organization_select_payload,
    build_protocol_headers,
    build_workspace_select_payload,
    callback_has_code,
    decode_oauth_session_cookie_value,
    extract_account_session_id_from_html,
    extract_continue_url,
    extract_email_verification_mode,
    extract_oauth_authorize_params,
    extract_oauth_callback_url_from_error,
    extract_page_type,
    format_oauth_authorize_hop_log,
    generate_openai_sentinel_token,
    normalize_auth_url,
    oauth2_auth_url_from_authorize,
    parse_oauth_callback_params,
    payload_has_cpa_config,
    perform_protocol_request,
    protocol_compact_error,
    read_response_text,
    safe_url_for_log,
    session_from_cpa_callback_result,
    validate_oauth_exchange_response,
    validate_session_response,
    workspace_select_next_url,
    needs_add_phone,
    needs_modern_otp,
    needs_phone_channel_selection,
    needs_phone_verification,
)
from .service import exchange_openai_oauth_code, merge_session_with_oauth
from .verification import (
    build_phone_number_verification_attempts,
    build_phone_otp_channel_attempts,
    build_phone_verification_code_attempts,
    extract_phone_hint_from_step,
    fetch_login_verification_code,
    normalize_phone_digits,
    poll_phone_code,
    resolve_phone_code_source,
)


def coerce_text(value: Any) -> str:
    """把兼容输入收敛成协议状态机可判断的文本。"""
    return str(value or "").strip()


def first_text(*values: Any) -> str:
    """保持旧脚本取第一个非空值的兼容优先级。"""
    for value in values:
        text = coerce_text(value)
        if text:
            return text
    return ""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """禁止 urllib 自动跟随重定向，让协议状态机显式处理下一跳。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(frozen=True)
class ProtocolLoginRuntime:
    """协议登录运行时依赖。

    旧脚本里的常量、CPA 回调和 Sentinel helper 路径通过这里注入，
    让登录域可以独立承接状态机，同时保持现有部署配置不变。
    """

    default_http_headers: dict[str, str]
    openai_sec_ch_ua: str
    openai_sec_ch_ua_full_version_list: str
    openai_oauth_redirect_uri: str
    openai_codex_client_id: str
    login_node_bin: str
    openai_sentinel_helper: Path
    environ: Mapping[str, str]
    cpa_direct_oauth_start: Callable[[dict[str, Any]], dict[str, Any]]
    cpa_direct_oauth_callback: Callable[[dict[str, Any]], dict[str, Any]]


class ChatGPTProtocolLogin:
    def __init__(self, job_id: str, payload: dict[str, Any], *, runtime: ProtocolLoginRuntime):
        self.job_id = job_id
        self.payload = payload
        self.runtime = runtime
        self.proxy_url = request_proxy_url(payload)
        self.cookie_jar = http.cookiejar.CookieJar()
        handlers: list[Any] = [
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
            NoRedirectHandler(),
        ]
        if self.proxy_url and urllib.parse.urlparse(self.proxy_url).scheme.lower() in {"http", "https"}:
            handlers.append(urllib.request.ProxyHandler({
                "http": self.proxy_url,
                "https": self.proxy_url,
            }))
        elif not self.proxy_url:
            handlers.append(urllib.request.ProxyHandler({}))
        self.opener = urllib.request.build_opener(
            *handlers,
        )
        self.auth_url = ""
        self.login_url = ""
        self.state = ""
        self.device_id = ""
        self.sentinel_token = ""
        self.oauth_state = ""
        self.oauth_code_verifier = ""
        self.oauth_redirect_uri = runtime.openai_oauth_redirect_uri
        self.oauth_client_id = runtime.openai_codex_client_id
        self.oauth_authorize_url = ""
        self.oauth_authorize_source = "local"
        self.oauth_cpa_state = ""

    def log(self, step: str, message: str, level: str = "info") -> None:
        append_login_log(self.job_id, message, level, step)

    def headers(self, url: str, extra: dict[str, str] | None = None) -> dict[str, str]:
        return build_protocol_headers(
            url,
            device_id=self.device_id,
            default_http_headers=self.runtime.default_http_headers,
            openai_sec_ch_ua=self.runtime.openai_sec_ch_ua,
            openai_sec_ch_ua_full_version_list=self.runtime.openai_sec_ch_ua_full_version_list,
            extra=extra,
        )

    def generate_sentinel_token(self, flow: str) -> str:
        """按当前协议运行时配置生成 Sentinel token。"""
        return generate_openai_sentinel_token(
            self.device_id,
            flow,
            self.proxy_url,
            node_bin=self.runtime.login_node_bin,
            helper_path=self.runtime.openai_sentinel_helper,
            environ=self.runtime.environ,
        )

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        json_data: dict[str, Any] | None = None,
        form_data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = 60,
    ) -> ProtocolResponse:
        return perform_protocol_request(
            url=url,
            method=method,
            json_data=json_data,
            form_data=form_data,
            headers=headers,
            timeout=timeout,
            proxy_url=self.proxy_url,
            opener_open_func=self.opener.open,
            temporary_socket_proxy_func=temporary_socket_proxy,
            open_with_fast_dns_func=open_with_fast_dns,
            extract_cookies_func=lambda resp, req: self.cookie_jar.extract_cookies(resp, req),
            sleep_func=time.sleep,
            network_error_message_func=network_error_message,
            response_factory=ProtocolResponse,
            read_response_text_func=read_response_text,
        )

    def login(self) -> dict[str, Any]:
        email_addr = coerce_text(self.payload.get("email"))
        password = coerce_text(self.payload.get("password"))
        force_email_code = str(first_text(
            self.payload.get("force_email_code"),
            self.payload.get("forceEmailCode"),
            self.payload.get("email_code_login"),
            self.payload.get("emailCodeLogin"),
        )).lower() in {"1", "true", "yes", "on"}
        if force_email_code:
            password = ""
        if not email_addr:
            raise RuntimeError("protocol login needs email")

        self.device_id = self.device_id or uuid.uuid4().hex
        self.set_cookie("oai-did", self.device_id, "auth.openai.com")
        self.set_cookie("oai-did", self.device_id, ".auth.openai.com")
        self.set_cookie("oai-did", self.device_id, "chatgpt.com")
        self.set_cookie("oai-did", self.device_id, ".chatgpt.com")

        self.log("oauth_init", "后端协议：生成 OpenAI OAuth 授权会话")
        self.auth_url = self.prepare_oauth_authorize_url()
        self.log("authorize", "后端协议：打开 OAuth 授权入口并建立 login_session")
        login_state = self.bootstrap_oauth_session(self.auth_url)
        if not login_state.get("ok"):
            raw_error = login_state.get("error") or "OAuth 授权入口没有建立 auth.openai.com 登录会话。"
            raw_hint = login_state.get("hint") or "CPA 已返回授权链接，但协议链路没有拿到 auth.openai.com 的 login_session；请看 authorize 日志里的最终 URL、HTTP 状态和响应摘要。"
            error_code = "oauth_session_missing"
            lowered_error = f"{raw_error} {raw_hint}".lower()
            if "unsupported_country_region_territory" in lowered_error or "country, region, or territory not supported" in lowered_error:
                error_code = "unsupported_country_region_territory"
                raw_hint = "OpenAI OAuth 明确拒绝当前后端出口：所在国家/地区不受支持。这一步还没有到邮箱验证码，也不是邮箱/JWT问题；请看“当前后端出口”日志，换成 OpenAI 支持地区的 HTTP 代理或 VPS 出口后重试。"
            raise LoginFlowError(
                raw_error,
                code=error_code,
                hint=raw_hint,
                status=login_state.get("status") if isinstance(login_state.get("status"), int) else None,
                retryable=True,
            )

        issued_after = time.time()
        self.log("sentinel", "Protocol login: generate Sentinel token")
        self.sentinel_token = self.generate_sentinel_token("authorize_continue")
        if not self.sentinel_token:
            self.log("sentinel", "Sentinel token helper returned empty token; continuing once", "warning")

        self.log("identifier", "Protocol login: submit email")
        step = self.authorize_continue(email_addr)
        continue_url = self.complete_modern_login(step, password, issued_after)
        self.log("callback", "后端协议：跟随 OAuth 后续页面并捕获 callback code")
        callback_url, final_url = self.capture_oauth_callback(continue_url or self.auth_url)
        if not callback_url and continue_url:
            callback_url, final_url = self.capture_oauth_callback(self.auth_url)
        if not callback_url:
            raise RuntimeError(f"OAuth flow did not return callback code; final={final_url[:220] if final_url else 'empty'}")

        if payload_has_cpa_config(self.payload) and self.oauth_authorize_source == "cpa":
            self.log("cpa_callback", "后端协议：把 OAuth callback 直接提交给 CPA")
            cpa_result = self.runtime.cpa_direct_oauth_callback({
                **self.payload,
                "callback_url": callback_url,
                "state": self.oauth_cpa_state or self.oauth_state,
            })
            session = session_from_cpa_callback_result(cpa_result, email_addr)
            self.log("success", "Protocol login succeeded", "success")
            return session

        self.log("token", "后端协议：交换 OpenAI OAuth token")
        session = self.exchange_oauth_callback(callback_url)
        email_from_token = access_token_email(session.get("access_token", ""))
        if email_from_token:
            session["email"] = email_from_token
        else:
            session["email"] = email_addr
        session["user"] = {**(session.get("user") if isinstance(session.get("user"), dict) else {}), "email": session["email"]}
        self.log("success", "Protocol login succeeded", "success")
        return session

    def set_cookie(self, name: str, value: str, domain: str, path: str = "/") -> None:
        if not value:
            return
        cookie = http.cookiejar.Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=True,
            domain_initial_dot=domain.startswith("."),
            path=path,
            path_specified=True,
            secure=True,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={},
            rfc2109=False,
        )
        self.cookie_jar.set_cookie(cookie)

    def prepare_oauth_authorize_url(self) -> str:
        if payload_has_cpa_config(self.payload):
            data = self.runtime.cpa_direct_oauth_start(self.payload)
            authorize_url = coerce_text(data.get("authorize_url") or data.get("oauth_url"))
            if not authorize_url.startswith(("http://", "https://")):
                raise RuntimeError("CPA did not return a valid OAuth authorize URL")
            self.oauth_authorize_source = "cpa"
            self.oauth_cpa_state = coerce_text(data.get("state"))
            self.remember_oauth_params_from_authorize_url(authorize_url)
            return authorize_url
        self.oauth_authorize_source = "local"
        self.oauth_state = secrets.token_urlsafe(32)
        self.oauth_code_verifier = generate_openai_code_verifier()
        authorize_url = build_openai_oauth_authorize_url(self.oauth_state, openai_code_challenge(self.oauth_code_verifier))
        self.remember_oauth_params_from_authorize_url(authorize_url)
        return authorize_url

    def remember_oauth_params_from_authorize_url(self, authorize_url: str) -> None:
        oauth_params = extract_oauth_authorize_params(
            authorize_url,
            current_state=self.oauth_state,
            current_cpa_state=self.oauth_cpa_state,
            current_redirect_uri=self.oauth_redirect_uri or self.runtime.openai_oauth_redirect_uri,
            current_client_id=self.oauth_client_id or self.runtime.openai_codex_client_id,
        )
        self.oauth_authorize_url = oauth_params["oauth_authorize_url"]
        self.oauth_state = oauth_params["oauth_state"]
        self.oauth_redirect_uri = oauth_params["oauth_redirect_uri"]
        self.oauth_client_id = oauth_params["oauth_client_id"]
        if not self.oauth_code_verifier and self.oauth_authorize_source == "local":
            self.oauth_code_verifier = generate_openai_code_verifier()

    def bootstrap_oauth_session(self, authorize_url: str) -> dict[str, Any]:
        attempts = [
            ("CPA 授权链接", authorize_url, "https://chatgpt.com/"),
            ("OpenAI OAuth API", oauth2_auth_url_from_authorize(authorize_url), authorize_url),
        ]
        best: dict[str, Any] = {"ok": False, "final_url": "", "status": None, "hint": ""}
        seen_starts: set[str] = set()
        for label, start_url, referer in attempts:
            if not start_url or start_url in seen_starts:
                continue
            seen_starts.add(start_url)
            state = self.follow_oauth_authorize_chain(start_url, referer, label)
            if state.get("ok"):
                return state
            if state.get("final_url") or state.get("status") is not None or state.get("hint"):
                best = state
        final_url = coerce_text(best.get("final_url"))
        if final_url:
            self.login_url = final_url if "auth.openai.com" in final_url else "https://auth.openai.com/log-in"
        ok = self.has_auth_session_cookie()
        if ok:
            return {"ok": True, "final_url": final_url}
        cookie_names = self.auth_cookie_names()
        final_label = safe_url_for_log(final_url) if final_url else "空"
        status = best.get("status")
        hint = coerce_text(best.get("hint")) or "没有收到 login_session / oai-client-auth-session cookie"
        error = f"OAuth 授权入口没有建立 auth.openai.com 登录会话：final={final_label}，HTTP {status or '-'}，cookies={cookie_names or '无'}，摘要：{hint}"
        self.log("authorize", error[:700], "error")
        return {**best, "ok": False, "error": error, "hint": hint}

    def follow_oauth_authorize_chain(self, start_url: str, referer: str, label: str, max_hops: int = 12) -> dict[str, Any]:
        current_url = normalize_auth_url(start_url)
        last_url = current_url
        last_status: int | None = None
        last_hint = ""
        visited: set[str] = set()
        for hop in range(max_hops):
            if not current_url or current_url in visited:
                break
            visited.add(current_url)
            try:
                resp = self.request(
                    current_url,
                    headers=self.headers(current_url, {
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
                        "Referer": referer or last_url or "https://chatgpt.com/",
                        "Upgrade-Insecure-Requests": "1",
                    }),
                    timeout=45,
                )
            except Exception as exc:
                last_hint = str(exc)[:260]
                self.log("authorize", f"OAuth {label} 第 {hop + 1} 跳请求异常：{last_hint}", "warning")
                return {"ok": False, "final_url": current_url, "status": last_status, "hint": last_hint}

            hop_result = analyze_oauth_authorize_hop(resp, current_url, self.has_auth_session_cookie())
            last_status = int(hop_result.get("status") or 0) or None
            last_url = coerce_text(hop_result.get("last_url"))
            last_hint = coerce_text(hop_result.get("hint"))
            next_url = coerce_text(hop_result.get("next_url"))
            self.log(
                "authorize",
                format_oauth_authorize_hop_log(label, hop + 1, hop_result),
                "info" if next_url or hop_result.get("session_ready") else "warning",
            )

            if hop_result.get("session_ready"):
                self.login_url = coerce_text(hop_result.get("final_login_url"))
                return {"ok": True, "final_url": last_url, "status": resp.status, "hint": last_hint}

            if not next_url:
                break
            referer = current_url
            current_url = normalize_auth_url(next_url)

        return {"ok": False, "final_url": last_url, "status": last_status, "hint": last_hint}

    def has_auth_session_cookie(self) -> bool:
        return self.has_cookie("login_session") or self.has_cookie("oai-client-auth-session")

    def auth_cookie_names(self) -> str:
        names = sorted({cookie.name for cookie in self.cookie_jar if "openai.com" in coerce_text(cookie.domain)})
        return ",".join(names)

    def has_cookie(self, name: str) -> bool:
        return bool(self.cookie_value(name))

    def get_csrf_token(self) -> str:
        url = "https://chatgpt.com/api/auth/csrf"
        resp = self.request(url, headers=self.headers(url, {"Referer": "https://chatgpt.com/auth/login"}))
        data = resp.json()
        csrf_token = coerce_text(data.get("csrfToken"))
        if resp.status != 200 or not csrf_token:
            compact = protocol_compact_error(data)
            proxy_text = "已启用代理" if self.proxy_url else "未启用代理"
            raise LoginFlowError(
                f"CSRF 校验失败：HTTP {resp.status} - {compact}",
                code="csrf_or_risk_blocked",
                hint=f"{proxy_text}。请确认整轮登录使用同一出口 IP/cookie 会话，然后重试协议登录。",
                status=resp.status,
                retryable=True,
            )
        return csrf_token

    def signin_openai(self, csrf_token: str) -> str:
        attempts = [
            {
                "url": "https://chatgpt.com/api/auth/signin/openai",
                "callbackUrl": "https://chatgpt.com/",
                "referer": "https://chatgpt.com/auth/login",
            },
            {
                "url": "https://chatgpt.com/api/auth/signin/login-web?callbackUrl=%2F",
                "callbackUrl": "/",
                "referer": "https://chatgpt.com/",
            },
        ]
        last_url = ""
        for attempt in attempts:
            url = attempt["url"]
            resp = self.request(
                url,
                method="POST",
                form_data={"callbackUrl": attempt["callbackUrl"], "csrfToken": csrf_token, "json": "true"},
                headers=self.headers(url, {
                    "Origin": "https://chatgpt.com",
                    "Referer": attempt["referer"],
                }),
            )
            data = resp.json()
            last_url = coerce_text(data.get("url") or resp.location())
            if last_url and "/api/auth/signin?csrf=true" not in last_url:
                return urllib.parse.urljoin(url, last_url)
        raise RuntimeError(f"signin did not return authorize URL: {last_url or 'empty'}")

    def authorize_continue(self, email_addr: str) -> dict[str, Any]:
        url = "https://auth.openai.com/api/accounts/authorize/continue"
        headers = self.headers(url, {
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/log-in?usernameKind=email",
        })
        if self.sentinel_token:
            headers["openai-sentinel-token"] = self.sentinel_token
        payload = {"username": {"kind": "email", "value": email_addr}}
        resp = self.request(
            url,
            method="POST",
            json_data=payload,
            headers=headers,
        )
        data = resp.json()
        if authorize_continue_requires_session_retry(resp.status, data):
            self.log("authorize", "OAuth login_session 失效，重新建立授权会话后重试", "warning")
            self.bootstrap_oauth_session(self.auth_url)
            headers = self.headers(url, {
                "Accept": "application/json",
                "Origin": "https://auth.openai.com",
                "Referer": "https://auth.openai.com/log-in?usernameKind=email",
            })
            self.sentinel_token = self.generate_sentinel_token("authorize_continue")
            if self.sentinel_token:
                headers["openai-sentinel-token"] = self.sentinel_token
            resp = self.request(
                url,
                method="POST",
                json_data=payload,
                headers=headers,
            )
            data = resp.json()
        if resp.status != 200:
            raise RuntimeError(f"submit email failed: HTTP {resp.status} - {protocol_compact_error(data)}")
        return data

    def complete_modern_login(self, step: dict[str, Any], password: str, issued_after: float) -> str:
        current_step = step or {}
        continue_url = normalize_auth_url(extract_continue_url(current_step))
        page_type = extract_page_type(current_step)
        mode = extract_email_verification_mode(current_step)
        self.log("identifier", f"登录步骤：page={page_type or '-'}，mode={mode or '-'}", "info")

        if (page_type == "login_password" or "/log-in/password" in continue_url) and password:
            self.log("password", "Protocol login: submit password")
            self.sentinel_token = self.generate_sentinel_token("password_verify")
            current_step = self.submit_modern_password(password)
            continue_url = normalize_auth_url(extract_continue_url(current_step))
            page_type = extract_page_type(current_step)
            mode = extract_email_verification_mode(current_step) or mode
        elif page_type == "login_password" or "/log-in/password" in continue_url:
            self.log("send_code", "Protocol login: use email code path", "info")
            self.sentinel_token = self.generate_sentinel_token("email_verification")
            if not self.kickoff_modern_otp(mode):
                self.log("send_code", "OpenAI 发码接口没有返回确认，继续等待邮箱新验证码", "warning")
            continue_url = ""
            page_type = "email_otp_verification"

        if continue_url and not needs_modern_otp(page_type, continue_url):
            return continue_url

        self.log("waiting_code", "Protocol login: waiting for email code")
        code = manual_email_code_for_payload(self.payload)
        if code:
            self.log("waiting_code", "使用手动填写的邮箱验证码", "info")
        else:
            code = fetch_login_verification_code(self.payload, since=issued_after, attempts=12, delay=5)
        if not code:
            self.log("send_code", "Protocol login: request a fresh email code", "warning")
            resent_after = time.time()
            self.sentinel_token = self.generate_sentinel_token("email_verification")
            self.kickoff_modern_otp(mode)
            code = fetch_login_verification_code(self.payload, since=resent_after, attempts=20, delay=5)
        if not code:
            raise RuntimeError("no verification code was found in local mailbox credentials")

        self.log("verify_code", "Protocol login: submit email code")
        current_step = self.submit_modern_code(code)
        continue_url = normalize_auth_url(extract_continue_url(current_step))
        if needs_phone_verification(current_step, continue_url):
            continue_url = self.complete_phone_verification(current_step, continue_url)
        if not continue_url:
            raise RuntimeError(f"email code accepted but no continue URL returned: {protocol_compact_error(current_step)}")
        return continue_url

    def complete_phone_verification(self, step: dict[str, Any], continue_url: str = "") -> str:
        self.log("phone_code", "账号要求手机二次验证", "warning")
        phone_hint = extract_phone_hint_from_step(step, continue_url)
        if phone_hint:
            self.payload["_detected_phone_hint"] = phone_hint
            self.log("phone_pool", f"检测到账号使用手机号尾号 {phone_hint[-4:]}", "info")
        if needs_add_phone(step, continue_url):
            continue_url = self.submit_phone_number_for_verification(continue_url, phone_hint)
        elif needs_phone_channel_selection(step, continue_url):
            continue_url = self.select_phone_otp_channel(step, continue_url)
        code = self.fetch_phone_verification_code(phone_hint)
        if not code:
            raise LoginFlowError(
                "手机二次验证失败：没有收到手机验证码。",
                code="phone_2fa_failed",
                hint="账号已经通过邮箱验证码，但后续要求手机短信二次验证。请绑定长效手机 API，或在任务运行时手动输入手机验证码。",
                retryable=False,
            )
        self.log("phone_code", "已取到手机验证码，正在提交", "info")
        current_step = self.submit_phone_verification_code(code, continue_url)
        next_url = normalize_auth_url(extract_continue_url(current_step))
        if not next_url and needs_phone_verification(current_step, ""):
            raise LoginFlowError(
                "手机二次验证失败：验证码无效或仍停留在手机验证步骤。",
                code="phone_2fa_failed",
                hint="手机验证码提交后仍未进入授权回调，通常是验证码无效、过期或该号码无法完成验证。",
                retryable=False,
            )
        if not next_url:
            raise LoginFlowError(
                f"手机二次验证失败：没有返回继续授权地址。{protocol_compact_error(current_step)}",
                code="phone_2fa_failed",
                hint="手机验证码已提交，但 OpenAI 没有返回可继续的 OAuth 地址；请保留日志用于确认返回结构。",
                retryable=False,
            )
        return next_url

    def resolve_phone_code_source(self, phone_hint: str = "", *, allow_batch: bool = False) -> dict[str, str]:
        return resolve_phone_code_source(self.payload, phone_hint, allow_batch=allow_batch)

    def submit_phone_number_for_verification(self, continue_url: str = "", phone_hint: str = "") -> str:
        source = self.resolve_phone_code_source(phone_hint, allow_batch=True)
        phone = coerce_text(source.get("phone"))
        if not phone:
            raise LoginFlowError(
                "手机二次验证失败：账号要求绑定手机号，但当前账号没有绑定长效手机。",
                code="phone_2fa_failed",
                hint="这个提示窗需要先提交手机号，再收短信验证码。请在长效手机池给该账号绑定手机号和 API URL 后重试。",
                retryable=False,
            )
        self.payload["phone_number"] = phone
        self.payload["phone_api_url"] = coerce_text(source.get("api_url"))
        self.log("phone_pool", "提交绑定手机号", "info")
        referer = continue_url or "https://auth.openai.com/add-phone"
        attempts = build_phone_number_verification_attempts(
            referer=referer,
            phone=phone,
            normalize_auth_url_func=normalize_auth_url,
        )
        last_status = 0
        last_data: dict[str, Any] = {}
        for attempt in attempts:
            url = coerce_text(attempt.get("url"))
            if not url:
                continue
            is_form = bool(attempt.get("is_form"))
            resp = self.request(
                url,
                method="POST",
                form_data=attempt.get("form_data") if is_form else None,
                json_data=None if is_form else attempt.get("json_data"),
                headers=self.headers(url, {
                    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8" if is_form else "application/json",
                    "Origin": "https://auth.openai.com",
                    "Referer": referer,
                }),
                timeout=45,
            )
            last_status = resp.status
            if resp.status in {301, 302, 303, 307, 308} and resp.location():
                return urllib.parse.urljoin(url, resp.location())
            data = resp.json()
            last_data = data
            next_url = normalize_auth_url(extract_continue_url(data))
            if resp.status == 200 and next_url:
                return next_url
            if resp.status == 200 and needs_phone_verification(data, resp.url):
                return resp.url or "https://auth.openai.com/phone-verification"
        raise LoginFlowError(
            f"手机二次验证失败：手机号提交失败 HTTP {last_status or '-'} - {protocol_compact_error(last_data)}",
            code="phone_2fa_failed",
            hint="账号要求先提交手机号，但目标站没有接受当前号码。请更换绑定手机或检查号码格式。",
            status=last_status or None,
            retryable=False,
        )

    def select_phone_otp_channel(self, step: dict[str, Any], continue_url: str = "") -> str:
        referer = normalize_auth_url(continue_url) or "https://auth.openai.com/phone-otp/select-channel"
        phone_hint = extract_phone_hint_from_step(step, continue_url)
        source = self.resolve_phone_code_source(phone_hint, allow_batch=True)
        phone = coerce_text(source.get("phone"))
        self.log("phone_code", "进入手机验证码通道，尝试发送短信", "info")
        try:
            page_resp = self.request(
                referer,
                headers=self.headers(referer, {
                    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                    "Referer": "https://auth.openai.com/email-verification",
                }),
                timeout=45,
            )
            if page_resp.status in {301, 302, 303, 307, 308} and page_resp.location():
                return urllib.parse.urljoin(referer, page_resp.location())
            page_data = page_resp.json()
            page_hint = extract_phone_hint_from_step(page_data, page_resp.url or referer)
            if page_hint and not phone_hint:
                phone_hint = page_hint
                self.payload["_detected_phone_hint"] = phone_hint
        except Exception as exc:
            self.log("phone_code", f"读取手机验证页失败，继续尝试发码：{str(exc)[:120]}", "warning")

        attempts = build_phone_otp_channel_attempts(phone=phone)
        last_status = 0
        last_data: dict[str, Any] = {}
        for attempt in attempts:
            url = coerce_text(attempt.get("url"))
            request_body = dict(attempt.get("json_data") or {})
            headers = self.headers(url, {
                "Accept": "application/json",
                "Origin": "https://auth.openai.com",
                "Referer": referer,
            })
            if self.sentinel_token:
                headers["openai-sentinel-token"] = self.sentinel_token
            resp = self.request(url, method="POST", json_data=request_body, headers=headers, timeout=45)
            last_status = resp.status
            if resp.status in {301, 302, 303, 307, 308} and resp.location():
                self.log("phone_code", "已请求手机验证码，等待接码", "info")
                return urllib.parse.urljoin(url, resp.location())
            data = resp.json()
            last_data = data
            next_url = normalize_auth_url(extract_continue_url(data))
            if resp.status == 200:
                self.log("phone_code", "已请求手机验证码，等待接码", "info")
                return next_url or "https://auth.openai.com/phone-otp"
            if resp.status in {400, 401, 403} and re.search(r"invalid|expired|incorrect|验证码", protocol_compact_error(data), re.I):
                continue
        if last_status:
            self.log("phone_code", f"手机短信通道请求未确认：HTTP {last_status}", "warning")
            if last_data:
                self.log("phone_code", protocol_compact_error(last_data), "warning")
        return referer or "https://auth.openai.com/phone-otp"

    def fetch_phone_verification_code(self, phone_hint: str = "", attempts: int = 24, delay: float = 5) -> str:
        source = self.resolve_phone_code_source(phone_hint, allow_batch=False)
        phone = coerce_text(source.get("phone"))
        api_url = coerce_text(source.get("api_url"))
        if phone and api_url:
            self.payload["phone_number"] = phone
            self.payload["phone_api_url"] = api_url
            self.log("phone_pool", f"按手机号匹配长效手机尾号 {normalize_phone_digits(phone)[-4:]}", "info")
        since = str(int(time.time()))
        for attempt in range(1, max(1, attempts) + 1):
            raise_if_login_job_cancelled(self.job_id)
            manual_code = manual_phone_code_for_payload(self.payload)
            if manual_code:
                self.log("manual_phone_code", "使用手动填写的手机验证码", "info")
                return manual_code
            if phone and api_url:
                try:
                    result = poll_phone_code({
                        "phone": phone,
                        "api_url": api_url,
                        "account_email": self.payload.get("email", ""),
                        "since": since,
                    })
                    if result.get("code"):
                        self.log("phone_code", "已从长效手机 API 收到验证码", "success")
                        return coerce_text(result.get("code"))
                    if attempt == 1 or attempt % 4 == 0:
                        self.log("phone_code", "等待手机验证码", "warning")
                except Exception as exc:
                    if attempt == 1 or attempt % 4 == 0:
                        self.log("phone_code", f"手机取码失败：{str(exc)[:180]}", "warning")
            elif attempt == 1:
                self.log("phone_code", "未绑定长效手机，等待手动输入手机验证码", "warning")
            time.sleep(max(1, delay))
        return ""

    def submit_phone_verification_code(self, code: str, referer_url: str = "") -> dict[str, Any]:
        referer = referer_url or "https://auth.openai.com/phone-verification"
        attempts = build_phone_verification_code_attempts(
            code=code,
            referer=referer,
            normalize_auth_url_func=normalize_auth_url,
        )
        last_status = 0
        last_data: dict[str, Any] = {}
        for attempt in attempts:
            method = coerce_text(attempt.get("method") or "POST")
            url = coerce_text(attempt.get("url"))
            if not url:
                continue
            is_form = bool(attempt.get("is_form"))
            headers = self.headers(url, {
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8" if is_form else "application/json",
                "Origin": "https://auth.openai.com",
                "Referer": referer,
            })
            if not is_form and self.sentinel_token:
                headers["openai-sentinel-token"] = self.sentinel_token
            resp = self.request(
                url,
                method=method,
                form_data=attempt.get("form_data") if is_form else None,
                json_data=None if is_form else attempt.get("json_data"),
                headers=headers,
                timeout=45,
            )
            last_status = resp.status
            if resp.status in {301, 302, 303, 307, 308} and resp.location():
                return {"continue_url": urllib.parse.urljoin(url, resp.location())}
            data = resp.json()
            last_data = data
            if is_form:
                if resp.status == 200:
                    if extract_continue_url(data):
                        return data
                    if not needs_phone_verification(data, resp.url or url):
                        return {"continue_url": resp.url or url}
                continue
            if resp.status == 200:
                return data
            compact = protocol_compact_error(data)
            if resp.status in {400, 401, 403} and re.search(r"invalid|expired|incorrect|code|验证码", compact, re.I):
                break
        raise LoginFlowError(
            f"手机二次验证失败：HTTP {last_status or '-'} - {protocol_compact_error(last_data)}",
            code="phone_2fa_failed",
            hint="账号要求手机二次验证，但短信验证码提交未通过。请确认收到的是本轮最新验证码。",
            status=last_status or None,
            retryable=False,
        )
    def submit_modern_password(self, password: str) -> dict[str, Any]:
        url = "https://auth.openai.com/api/accounts/password/verify"
        headers = self.headers(url, {
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/log-in/password",
        })
        if self.sentinel_token:
            headers["openai-sentinel-token"] = self.sentinel_token
        resp = self.request(url, method="POST", json_data={"password": password}, headers=headers)
        data = resp.json()
        if resp.status != 200:
            raise RuntimeError(f"password verify failed: HTTP {resp.status} - {protocol_compact_error(data)}")
        return data

    def kickoff_modern_otp(self, mode: str = "") -> bool:
        mode_lc = coerce_text(mode).lower()
        payload_mode = coerce_text(self.payload.get("mode") or "login").lower()
        existing = (
            payload_mode != "signup"
            or "passwordless_login" in mode_lc
            or "existing" in mode_lc
        )
        attempts = (
            [
                ("POST", "https://auth.openai.com/api/accounts/email-otp/resend", "https://auth.openai.com/email-verification", None),
                ("GET", "https://auth.openai.com/api/accounts/email-otp/send", "https://auth.openai.com/email-verification", None),
                ("POST", "https://auth.openai.com/api/accounts/passwordless/send-otp", "https://auth.openai.com/email-verification", {}),
            ]
            if existing
            else [
                ("POST", "https://auth.openai.com/api/accounts/passwordless/send-otp", "https://auth.openai.com/create-account/password", {}),
                ("POST", "https://auth.openai.com/api/accounts/email-otp/resend", "https://auth.openai.com/email-verification", None),
                ("GET", "https://auth.openai.com/api/accounts/email-otp/send", "https://auth.openai.com/email-verification", None),
            ]
        )
        for method, url, referer, body in attempts:
            headers = self.headers(url, {
                "Accept": "application/json",
                "Origin": "https://auth.openai.com",
                "Referer": referer,
            })
            if self.sentinel_token:
                headers["openai-sentinel-token"] = self.sentinel_token
            try:
                resp = self.request(url, method=method, json_data=body, headers=headers, timeout=30)
                if resp.status == 200:
                    self.log("send_code", f"OpenAI 已返回发送/重发验证码请求：{urllib.parse.urlparse(url).path}", "info")
                    return True
            except Exception:
                continue
        return False

    def submit_modern_code(self, code: str) -> dict[str, Any]:
        url = "https://auth.openai.com/api/accounts/email-otp/validate"
        headers = self.headers(url, {
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/email-verification",
        })
        if self.sentinel_token:
            headers["openai-sentinel-token"] = self.sentinel_token
        resp = self.request(url, method="POST", json_data={"code": code}, headers=headers)
        data = resp.json()
        if resp.status != 200:
            raise RuntimeError(f"email code verify failed: HTTP {resp.status} - {protocol_compact_error(data)}")
        next_url = normalize_auth_url(extract_continue_url(data))
        self.log("verify_code", f"验证码提交响应：page={extract_page_type(data) or '-'}，next={safe_url_for_log(next_url) if next_url else '-'}", "info")
        return data

    def capture_oauth_callback(self, start_url: str, max_hops: int = 18) -> tuple[str, str]:
        current_url = normalize_auth_url(start_url)
        last_url = current_url
        chose_account = False
        for hop in range(max_hops):
            if callback_has_code(current_url, self.oauth_redirect_uri):
                return current_url, current_url
            try:
                resp = self.request(
                    current_url,
                    headers=self.headers(current_url, {
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Referer": last_url if hop else "https://chatgpt.com/",
                        "Upgrade-Insecure-Requests": "1",
                    }),
                    timeout=45,
                )
            except Exception as exc:
                callback_url = extract_oauth_callback_url_from_error(str(exc), self.oauth_redirect_uri)
                if callback_url:
                    return callback_url, callback_url
                raise
            hop_result = analyze_oauth_callback_capture_hop(
                resp,
                current_url,
                self.oauth_redirect_uri,
                chose_account=chose_account,
            )
            last_url = coerce_text(hop_result.get("last_url")) or resp.url or current_url
            action = coerce_text(hop_result.get("action"))
            if action == "callback":
                callback_url = coerce_text(hop_result.get("callback_url"))
                return callback_url, callback_url
            if action == "workspace":
                next_url = self.submit_workspace_and_org(current_url)
                if next_url:
                    if callback_has_code(next_url, self.oauth_redirect_uri):
                        return next_url, next_url
                    current_url = normalize_auth_url(next_url)
                    continue
                break
            if action == "choose_account":
                chose_account = True
                next_url = self.choose_account_from_html(resp.text, current_url)
                if next_url:
                    current_url = normalize_auth_url(next_url)
                    continue
                break
            if action == "next":
                current_url = coerce_text(hop_result.get("next_url"))
                if current_url:
                    continue
            break
        return "", last_url

    def submit_workspace_and_org(self, referer_url: str) -> str:
        session_data = self.decode_oauth_session_cookie()
        workspace_payload = build_workspace_select_payload(session_data)
        url = coerce_text(workspace_payload.get("url"))
        body = workspace_payload.get("json_data") if isinstance(workspace_payload, dict) else {}
        if not url or not body:
            return ""
        headers = self.headers(url, {
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": referer_url,
        })
        resp = self.request(url, method="POST", json_data=body, headers=headers, timeout=45)
        if resp.status in {301, 302, 303, 307, 308} and resp.location():
            return urllib.parse.urljoin(url, resp.location())
        data = resp.json()
        next_url = workspace_select_next_url(data)
        if next_url:
            return next_url
        org_payload = build_organization_select_payload(data, session_data)
        org_url = coerce_text(org_payload.get("url"))
        org_body = org_payload.get("json_data") if isinstance(org_payload, dict) else {}
        if not org_url or not org_body:
            return ""
        org_resp = self.request(
            org_url,
            method="POST",
            json_data=org_body,
            headers=self.headers(org_url, {
                "Accept": "application/json",
                "Origin": "https://auth.openai.com",
                "Referer": normalize_auth_url(next_url) or referer_url,
            }),
            timeout=45,
        )
        if org_resp.status in {301, 302, 303, 307, 308} and org_resp.location():
            return urllib.parse.urljoin(org_url, org_resp.location())
        return normalize_auth_url(extract_continue_url(org_resp.json()))

    def choose_account_from_html(self, html_text: str, referer_url: str) -> str:
        session_id = extract_account_session_id_from_html(html_text)
        if not session_id:
            return ""
        url = "https://auth.openai.com/api/accounts/session/select"
        resp = self.request(
            url,
            method="POST",
            json_data={"session_id": session_id},
            headers=self.headers(url, {
                "Accept": "application/json",
                "Origin": "https://auth.openai.com",
                "Referer": referer_url,
            }),
            timeout=45,
        )
        if resp.status in {301, 302, 303, 307, 308} and resp.location():
            return urllib.parse.urljoin(url, resp.location())
        return account_session_next_url(resp.json(), referer_url)

    def decode_oauth_session_cookie(self) -> dict[str, Any]:
        return decode_oauth_session_cookie_value(self.cookie_value("oai-client-auth-session"))

    def exchange_oauth_callback(self, callback_url: str) -> dict[str, Any]:
        callback = parse_oauth_callback_params(callback_url, self.oauth_state or self.oauth_cpa_state)
        code = callback["code"]
        if not self.oauth_code_verifier:
            raise RuntimeError("OAuth callback captured, but code_verifier is unavailable; CPA callback was submitted but local token exchange cannot run")
        status, data, raw = exchange_openai_oauth_code(code, self.oauth_code_verifier, proxy_url=self.proxy_url)
        validate_oauth_exchange_response(status, data, raw)
        return merge_session_with_oauth({}, data)

    def follow_callback(self, callback_url: str) -> None:
        current_url = normalize_auth_url(callback_url)
        for _ in range(12):
            resp = self.request(
                current_url,
                headers=self.headers(current_url, {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                }),
            )
            if 300 <= resp.status < 400 and resp.location():
                current_url = urllib.parse.urljoin(current_url, resp.location())
                parsed = urllib.parse.urlparse(current_url)
                if parsed.hostname == "chatgpt.com" and not parsed.path.startswith("/api/auth/"):
                    return
                continue
            return

    def get_session(self) -> dict[str, Any]:
        url = "https://chatgpt.com/api/auth/session"
        resp = self.request(url, headers=self.headers(url, {"Referer": "https://chatgpt.com/"}))
        data = resp.json()
        return validate_session_response(resp.status, data)

    def get_session_cookie(self) -> str:
        names = [
            "__Secure-next-auth.session-token",
            "__Secure-authjs.session-token",
            "next-auth.session-token",
            "authjs.session-token",
        ]
        for name in names:
            direct = self.cookie_value(name)
            if direct:
                return direct
            chunks: list[tuple[int, str]] = []
            for cookie in self.cookie_jar:
                if cookie.name.startswith(f"{name}."):
                    try:
                        idx = int(cookie.name.rsplit(".", 1)[1])
                    except ValueError:
                        continue
                    chunks.append((idx, cookie.value))
            if chunks:
                return "".join(value for _, value in sorted(chunks))
        return ""

    def cookie_value(self, name: str) -> str:
        for cookie in self.cookie_jar:
            if cookie.name == name:
                return coerce_text(cookie.value)
        return ""


def run_chatgpt_login_with_protocol(job_id: str, payload: dict[str, Any], *, runtime: ProtocolLoginRuntime) -> dict[str, Any]:
    """执行协议登录并返回旧接口兼容的 session 载荷。"""
    return ChatGPTProtocolLogin(job_id, payload, runtime=runtime).login()
