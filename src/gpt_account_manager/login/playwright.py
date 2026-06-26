"""登录域的 Playwright 页面辅助函数。

这里先收纳登录浏览器流程里不直接碰业务编排的页面 helper，只负责
页面文本提示、可见输入框探测、轻量点击动作和安全验证页识别。
真正的登录主流程、日志、快照和 OAuth 编排仍留给上层调用方逐步收口。
"""
from __future__ import annotations

import html
import json
import re
import secrets
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Callable

from .errors import LoginFlowError, openai_turnstile_error


def _coerce_text(value: Any) -> str:
    """把页面返回值压成可展示文本。"""
    return str(value or "").strip()


def _strip_page_text(value: str) -> str:
    """把页面 body 文本做一次轻量清洗，方便日志和错误提示复用。"""
    clean = re.sub(r"<style.*?</style>", " ", value, flags=re.I | re.S)
    clean = re.sub(r"<script.*?</script>", " ", clean, flags=re.I | re.S)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = html.unescape(clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean


def is_openai_security_verification_text(value: str) -> bool:
    """判断页面提示是否已经落在人机验证/安全校验页。"""
    lowered = _coerce_text(value).lower()
    return any(
        marker in lowered
        for marker in [
            "performing security verification",
            "security service to protect against malicious bots",
            "this page is displayed while the website verifies",
            "ray id:",
            "just a moment",
        ]
    )


def playwright_page_hint(page: Any) -> str:
    """提取当前页面最可读的一段提示文本。"""
    try:
        text = page.locator("body").inner_text(timeout=3000)
    except Exception:
        text = ""
    hint = _strip_page_text(text).strip().replace("\n", " ")
    return hint[:260] or _coerce_text(getattr(page, "url", ""))


def first_visible_selector(page: Any, selectors: list[str], *, timeout: int = 30000) -> str:
    """在一组候选 selector 中返回第一个真正可见的输入控件。"""
    deadline = time.monotonic() + (timeout / 1000)
    last_error = ""
    while time.monotonic() < deadline:
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if locator.count() and locator.is_visible(timeout=500):
                    return selector
            except Exception as exc:
                last_error = str(exc)
        time.sleep(0.35)
    body_text = ""
    try:
        body_text = page.locator("body").inner_text(timeout=2000)
    except Exception:
        pass
    hint = _strip_page_text(body_text).strip().replace("\n", " ")[:220]
    if hint:
        lowered_hint = hint.lower()
        if is_openai_security_verification_text(lowered_hint):
            raise openai_turnstile_error(hint)
        raise RuntimeError(f"登录页没有出现可填写输入框，页面提示：{hint}")
    raise RuntimeError(f"登录页没有出现可填写输入框。{last_error[:160]}")


def optional_visible_selector(page: Any, selectors: list[str], *, timeout: int = 30000) -> str:
    """可选地查找可见控件，找不到时返回空串而不是抛错。"""
    try:
        return first_visible_selector(page, selectors, timeout=timeout)
    except RuntimeError:
        return ""


def login_page_snapshot(page: Any) -> dict[str, Any]:
    """采集当前登录页的轻量状态快照。

    这里仅读取页面上已经渲染的控件、标题和常见输入框存在性，不做截图、
    文件落盘或任务日志更新；这样页面状态采集可以留在 Playwright helper 层，
    而真正的快照持久化继续由上层流程控制。
    """
    try:
        controls = page.locator("input,button,a").evaluate_all(
            """els => els.slice(0, 80).map((el, index) => ({
                index,
                tag: el.tagName,
                type: el.getAttribute('type') || '',
                name: el.getAttribute('name') || '',
                id: el.id || '',
                text: (el.innerText || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '').trim().slice(0, 80),
                value: (el.value || '').slice(0, 80),
                disabled: !!el.disabled,
                visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            }))"""
        )
    except Exception as exc:
        controls = [{"error": str(exc)[:180]}]
    try:
        title = page.title(timeout=2000)
    except Exception:
        title = ""
    try:
        has_turnstile = page.locator("input[name='cf-turnstile-response'], iframe[src*='turnstile'], iframe[src*='challenges.cloudflare.com']").count() > 0
    except Exception:
        has_turnstile = False
    try:
        has_email_input = page.locator("input[type=email], input[name=username], input[name=email], input#username, input[autocomplete=username]").count() > 0
    except Exception:
        has_email_input = False
    try:
        has_code_input = page.locator("input[autocomplete='one-time-code'], input[name*='code' i], input[id*='code' i], input[inputmode='numeric']").count() > 0
    except Exception:
        has_code_input = False
    return {
        "url": _coerce_text(getattr(page, "url", "")),
        "title": _coerce_text(title),
        "hint": playwright_page_hint(page),
        "has_turnstile": bool(has_turnstile),
        "has_email_input": bool(has_email_input),
        "has_code_input": bool(has_code_input),
        "controls": controls,
    }


def save_login_debug_snapshot(
    page: Any,
    job_id: str,
    label: str,
    *,
    login_debug_dir: Any,
    page_snapshot_func: Callable[[Any], dict[str, Any]] = login_page_snapshot,
) -> dict[str, str]:
    """保存 Playwright 登录页调试快照。

    快照属于登录浏览器流程的页面诊断能力，因此放在登录域；目录、任务日志等
    运行时状态仍由调用方注入，避免页面 helper 直接绑定全局 job 表。
    """
    login_debug_dir.mkdir(parents=True, exist_ok=True)
    safe_label = re.sub(r"[^a-zA-Z0-9_-]+", "-", label).strip("-") or "snapshot"
    stem = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{job_id[:10]}-{safe_label}"
    png_path = login_debug_dir / f"{stem}.png"
    json_path = login_debug_dir / f"{stem}.json"
    snapshot = page_snapshot_func(page)
    try:
        page.screenshot(path=str(png_path), full_page=True, timeout=10000)
    except Exception as exc:
        snapshot["screenshot_error"] = str(exc)[:300]
    json_path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "screenshot": str(png_path),
        "json": str(json_path),
        "screenshot_url": f"/login-debug/{png_path.name}",
        "json_url": f"/login-debug/{json_path.name}",
        "url": _coerce_text(snapshot.get("url")),
        "hint": _coerce_text(snapshot.get("hint")),
    }


def append_login_snapshot_log(
    job_id: str,
    page: Any,
    label: str,
    level: str = "info",
    *,
    login_debug_dir: Any,
    login_jobs: dict[str, dict[str, Any]],
    login_jobs_lock: Any,
    append_login_log_func: Callable[[str, str, str, str], Any],
) -> None:
    """保存页面快照并把快照链接挂到最近一条登录日志上。"""
    try:
        snapshot = save_login_debug_snapshot(page, job_id, label, login_debug_dir=login_debug_dir)
        message = f"页面快照[{label}] URL={snapshot['url']} 提示={snapshot['hint'][:180]} 截图={snapshot['screenshot_url']}"
        append_login_log_func(job_id, message, level, "snapshot")
        with login_jobs_lock:
            job = login_jobs.get(job_id)
            if job and job.get("logs"):
                job["logs"][-1]["snapshot_url"] = snapshot["screenshot_url"]
                job["logs"][-1]["snapshot_json_url"] = snapshot["json_url"]
                job["logs"][-1]["page_url"] = snapshot["url"]
                job["logs"][-1]["snapshot_file"] = snapshot["screenshot"]
    except Exception as exc:
        append_login_log_func(job_id, f"页面快照保存失败[{label}]：{str(exc)[:180]}", "warning", "snapshot")

def fill_login_code(page: Any, selector: str, code: str) -> None:
    """给登录页验证码输入框回填验证码。

    OpenAI/ChatGPT 有时会把验证码拆成多个单字符输入框；这里先尽量按
    可见输入框逐位填写，只有在输入框不是分栏场景时才回退成整串 fill。
    """
    locator = page.locator(selector)
    visible_inputs = []
    try:
        count = locator.count()
    except Exception:
        count = 0
    for index in range(min(count, 12)):
        item = locator.nth(index)
        try:
            if item.is_visible(timeout=500):
                visible_inputs.append(item)
        except Exception:
            continue
    if len(visible_inputs) >= min(len(code), 4):
        for item, char in zip(visible_inputs, code):
            item.fill(char)
        return
    page.fill(selector, code)


def wait_for_chatgpt_logged_in(page: Any, *, timeout: int = 90000) -> bool:
    """等待页面进入已登录的 ChatGPT 会话。"""
    deadline = time.monotonic() + (timeout / 1000)
    while time.monotonic() < deadline:
        current_url = _coerce_text(getattr(page, "url", ""))
        if (
            "chatgpt.com" in current_url
            and "/auth/login" not in current_url
            and "/api/auth/error" not in current_url
        ):
            return True
        try:
            text = page.locator("body").inner_text(timeout=1000).lower()
        except Exception:
            text = ""
        if any(marker in text for marker in ["message chatgpt", "new chat", "what can i help with", "有什么可以帮"]):
            return True
        page.wait_for_timeout(1000)
    return False


def wait_for_openai_login_ready(
    page: Any,
    selectors: list[str],
    *,
    timeout: int = 90000,
    job_id: str = "",
    append_log_func: Callable[[str, str, str, str], Any] | None = None,
    append_snapshot_log_func: Callable[[str, Any, str, str], Any] | None = None,
) -> None:
    """等待 OpenAI 登录页进入可输入邮箱或明确风控的状态。

    这里把“页面是否可继续”的判断逻辑收口到 Playwright helper 层，但不直接
    绑定 job 运行时；如果上层希望沿用旧日志和快照行为，可以把记录回调注入
    进来。这样页面等待规则可以复用，副作用仍由外层流程掌控。
    """
    deadline = time.monotonic() + (timeout / 1000)
    last_hint = ""
    next_log_at = time.monotonic()
    while time.monotonic() < deadline:
        try:
            if page.locator("input[name='cf-turnstile-response'], iframe[src*='turnstile'], iframe[src*='challenges.cloudflare.com']").count() > 0:
                if job_id and append_snapshot_log_func:
                    append_snapshot_log_func(job_id, page, "turnstile-challenge", "warning")
                raise openai_turnstile_error("页面出现 Cloudflare Turnstile 组件，还没有发送邮箱验证码")
        except LoginFlowError:
            raise
        except Exception:
            pass
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if locator.count() and locator.is_visible(timeout=500):
                    if job_id and append_log_func:
                        append_log_func(job_id, "登录页已可输入邮箱", "info", "login_ready")
                    return
            except Exception:
                pass
        hint = playwright_page_hint(page)
        if hint:
            last_hint = hint
            if hint.startswith("http"):
                if job_id and append_log_func and time.monotonic() >= next_log_at:
                    append_log_func(job_id, f"登录页仍在加载，当前 URL：{hint[:180]}", "info", "login_loading")
                    next_log_at = time.monotonic() + 10
                page.wait_for_timeout(1500)
                continue
            if not is_openai_security_verification_text(hint):
                if job_id and append_log_func and time.monotonic() >= next_log_at:
                    append_log_func(job_id, f"登录页已有内容但未出现输入框：{hint[:180]}", "warning", "login_loading")
                    next_log_at = time.monotonic() + 10
                page.wait_for_timeout(1500)
                continue
            if job_id and append_log_func and time.monotonic() >= next_log_at:
                append_log_func(job_id, "等待 OpenAI 安全验证通过，还未发送邮箱验证码", "warning", "security_check")
                next_log_at = time.monotonic() + 10
        page.wait_for_timeout(1500)
    if last_hint and is_openai_security_verification_text(last_hint):
        if job_id and append_snapshot_log_func:
            append_snapshot_log_func(job_id, page, "security-verification-timeout", "warning")
        raise openai_turnstile_error(last_hint)
    if last_hint:
        raise RuntimeError(f"OpenAI 登录页没有渲染出邮箱输入框，还没有发送验证码。当前页面提示：{last_hint[:220]}")
    raise RuntimeError("OpenAI 登录页没有渲染出邮箱输入框，还没有发送验证码。")


def read_playwright_session(
    context: Any,
    *,
    session_url: str,
    html_challenge_hint_func: Callable[[str], str],
    strip_html_func: Callable[[str], str],
    first_text_func: Callable[..., str],
) -> dict[str, Any]:
    """读取 Playwright 浏览器上下文里的 ChatGPT session JSON。

    这里保留既有的接口访问和错误提示语义，但把 HTML 拒绝页提示和字段判空
    通过注入函数交给上层复用旧逻辑，避免在登录浏览器 helper 里重新散落
    一套 HTML/文本清洗规则。
    """
    response = context.request.get(
        session_url,
        headers={"Accept": "application/json"},
        timeout=60000,
    )
    content = response.text()
    try:
        session = json.loads(content)
    except Exception as exc:
        hint = html_challenge_hint_func(content) or strip_html_func(content).strip().replace("\n", " ")[:260]
        raise RuntimeError(f"Session 接口没有返回 JSON：HTTP {response.status} - {hint}") from exc
    if not isinstance(session, dict) or not first_text_func(session.get("accessToken"), session.get("access_token")):
        raise RuntimeError("Session 接口没有返回有效 accessToken")
    return session


def fetch_openai_oauth_from_captured_code(
    captured: dict[str, str],
    code_verifier: str,
    page: Any,
    *,
    proxy_url: str = "",
    exchange_openai_oauth_code_func: Callable[..., tuple[int, dict[str, Any], str]],
    protocol_compact_error_func: Callable[[Any], str],
) -> dict[str, Any]:
    """等待浏览器拿到 OAuth code，并换取 OpenAI token。

    Playwright 主流程已经负责监听回调 URL 和维护 `captured`；这里仅负责在
    页面上补做一次轮询兜底，并把 authorization code 兑换成 token 响应。
    真实的 HTTP 请求仍由上层注入的 exchange helper 执行。
    """
    code = _coerce_text(captured.get("code"))
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline and not code:
        current_url = _coerce_text(getattr(page, "url", ""))
        parsed = urllib.parse.urlparse(current_url)
        if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"} and parsed.port == 1455 and parsed.path == "/auth/callback":
            query = urllib.parse.parse_qs(parsed.query)
            error = _coerce_text(query.get("error", [""])[0]) or _coerce_text(query.get("error_description", [""])[0])
            if error:
                raise RuntimeError(f"OpenAI OAuth 授权失败：{error}")
            code = _coerce_text(query.get("code", [""])[0])
            if code:
                captured["code"] = code
                break
        page.wait_for_timeout(500)
        code = _coerce_text(captured.get("code"))
    if not code:
        hint = playwright_page_hint(page)
        raise RuntimeError(f"没有拿到 OpenAI OAuth authorization code。当前页面：{hint}")

    status, data, raw = exchange_openai_oauth_code_func(code, code_verifier, proxy_url=proxy_url)
    if status != 200:
        compact = protocol_compact_error_func(data) or raw[:260]
        raise RuntimeError(f"OpenAI OAuth token exchange 失败：HTTP {status} - {compact}")
    if not _coerce_text(data.get("refresh_token")):
        raise RuntimeError("OpenAI OAuth token exchange 成功，但返回里没有 refresh_token")
    if not _coerce_text(data.get("access_token")):
        raise RuntimeError("OpenAI OAuth token exchange 成功，但返回里没有 access_token")
    return data


def fetch_openai_oauth_with_playwright(
    page: Any,
    *,
    proxy_url: str = "",
    generate_openai_code_verifier_func: Callable[[], str],
    build_openai_oauth_authorize_url_func: Callable[[str, str], str],
    openai_code_challenge_func: Callable[[str], str],
    exchange_openai_oauth_code_func: Callable[..., tuple[int, dict[str, Any], str]],
    protocol_compact_error_func: Callable[[Any], str],
) -> dict[str, Any]:
    """在已登录的 ChatGPT 浏览器页里完成 OpenAI OAuth token 获取。

    这里负责生成 state/code_verifier、监听本地回调 URL，并在浏览器侧等待
    authorization code 返回；真正的 token 兑换请求仍通过注入的 exchange
    helper 执行，避免把 HTTP 细节重新耦合进页面 helper。
    """
    redirect_uri = "http://localhost:1455/auth/callback"
    state = secrets.token_urlsafe(32)
    code_verifier = generate_openai_code_verifier_func()
    authorize_url = build_openai_oauth_authorize_url_func(state, openai_code_challenge_func(code_verifier))
    captured: dict[str, str] = {}

    def remember_callback(value: str) -> None:
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1"}:
            return
        if parsed.port != 1455 or parsed.path != "/auth/callback":
            return
        query = urllib.parse.parse_qs(parsed.query)
        returned_state = _coerce_text(query.get("state", [""])[0])
        if returned_state and returned_state != state:
            raise RuntimeError("OpenAI OAuth state 校验失败")
        error = _coerce_text(query.get("error", [""])[0]) or _coerce_text(query.get("error_description", [""])[0])
        if error:
            raise RuntimeError(f"OpenAI OAuth 授权失败：{error}")
        code = _coerce_text(query.get("code", [""])[0])
        if code:
            captured["code"] = code

    def on_request(request: Any) -> None:
        try:
            remember_callback(request.url)
        except Exception:
            pass

    page.on("request", on_request)
    try:
        try:
            page.goto(authorize_url, wait_until="domcontentloaded", timeout=60000)
        except Exception as exc:
            remember_callback(_coerce_text(getattr(page, "url", "")))
            message = str(exc)
            if not captured.get("code") and "ERR_CONNECTION_REFUSED" not in message and redirect_uri not in message:
                raise
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and not captured.get("code"):
            remember_callback(_coerce_text(getattr(page, "url", "")))
            if captured.get("code"):
                break
            page.wait_for_timeout(500)
    finally:
        try:
            page.remove_listener("request", on_request)
        except Exception:
            pass

    code = captured.get("code")
    if not code:
        hint = playwright_page_hint(page)
        raise RuntimeError(f"已登录 ChatGPT，但没有拿到 OpenAI OAuth authorization code。当前页面：{hint}")

    status, data, raw = exchange_openai_oauth_code_func(code, code_verifier, proxy_url=proxy_url)
    if status != 200:
        compact = protocol_compact_error_func(data) or raw[:260]
        raise RuntimeError(f"OpenAI OAuth token exchange 失败：HTTP {status} - {compact}")
    if not _coerce_text(data.get("refresh_token")):
        raise RuntimeError("OpenAI OAuth token exchange 成功，但返回里没有 refresh_token")
    if not _coerce_text(data.get("access_token")):
        raise RuntimeError("OpenAI OAuth token exchange 成功，但返回里没有 access_token")
    return data


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
    build_chatgpt_login_url_func: Callable[[str], str],
    generate_openai_code_verifier_func: Callable[[], str],
    build_openai_oauth_authorize_url_func: Callable[[str, str], str],
    openai_code_challenge_func: Callable[[str], str],
    playwright_proxy_options_func: Callable[[str], dict[str, str]],
    append_login_log_func: Callable[[str, str, str, str], Any],
    append_login_snapshot_log_func: Callable[[str, Any, str, str], Any],
    fetch_login_verification_code_func: Callable[..., str],
    fetch_openai_oauth_from_captured_code_func: Callable[..., dict[str, Any]],
    read_playwright_session_func: Callable[[Any], dict[str, Any]],
    merge_session_with_oauth_func: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    first_text_func: Callable[..., str],
    redirect_uri: str,
) -> dict[str, Any]:
    """执行 Playwright 登录的浏览器主流程。

    外层仍负责队列、依赖导入和 job 生命周期；这里只接管页面动作、
    OAuth code 捕获和 session 装配，所有旧入口副作用都通过注入函数执行。
    """
    password = _coerce_text(payload.get("password"))
    oauth_state = secrets.token_urlsafe(32)
    oauth_code_verifier = generate_openai_code_verifier_func()
    oauth_authorize_url = build_openai_oauth_authorize_url_func(
        oauth_state,
        openai_code_challenge_func(oauth_code_verifier),
    )
    captured_oauth: dict[str, str] = {}
    otp_request_seen = False
    otp_sent_at = 0.0
    with sync_playwright() as playwright:
        launch_options: dict[str, Any] = {
            "headless": headless,
            "args": ["--no-sandbox"],
        }
        if proxy_url:
            launch_options["proxy"] = playwright_proxy_options_func(proxy_url)
        browser = playwright.chromium.launch(
            **launch_options,
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 860},
            locale="en-US",
            timezone_id="America/New_York",
        )
        page = context.new_page()

        def remember_oauth_callback(value: str) -> None:
            parsed = urllib.parse.urlparse(value)
            if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1"}:
                return
            if parsed.port != 1455 or parsed.path != "/auth/callback":
                return
            query = urllib.parse.parse_qs(parsed.query)
            returned_state = first_text_func(query.get("state", [""])[0])
            if returned_state and returned_state != oauth_state:
                raise RuntimeError("OpenAI OAuth state 校验失败")
            error = first_text_func(query.get("error", [""])[0], query.get("error_description", [""])[0])
            if error:
                raise RuntimeError(f"OpenAI OAuth 授权失败：{error}")
            code = first_text_func(query.get("code", [""])[0])
            if code:
                captured_oauth["code"] = code

        def on_oauth_request(request: Any) -> None:
            try:
                remember_oauth_callback(request.url)
            except Exception:
                pass

        def on_login_response(response: Any) -> None:
            nonlocal otp_request_seen, otp_sent_at
            try:
                url = response.url
                if "/email-otp/" in url or "/passwordless/send-otp" in url:
                    otp_request_seen = True
                    if int(response.status) < 400:
                        otp_sent_at = time.time() - 2
                        append_login_log_func(job_id, f"OpenAI 已返回发送验证码请求：HTTP {response.status}", "info", "send_code")
                    else:
                        append_login_log_func(job_id, f"发送验证码请求返回 HTTP {response.status}", "warning", "send_code")
            except Exception:
                pass

        page.on("request", on_oauth_request)
        page.on("response", on_login_response)
        try:
            append_login_log_func(job_id, "打开 ChatGPT 登录页", "info", "identifier")
            try:
                page.goto(build_chatgpt_login_url_func(email_addr), wait_until="domcontentloaded", timeout=60000)
            except Exception:
                raise
            page.wait_for_timeout(1500)
            append_login_snapshot_log_func(job_id, page, "login-page-loaded")
            login_input_selectors = [
                "input[type=email]",
                "input[name=username]",
                "input[name=email]",
                "input#username",
                "input[autocomplete=username]",
                "input[type=text]",
            ]
            if not captured_oauth.get("code"):
                append_login_log_func(job_id, "等待 OpenAI 登录页加载或安全验证通过", "info", "security_check")
                wait_for_openai_login_ready(
                    page,
                    login_input_selectors,
                    timeout=90000,
                    job_id=job_id,
                    append_log_func=append_login_log_func,
                    append_snapshot_log_func=append_login_snapshot_log_func,
                )

            if not captured_oauth.get("code"):
                append_login_log_func(job_id, "提交邮箱", "info", "identifier")
                email_selector = first_visible_selector(page, login_input_selectors, timeout=45000)
                email_input = page.locator(email_selector).first
                email_input.click(timeout=10000)
                try:
                    email_input.fill(email_addr, timeout=10000)
                except Exception:
                    page.keyboard.press("Control+A")
                    page.keyboard.type(email_addr, delay=35)
                page.wait_for_timeout(400)
                click_first_available(page, [
                    "button[type=submit]",
                    "button:has-text('Continue')",
                    "button:has-text('继续')",
                    "button:has-text('下一步')",
                    "button:has-text('Log in')",
                    "button:has-text('登录')",
                ])
                page.wait_for_timeout(1800)
                remember_oauth_callback(_coerce_text(getattr(page, "url", "")))
                append_login_snapshot_log_func(job_id, page, "after-email-submit")
                raise_if_playwright_auth_blocked(page)

            code_selectors = [
                "input[autocomplete='one-time-code']",
                "input[name*='code' i]",
                "input[id*='code' i]",
                "input[placeholder*='code' i]",
                "input[inputmode='numeric']",
                "input[type='tel']",
                "input[type='text'][maxlength='6']",
            ]
            password_selectors = [
                "input[type=password]",
                "input[name=password]",
                "input#password",
                "input[autocomplete=current-password]",
            ]
            email_code_actions = [
                "button:has-text('Email code')",
                "button:has-text('Use email')",
                "button:has-text('Send code')",
                "button:has-text('Continue with email')",
                "button:has-text('Try another method')",
                "button:has-text('Use email code')",
                "button:has-text('Email me a code')",
                "button:has-text('Send email code')",
                "a:has-text('Email code')",
                "a:has-text('Use email')",
                "a:has-text('Use email code')",
                "a:has-text('Send code')",
                "button:has-text('邮箱验证码')",
                "button:has-text('发送验证码')",
                "button:has-text('使用邮箱')",
                "a:has-text('邮箱验证码')",
                "a:has-text('发送验证码')",
                "a:has-text('使用邮箱')",
                "text=/email code/i",
                "text=/send.*code/i",
                "text=/use.*email/i",
            ]

            code_selector = "" if captured_oauth.get("code") else optional_visible_selector(page, code_selectors, timeout=8000)
            if password and not code_selector and not captured_oauth.get("code"):
                append_login_log_func(job_id, "提交密码", "info", "password")
                password_selector = first_visible_selector(page, password_selectors, timeout=45000)
                page.fill(password_selector, password)
                click_first_available(page, [
                    "button[type=submit]",
                    "button:has-text('Continue')",
                    "button:has-text('Log in')",
                    "button:has-text('登录')",
                    "button:has-text('继续')",
                ])
                page.wait_for_timeout(2500)
                remember_oauth_callback(_coerce_text(getattr(page, "url", "")))
            elif not password and not code_selector and not captured_oauth.get("code"):
                password_selector = optional_visible_selector(page, password_selectors, timeout=1500)
                if password_selector:
                    append_login_log_func(job_id, "页面要求密码，尝试切换邮箱验证码", "warning", "send_code")
                    if wait_and_click_first_available(page, email_code_actions, timeout=10000, fallback_enter=False):
                        append_login_log_func(job_id, "已点击发送邮箱验证码", "info", "send_code")
                else:
                    append_login_log_func(job_id, "邮箱已提交，查找发送验证码入口", "info", "send_code")
                    if wait_and_click_first_available(page, email_code_actions, timeout=10000, fallback_enter=False):
                        append_login_log_func(job_id, "已点击发送邮箱验证码", "info", "send_code")
                    else:
                        append_login_log_func(job_id, "未看到单独发送验证码按钮，等待验证码输入框", "info", "send_code")
            page.wait_for_timeout(2500)
            remember_oauth_callback(_coerce_text(getattr(page, "url", "")))
            append_login_snapshot_log_func(job_id, page, "before-code-detect")
            if not captured_oauth.get("code"):
                raise_if_playwright_auth_blocked(page)

            append_login_log_func(job_id, "等待页面进入邮箱验证码步骤", "info", "waiting_code")
            if not code_selector:
                code_selector = "" if captured_oauth.get("code") else optional_visible_selector(page, code_selectors, timeout=10000 if password else 60000)
            if not code_selector and not password and not captured_oauth.get("code") and optional_visible_selector(page, password_selectors, timeout=1000):
                append_login_log_func(job_id, "页面仍在要求密码，继续尝试切换邮箱验证码", "warning", "send_code")
                if wait_and_click_first_available(page, email_code_actions, timeout=10000, fallback_enter=False):
                    append_login_log_func(job_id, "已再次点击发送邮箱验证码", "info", "send_code")
                code_selector = optional_visible_selector(page, code_selectors, timeout=45000)
            if not password and not code_selector and not captured_oauth.get("code"):
                append_login_snapshot_log_func(job_id, page, "no-code-page", "warning")
                hint = playwright_page_hint(page)
                raise RuntimeError(f"Playwright 没有进入邮箱验证码页，无法继续无密码登录。当前页面提示：{hint}")
            if code_selector:
                if otp_sent_at:
                    code_since = otp_sent_at
                elif not otp_request_seen:
                    append_login_log_func(job_id, "已出现验证码输入框，但没有捕捉到发码接口；仍将尝试查收邮箱", "warning", "send_code")
                append_login_log_func(job_id, "正在查收邮箱验证码", "warning", "waiting_code")
                code = fetch_login_verification_code_func(payload, since=code_since, attempts=20, delay=5)
                if not code:
                    raise RuntimeError("没有从本地邮箱凭证里收到验证码")
                append_login_log_func(job_id, "已取到验证码，自动提交", "info", "verify_code")
                fill_login_code(page, code_selector, code)
                click_first_available(page, [
                    "button[type=submit]",
                    "button:has-text('Continue')",
                    "button:has-text('Verify')",
                    "button:has-text('验证')",
                    "button:has-text('继续')",
                ])
                page.wait_for_timeout(3000)
                remember_oauth_callback(_coerce_text(getattr(page, "url", "")))

            if not captured_oauth.get("code"):
                append_login_log_func(job_id, "确认 ChatGPT 已登录，准备打开 OAuth 授权页", "info", "oauth")
                if not wait_for_chatgpt_logged_in(page, timeout=90000):
                    hint = playwright_page_hint(page)
                    raise RuntimeError(f"验证码提交后没有进入 ChatGPT 登录态，无法继续 OAuth 授权。当前页面提示：{hint}")
                append_login_log_func(job_id, "打开 OpenAI OAuth 授权页获取 RT", "info", "oauth")
                try:
                    page.goto(oauth_authorize_url, wait_until="domcontentloaded", timeout=60000)
                except Exception as exc:
                    remember_oauth_callback(_coerce_text(getattr(page, "url", "")))
                    message = str(exc)
                    if not captured_oauth.get("code") and "ERR_CONNECTION_REFUSED" not in message and redirect_uri not in message:
                        raise
                page.wait_for_timeout(1500)
                remember_oauth_callback(_coerce_text(getattr(page, "url", "")))

            append_login_log_func(job_id, "换取 OpenAI OAuth refresh_token", "info", "oauth")
            oauth_payload = fetch_openai_oauth_from_captured_code_func(
                captured_oauth,
                oauth_code_verifier,
                page,
                proxy_url=proxy_url,
            )
            session: dict[str, Any] = {}
            try:
                append_login_log_func(job_id, "读取 ChatGPT Session", "info", "session")
                session = read_playwright_session_func(context)
            except Exception as exc:
                append_login_log_func(job_id, f"ChatGPT Session 暂不可读，使用 OAuth token 继续转换：{str(exc)[:180]}", "warning", "session")
            session = merge_session_with_oauth_func(session, oauth_payload)
            if not first_text_func(session.get("email"), session.get("user", {}).get("email") if isinstance(session.get("user"), dict) else ""):
                session["email"] = email_addr
                session["user"] = {**(session.get("user") if isinstance(session.get("user"), dict) else {}), "email": email_addr}
            return session
        except PlaywrightTimeoutError as exc:
            try:
                append_login_snapshot_log_func(job_id, page, "playwright-timeout", "warning")
            except Exception:
                pass
            raise RuntimeError(f"登录页面等待超时：{exc}") from exc
        except Exception:
            try:
                append_login_snapshot_log_func(job_id, page, "playwright-error", "warning")
            except Exception:
                pass
            raise
        finally:
            try:
                page.remove_listener("request", on_oauth_request)
            except Exception:
                pass
            try:
                page.remove_listener("response", on_login_response)
            except Exception:
                pass
            context.close()
            browser.close()


def run_chatgpt_login_with_playwright(
    job_id: str,
    payload: dict[str, Any],
    *,
    playwright_semaphore: Any,
    playwright_max_concurrency: int,
    request_proxy_url_func: Callable[[dict[str, Any] | None], str],
    append_login_log_func: Callable[[str, str, str, str], Any],
    unlocked_login_func: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """执行 Playwright 登录的外层队列和依赖导入。

    真正的页面动作仍由 unlocked 主流程处理；这一层只负责可选依赖提示、并发控制和
    运行时参数准备，让旧 `server.py` 不再直接承载浏览器队列逻辑。
    """
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(
            "VPS 还没安装 Playwright/Chromium，不能真正一键自动填 ChatGPT 登录。"
            "安装：python3 -m pip install playwright && python3 -m playwright install chromium"
        ) from exc

    email_addr = _coerce_text(payload.get("email"))
    if not email_addr:
        raise RuntimeError("Playwright 登录需要邮箱")

    headless = str(payload.get("headless", "1")).lower() not in {"0", "false", "no"}
    proxy_url = request_proxy_url_func(payload)
    code_since = time.time()
    append_login_log_func(job_id, f"等待浏览器槽位（最多并发 {playwright_max_concurrency}）", "info", "browser_queue")
    acquired = playwright_semaphore.acquire(timeout=180)
    if not acquired:
        raise RuntimeError("浏览器登录队列繁忙，请稍后重试")
    try:
        append_login_log_func(job_id, "已获得浏览器槽位", "info", "browser_queue")
        return unlocked_login_func(
            job_id,
            payload,
            sync_playwright,
            PlaywrightTimeoutError,
            email_addr=email_addr,
            headless=headless,
            proxy_url=proxy_url,
            code_since=code_since,
        )
    finally:
        playwright_semaphore.release()


def run_chatgpt_signup_with_playwright(
    job_id: str,
    payload: dict[str, Any],
    sync_playwright: Any | None = None,
    PlaywrightTimeoutError: Any | None = None,
    *,
    request_proxy_url_func: Callable[[dict[str, Any] | None], str],
    user_agent: str,
    playwright_proxy_options_func: Callable[[str], dict[str, str]],
    append_login_log_func: Callable[[str, str, str, str], Any],
    fetch_registration_verification_link_func: Callable[..., str],
    fetch_openai_oauth_with_playwright_func: Callable[..., dict[str, Any]],
    merge_session_with_oauth_func: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """执行 Playwright 注册主流程。

    这里只接管 Playwright 可选依赖导入、注册页动作、确认邮件验证链接、
    会话读取和 OAuth 装配；外层继续负责任务生命周期和兼容入口转发。
    """
    import secrets
    if sync_playwright is None or PlaywrightTimeoutError is None:
        try:
            from playwright.sync_api import TimeoutError as imported_timeout_error
            from playwright.sync_api import sync_playwright as imported_sync_playwright
        except Exception as exc:
            raise RuntimeError(
                "VPS 还没安装 Playwright/Chromium，不能进行自动化注册。"
                "安装：python3 -m pip install playwright && python3 -m playwright install chromium"
            ) from exc
        sync_playwright = imported_sync_playwright
        PlaywrightTimeoutError = imported_timeout_error
    email_addr = _coerce_text(payload.get("email"))
    password = _coerce_text(payload.get("password"))
    if not email_addr:
        raise RuntimeError("一键注册需要邮箱账号")
    if not password:
        # 自动生成随机强密码
        password = secrets.token_urlsafe(10) + "aA1!"

    headless = str(payload.get("headless", "1")).lower() not in {"0", "false", "no"}
    proxy_url = request_proxy_url_func(payload)
    code_since = time.time()

    with sync_playwright() as playwright:
        launch_options: dict[str, Any] = {
            "headless": headless,
            "args": ["--no-sandbox"],
        }
        if proxy_url:
            launch_options["proxy"] = playwright_proxy_options_func(proxy_url)
        browser = playwright.chromium.launch(**launch_options)
        context = browser.new_context(
            viewport={"width": 1280, "height": 860},
            user_agent=user_agent,
            locale="zh-CN",
        )
        page = context.new_page()
        try:
            append_login_log_func(job_id, "打开 ChatGPT 注册页", "info", "signup_start")
            page.goto("https://chatgpt.com/auth/signup", wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(1500)

            append_login_log_func(job_id, f"填入注册邮箱: {email_addr}", "info", "email_input")
            email_selector = first_visible_selector(page, [
                "input[type=email]",
                "input[name=username]",
                "input[name=email]",
                "input#username",
                "input[autocomplete=username]",
                "input[type=text]",
            ], timeout=45000)
            page.fill(email_selector, email_addr)

            click_first_available(page, [
                "button[type=submit]",
                "button:has-text('Continue')",
                "button:has-text('继续')",
                "button:has-text('下一步')",
            ])
            page.wait_for_timeout(2000)

            append_login_log_func(job_id, "设置并提交密码", "info", "password_input")
            password_selector = first_visible_selector(page, [
                "input[type=password]",
                "input[name=password]",
                "input#password",
                "input[autocomplete=new-password]",
            ], timeout=45000)
            page.fill(password_selector, password)

            click_first_available(page, [
                "button[type=submit]",
                "button:has-text('Continue')",
                "button:has-text('继续')",
            ])
            page.wait_for_timeout(3000)

            append_login_log_func(job_id, "等待注册确认邮件...", "warning", "waiting_email")
            verification_link = fetch_registration_verification_link_func(
                payload,
                since=code_since,
            )
            if not verification_link:
                raise RuntimeError("超时未收到注册确认邮件，请检查邮箱是否能正常收件")

            append_login_log_func(job_id, "收到确认邮件，正在打开验证链接", "info", "email_verified")
            page.goto(verification_link, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(2500)

            # 完善个人资料
            try:
                first_name_sel = "input[name='firstName'], input[placeholder*='First' i]"
                page.wait_for_selector(first_name_sel, timeout=10000)
                append_login_log_func(job_id, "正在完善个人基本信息...", "info", "profile_input")
                page.fill(first_name_sel, "Aiden")
                page.fill("input[name='lastName'], input[placeholder*='Last' i]", "Smith")

                birthday_sel = "input[name='birthday'], input[placeholder*='Birthday' i], input[type='date']"
                if page.locator(birthday_sel).count():
                    page.fill(birthday_sel, "1995-05-15")

                click_first_available(page, [
                    "button[type=submit]",
                    "button:has-text('Agree')",
                    "button:has-text('Continue')",
                    "button:has-text('继续')",
                    "button:has-text('同意')",
                ])
                page.wait_for_timeout(3000)
            except Exception:
                pass

            # 检测是否强制要求手机号接码
            phone_sel = "input[type='tel'], input[placeholder*='phone' i], input[name*='phone' i]"
            if page.locator(phone_sel).count() and page.locator(phone_sel).first.is_visible():
                append_login_log_func(job_id, "需要手机验证，已按失败处理。", "error", "phone_verification_required")
                raise RuntimeError("需要手机验证，已按失败处理。")

            append_login_log_func(job_id, "读取注册成功后的会话...", "info", "fetch_session")
            page.goto("https://chatgpt.com/api/auth/session", wait_until="networkidle", timeout=60000)
            content = page.locator("body").inner_text(timeout=15000)
            session = json.loads(content)
            if not isinstance(session, dict) or not session.get("accessToken"):
                raise RuntimeError("注册成功但未能自动获取 accessToken 会话")

            append_login_log_func(job_id, "换取 OpenAI OAuth refresh_token", "info", "oauth")
            oauth_payload = fetch_openai_oauth_with_playwright_func(page, proxy_url=proxy_url)
            session = merge_session_with_oauth_func(session, oauth_payload)
            session["registration_password"] = password
            return session
        except PlaywrightTimeoutError as exc:
            raise RuntimeError(f"注册页面操作超时：{exc}") from exc
        finally:
            context.close()
            browser.close()

def click_first_available(page: Any, selectors: list[str], *, fallback_enter: bool = True) -> bool:
    """点击第一个真正可见的按钮或链接。

    这里不关心按钮点击后的业务含义，只负责按既有优先级尝试 selector；
    如果页面上没有任何目标控件，再按旧逻辑决定是否回退成回车提交。
    """
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            if locator.count() and locator.is_visible(timeout=1200):
                locator.click(timeout=5000, no_wait_after=True)
                return True
        except Exception:
            continue
    if fallback_enter:
        page.keyboard.press("Enter")
        return True
    return False


def wait_and_click_first_available(
    page: Any,
    selectors: list[str],
    *,
    timeout: int = 10000,
    fallback_enter: bool = False,
) -> bool:
    """在一段等待窗口内反复尝试点击目标控件。

    登录页的“继续/发送验证码/改用邮箱验证码”按钮经常延迟渲染，这里只做
    轮询点击，不写日志、不推进任务状态，保持为可复用的页面动作 helper。
    """
    deadline = time.monotonic() + (timeout / 1000)
    while time.monotonic() < deadline:
        if click_first_available(page, selectors, fallback_enter=False):
            return True
        page.wait_for_timeout(500)
    if fallback_enter:
        page.keyboard.press("Enter")
        return True
    return False


def build_playwright_login_url(*, login_url: str) -> str:
    """返回 Playwright 登录流程起始页 URL。"""
    return login_url


def raise_if_playwright_auth_blocked(page: Any) -> None:
    """检测当前页面是否已经落入风控/挑战/错误页。"""
    current_url = _coerce_text(getattr(page, "url", ""))
    hint = playwright_page_hint(page)
    lowered_hint = hint.lower()
    if any(
        marker in lowered_hint
        for marker in [
            "operation timed out",
            "unexpected token '<'",
            "cloudflare",
            "cf-ray",
            "糟糕",
        ]
    ):
        if is_openai_security_verification_text(hint):
            raise openai_turnstile_error(hint or current_url)
        raise RuntimeError(
            "OpenAI 登录邮箱提交接口被当前 VPS/代理出口风控拦截，未进入邮箱验证码页。"
            "这不是邮箱收件失败，也不是临时邮箱 JWT 问题；请更换能通过 auth.openai.com 的干净代理或出口后重试。"
            f"当前页面提示：{hint[:220]}"
        )
    if "/api/auth/error" in current_url:
        raise RuntimeError(
            "ChatGPT 登录入口进入 /api/auth/error。当前 VPS 或代理出口被 OpenAI/Cloudflare 风控拦截，"
            "还没有进入邮箱验证码阶段；请更换干净出口或使用可通过挑战的登录环境。"
        )
    lowered_url = current_url.lower()
    if any(marker in lowered_url for marker in ["challenge", "turnstile", "captcha"]):
        raise RuntimeError(
            "ChatGPT 登录入口出现人机验证/挑战页。当前自动刷新不能继续；请更换稳定代理或干净出口。"
        )
    try:
        has_turnstile = page.locator("input[name='cf-turnstile-response'], iframe[src*='turnstile']").count() > 0
    except Exception:
        has_turnstile = False
    if has_turnstile:
        raise openai_turnstile_error(playwright_page_hint(page) or current_url)


__all__ = [
    "build_playwright_login_url",
    "click_first_available",
    "fill_login_code",
    "fetch_openai_oauth_with_playwright",
    "fetch_openai_oauth_from_captured_code",
    "first_visible_selector",
    "is_openai_security_verification_text",
    "login_page_snapshot",
    "save_login_debug_snapshot",
    "append_login_snapshot_log",
    "optional_visible_selector",
    "playwright_page_hint",
    "raise_if_playwright_auth_blocked",
    "read_playwright_session",
    "wait_and_click_first_available",
    "wait_for_openai_login_ready",
    "wait_for_chatgpt_logged_in",
]
