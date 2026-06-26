"""登录域的错误模型和失败归类。

这里只做失败语义收敛：把协议登录、人机验证、代理异常、状态码异常
压成稳定的业务错误，方便上层统一展示和后续判断是否可重试。
"""
from __future__ import annotations

import re
from typing import Any, Callable


def _coerce_text(value: Any) -> str:
    return str(value or "").strip()


class LoginFlowError(RuntimeError):
    """登录流程里的可预期失败。

    这类错误不是程序崩溃，而是业务上能识别、能提示、能决定是否重试的
    失败出口。上层可以直接用 code/hint/status/retryable 做统一处理。
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "login_failed",
        hint: str = "",
        status: int | None = None,
        retryable: bool = True,
    ):
        super().__init__(message)
        self.code = code
        self.hint = hint
        self.status = status
        self.retryable = retryable


def openai_turnstile_error(hint: str = "") -> LoginFlowError:
    """把 Cloudflare / Turnstile 卡点压成统一的登录失败。"""
    detail = _coerce_text(hint).strip()
    message = "OpenAI 登录入口停在人机验证页，邮箱验证码尚未发送。"
    if detail:
        message = f"{message} 当前页面：{detail[:220]}"
    return LoginFlowError(
        message,
        code="openai_turnstile_challenge",
        hint="协议登录还没有进入邮箱输入/验证码阶段，也没有发码请求。请检查当前 CPA OAuth 授权入口、代理出口和 auth.openai.com 会话状态。",
        retryable=True,
    )


def classify_login_exception(
    exc: Exception,
    *,
    looks_like_html_challenge_func: Callable[[str], bool] | None = None,
    html_challenge_hint_func: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """把登录链路异常归类成稳定 code/hint/retryable 结构。

    这里只做纯文本归类，不读取任务状态、不写日志、不发起网络请求；HTML
    风控页摘要通过注入函数提供，避免错误模型反向依赖协议实现。
    """
    if isinstance(exc, LoginFlowError):
        return {
            "message": str(exc),
            "code": exc.code,
            "hint": exc.hint,
            "status": exc.status,
            "retryable": exc.retryable,
        }
    message = str(exc)
    lowered = message.lower()
    code = "login_failed"
    hint = ""
    retryable = True
    status = None
    match = re.search(r"http\s+(\d{3})", lowered)
    if match:
        try:
            status = int(match.group(1))
        except ValueError:
            status = None
    if (
        "凭证刷新必须填写代理" in message
        or "proxy required" in lowered
    ):
        return {
            "message": "凭证刷新必须填写代理 URL",
            "code": "proxy_required",
            "hint": "示例：http://USER:PASS@host:port 或 socks5://USER:PASS@host:port；VPS 部署时要填 VPS 能访问到的代理地址。",
            "status": status,
            "retryable": False,
        }
    if (
        "代理格式错误" in message
        or "代理端口格式错误" in message
        or "port could not be cast" in lowered
        or "failed to parse" in lowered and "proxy" in lowered
    ):
        code = "proxy_format_invalid"
        message = "代理格式错误：请使用 http://用户名:密码@host:port，不能写成 http://host:port:用户名:密码。"
        hint = "例如：http://USER:PASS@us.rrp.bestgo.work:10000；如果用 SOCKS，则写 socks5://USER:PASS@host:port。"
        retryable = False
        return {
            "message": message,
            "code": code,
            "hint": hint,
            "status": status,
            "retryable": retryable,
        }
    if (
        "服务器 dns 解析失败" in lowered
        or "temporary failure in name resolution" in lowered
        or "name or service not known" in lowered
        or "getaddrinfo failed" in lowered
    ):
        return {
            "message": "DNS 解析失败：VPS 或代理无法解析目标域名。",
            "code": "dns_failed",
            "hint": "这是网络基础问题，不是账号或邮箱问题。请检查 VPS DNS、代理 DNS 转发，或更换可解析 auth.openai.com / chatgpt.com 的代理出口。",
            "status": status,
            "retryable": True,
        }
    if (
        "unexpected_eof_while_reading" in lowered
        or "eof occurred in violation of protocol" in lowered
        or "代理 tls 连接被中断" in lowered
    ):
        return {
            "message": "代理 TLS 中断：代理出口没有稳定完成 HTTPS 握手。",
            "code": "proxy_tls_eof",
            "hint": "这不是账号失败，也不是邮箱收不到码；是代理到目标站的 TLS 连接被截断。请换代理出口，或检查代理协议/账号是否稳定。",
            "status": status,
            "retryable": True,
        }
    if (
        "代理连接超时" in lowered
        or "timed out" in lowered
        or "timeout" in lowered
        or "winerror 10060" in lowered
        or "没有正确答复" in message
        or "连接尝试失败" in message
    ):
        return {
            "message": "代理超时：代理出口响应太慢或不可用。",
            "code": "proxy_timeout",
            "hint": "请更换更稳定的代理，或降低批量数量后重试。",
            "status": status,
            "retryable": True,
        }
    if (
        "代理连接失败" in lowered
        or "connection reset" in lowered
        or "connection refused" in lowered
        or "remote end closed connection" in lowered
        or "without response" in lowered
        or "tunnel connection failed" in lowered
        or "cannot connect to proxy" in lowered
        or "proxy error" in lowered
        or "socks" in lowered and ("failed" in lowered or "error" in lowered)
    ):
        return {
            "message": "代理连接失败：当前代理出口不可用或被目标站断开。",
            "code": "proxy_connection_failed",
            "hint": "请确认代理 URL、用户名密码、协议类型正确，并更换稳定出口后重试。",
            "status": status,
            "retryable": True,
        }
    if "invalid_auth_step" in lowered or "invalid authorization step" in lowered:
        code = "oauth_invalid_auth_step"
        message = "OpenAI OAuth 步骤状态不匹配：授权会话还没有进入可提交邮箱的步骤。"
        hint = "这不是邮箱收信问题；请使用当前版本重新执行。若仍出现，请保留前面的 OAuth 跳转日志，用来确认是否继续跟随了 continue_url。"
        retryable = True
        return {
            "message": message,
            "code": code,
            "hint": hint,
            "status": status,
            "retryable": retryable,
        }
    if "did not return callback code" in lowered or "no continue url returned" in lowered or "没有返回可继续的 oauth 地址" in lowered:
        if any(marker in lowered for marker in [
            "phone_otp",
            "phone-otp",
            "phone verification",
            "phone-verification",
            "select-channel",
            "mfa",
            "sms",
            "手机",
        ]):
            return {
                "message": "手机二次验证未完成，已按失败处理。",
                "code": "phone_2fa_failed",
                "hint": "邮箱验证码已经通过，但 OAuth 后续进入了手机短信二次验证；需要长效手机 API 或手动输入本轮短信验证码。",
                "status": status,
                "retryable": False,
            }
        return {
            "message": "OAuth 授权回调未完成，已按失败处理。",
            "code": "oauth_callback_missing",
            "hint": "邮箱验证码已经提交，但授权链路没有拿到 callback code。通常是代理会话中途失效、账号进入额外验证，或授权页面没有继续跳转。",
            "status": status,
            "retryable": True,
        }
    if "unauthorized" in lowered or status == 401:
        return {
            "message": "授权失败或凭证已失效，已按失败处理。",
            "code": "authorization_failed",
            "hint": "目标接口返回未授权。请检查 CPA 管理密钥、OAuth 授权会话或已保存凭证是否已失效。",
            "status": status,
            "retryable": True,
        }
    if (
        "mfa_required" in lowered
        or "phone_2fa" in lowered
        or "two-factor" in lowered
        or "second factor" in lowered
        or "phone verification" in lowered
        or "phone number" in lowered
        or "mobile" in lowered
        or "手机号" in message
        or "手机验证" in message
        or "二次验证" in message
        or "接码" in message
    ):
        return {
            "message": "手机二次验证失败，已按失败处理。",
            "code": "phone_2fa_failed",
            "hint": "账号进入了手机二次验证，但没有完成短信验证码校验。请绑定长效手机 API，或在任务运行时手动输入手机验证码后重试。",
            "status": status,
            "retryable": False,
        }
    if (
        "deactivated" in lowered
        or "account disabled" in lowered
        or "disabled account" in lowered
        or "banned" in lowered
        or "suspended" in lowered
        or "deleted account" in lowered
        or "account deleted" in lowered
        or "账号被封" in message
        or "账号封禁" in message
        or "账号停用" in message
        or "已停用" in message
        or "被禁用" in message
    ):
        return {
            "message": "账号被封禁或停用，已按失败处理。",
            "code": "account_banned",
            "hint": "目标站返回账号停用/封禁/禁用信号，这类账号不再继续自动刷新。",
            "status": status,
            "retryable": False,
        }
    if (
        "invalid verification code" in lowered
        or "invalid email code" in lowered
        or "invalid otp" in lowered
        or "incorrect code" in lowered
        or "code expired" in lowered
        or "expired code" in lowered
        or "email code verify failed" in lowered
        or "验证码无效" in message
        or "验证码错误" in message
        or "验证码已过期" in message
        or "验证码过期" in message
    ):
        return {
            "message": "验证码无效或已过期，已按失败处理。",
            "code": "verification_code_invalid",
            "hint": "已经进入邮箱验证码阶段，但提交的验证码被目标站拒绝；通常是验证码过期、重复使用或邮箱里取到旧码。",
            "status": status,
            "retryable": True,
        }
    if (
        "user not found" in lowered
        or "account not found" in lowered
        or "no account" in lowered
        or "账号不存在" in message
        or "账户不存在" in message
    ):
        return {
            "message": "账号不存在或未注册，已按失败处理。",
            "code": "account_not_found",
            "hint": "目标站没有识别出这个邮箱对应的登录账号。",
            "status": status,
            "retryable": False,
        }
    if (
        "openai_turnstile_challenge" in lowered
        or "人机验证页" in message
        or "turnstile" in lowered
        or "performing security verification" in lowered
        or "protect against malicious bots" in lowered
    ):
        code = "openai_turnstile_challenge"
        hint = "当前真实浏览器被 OpenAI/Cloudflare 人机验证拦住，邮箱验证码尚未发送；请查看页面快照。自动查邮箱只有在出现验证码输入框或捕捉到发码请求后才会开始。"
        retryable = True
        return {
            "message": message[:800],
            "code": code,
            "hint": hint,
            "status": status,
            "retryable": retryable,
        }
    if "还没有发送验证码" in message or "没有渲染出邮箱输入框" in message:
        code = "login_page_not_ready"
        hint = "OpenAI 登录页还没有进入可发送邮箱验证码的状态；请查看页面快照确认是空白加载、安全验证，还是代理出口拦截。"
        retryable = True
        return {
            "message": message[:800],
            "code": code,
            "hint": hint,
            "status": status,
            "retryable": retryable,
        }
    if "安全验证页" in message or "没有进入邮箱验证码页" in message:
        code = "openai_security_verification"
        hint = "OpenAI 登录入口还停在安全验证页，没有发送邮箱验证码。协议登录不会自动切换其他方案，请更换可通过 auth.openai.com 安全验证的出口后重试。"
        retryable = True
        return {
            "message": "OpenAI 登录入口停在安全验证页，没有发送邮箱验证码。",
            "code": code,
            "hint": hint,
            "status": status,
            "retryable": retryable,
        }
    if "openai 登录邮箱提交接口被当前" in message or "未进入邮箱验证码页" in message:
        code = "openai_auth_risk_blocked"
        hint = "OpenAI 登录页在提交邮箱时返回风控/拒绝页；请更换能通过 auth.openai.com 的代理或出口后重试。"
        retryable = True
        return {
            "message": message[:800],
            "code": code,
            "hint": hint,
            "status": status,
            "retryable": retryable,
        }
    if "csrf" in lowered or "could not validate your token" in lowered:
        code = "csrf_or_risk_blocked"
        if looks_like_html_challenge_func and looks_like_html_challenge_func(message):
            message = html_challenge_hint_func(message) if html_challenge_hint_func else message
        hint = "ChatGPT 拒绝了当前服务端出口。请使用 VPS 可访问的稳定代理后重试；如果是 socks5://，VPS 还需要安装 PySocks。"
    elif "cloudflare" in lowered or "access denied" in lowered or "unable to load site" in lowered or "vpn" in lowered:
        code = "risk_blocked"
        if looks_like_html_challenge_func and looks_like_html_challenge_func(message):
            message = html_challenge_hint_func(message) if html_challenge_hint_func else message
        hint = "目标站点拒绝当前网络出口。协议登录不会自动切换其他方案，请更换干净代理或 VPS 出口后重试。"
    elif "unsupported_country_region_territory" in lowered or "country, region, or territory not supported" in lowered:
        code = "unsupported_country_region_territory"
        message = "OpenAI OAuth 拒绝当前后端出口：所在国家/地区不受支持。"
        hint = "这一步还没有到邮箱验证码，也不是邮箱/JWT问题。请看“当前后端出口”日志，换成 OpenAI 支持地区的 HTTP 代理或 VPS 出口后重试。"
    elif "err_connection_closed" in lowered or "connection closed" in lowered or "net::err" in lowered:
        code = "login_network_blocked"
        message = "ChatGPT 登录入口连接被中途断开，当前 VPS/代理出口没有稳定打开登录页。"
        hint = "这一步还没到邮箱验证码；请换一个 VPS 能直连的代理出口，再重试浏览器验证码模式。"
    elif "incompleteread" in lowered or "incomplete read" in lowered or "响应没有读完整" in message:
        code = "network_incomplete_read"
        message = "代理或目标站连接中途断开，响应没有读完整。请重试；如果连续出现，请更换更稳定的代理出口。"
        hint = "这不是邮箱收不到验证码，而是 ChatGPT 登录请求的网络连接被截断。"
    elif (
        "没安装 playwright" in message
        or "缺少 playwright" in message
        or "vps 还没安装 playwright" in message.lower()
        or "browserType.launch" in message
        or "executable doesn't exist" in lowered
        or "chromium" in lowered
    ):
        code = "playwright_unavailable"
        hint = "服务器缺少 Playwright/Chromium，安装后才能走浏览器登录。"
        retryable = False
    elif "playwright" in lowered:
        code = "playwright_login_failed"
        hint = "浏览器登录已经启动，但没有走到可提交验证码的页面。请检查代理出口是否稳定、账号是否被要求额外验证。"
    elif "password" in lowered or "密码" in message:
        code = "password_or_login_failed"
        hint = "请确认导入的是 OpenAI 登录密码，不是邮箱客户端密钥。"
    elif "verification code" in lowered or "验证码" in message:
        code = "verification_code_missing"
        hint = "登录已进入验证码阶段，但本地邮箱没有取到新验证码。请先确认邮箱同步可收信。"
    return {
        "message": message[:800],
        "code": code,
        "hint": hint,
        "status": status,
        "retryable": retryable,
    }


__all__ = [
    "LoginFlowError",
    "classify_login_exception",
    "openai_turnstile_error",
]
