"""登录邮箱/短信验证码提取与轮询。

这里只负责从邮件结果、短信接口结果里提取验证码，并按登录任务状态做
轮询与日志输出。邮件抓取、短信 HTTP 查询和远程地址校验都由上层注入，
这样登录域不用把外部 I/O 规则写死在模块里。
"""
from __future__ import annotations

import html
import json
import re
import time
import urllib.parse
from typing import Any, Callable

from gpt_account_manager.storage.messages import (
    message_sort_value,
    parse_message_datetime,
)

from .jobs import (
    append_login_log,
    manual_email_code_for_payload,
    raise_if_login_job_cancelled,
)


SMS_CODE_PATTERN = re.compile(r"\b\d{4,8}\b")
SMS_EMPTY_PATTERN = re.compile(r"^(?:no\s*(?:sms|message)|empty|none|null|暂无|没有|未收到)$", re.I)
SMS_GENERIC_OK_PATTERN = re.compile(r"^(?:ok|success|successful|true|请求成功|成功)$", re.I)
SMS_MESSAGE_FIELDS = {
    "data",
    "message",
    "msg",
    "content",
    "text",
    "body",
    "sms",
    "otp",
    "code",
    "verifycode",
    "verificationcode",
    "captcha",
    "result",
    "value",
}
SMS_IGNORE_FIELDS = {"status", "statuscode", "httpstatus", "ret", "errno", "errorcode"}


def _coerce_text(value: Any) -> str:
    return str(value or "").strip()


def _strip_html(value: str) -> str:
    """把 HTML 简单压成纯文本，给验证码提取做兜底。"""
    clean = re.sub(r"<style.*?</style>", " ", value, flags=re.I | re.S)
    clean = re.sub(r"<script.*?</script>", " ", clean, flags=re.I | re.S)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = html.unescape(clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean


def _extract_six_digit_codes(text: str) -> list[str]:
    return re.findall(r"(?<!\d)(\d{6})(?!\d)", text)


def normalize_sms_field_name(value: str) -> str:
    """把短信接口字段名压成稳定格式，便于跨供应商匹配。"""
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def collect_sms_candidates(value: Any, key: str = "", depth: int = 0) -> list[dict[str, Any]]:
    """从任意短信接口响应里提取候选文本，交给上层统一打分。"""
    if value is None or depth > 6:
        return []
    key_norm = normalize_sms_field_name(key)
    if key_norm in SMS_IGNORE_FIELDS:
        return []
    if isinstance(value, str):
        text = value.strip()
        candidates = []
        if text and len(text) <= 800:
            candidates.append({
                "text": text,
                "key": key_norm,
                "depth": depth,
                "preferred": key_norm in SMS_MESSAGE_FIELDS,
            })
        if text and text[:1] in "{[":
            try:
                candidates.extend(collect_sms_candidates(json.loads(text), key, depth + 1))
            except Exception:
                pass
        return candidates
    if isinstance(value, (int, float)):
        if key_norm in {"otp", "smscode", "verifycode", "verificationcode", "captcha", "code"}:
            return [{
                "text": str(int(value)),
                "key": key_norm,
                "depth": depth,
                "preferred": True,
            }]
        return []
    if isinstance(value, list):
        out: list[dict[str, Any]] = []
        for item in value:
            out.extend(collect_sms_candidates(item, key, depth + 1))
        return out
    if isinstance(value, dict):
        out: list[dict[str, Any]] = []
        for child_key, child_value in value.items():
            out.extend(collect_sms_candidates(child_value, str(child_key), depth + 1))
        return out
    return []


def extract_sms_code_payload(raw_payload: Any) -> dict[str, str]:
    """从短信接口响应里提取验证码和最可读的原始文本。"""
    candidates = collect_sms_candidates(raw_payload)
    scored: list[tuple[int, dict[str, Any], str]] = []
    for candidate in candidates:
        text = _coerce_text(candidate.get("text"))
        if not text or SMS_EMPTY_PATTERN.fullmatch(text) or SMS_GENERIC_OK_PATTERN.fullmatch(text):
            continue
        code_match = SMS_CODE_PATTERN.search(text)
        code = code_match.group(0) if code_match else ""
        score = (100 if code else 0) + (30 if candidate.get("preferred") else 0)
        if re.search(r"code|verify|verification|otp|openai|chatgpt|验证码|安全", text, re.I):
            score += 20
        score -= int(candidate.get("depth") or 0)
        scored.append((score, candidate, code))
    if scored:
        scored.sort(key=lambda item: item[0], reverse=True)
        _, candidate, code = scored[0]
        return {"code": code, "message": _coerce_text(candidate.get("text"))}
    fallback = next((_coerce_text(item.get("text")) for item in candidates if _coerce_text(item.get("text"))), "")
    return {"code": "", "message": fallback}


def fetch_registration_verification_link(
    payload: dict[str, Any],
    *,
    since: float = 0,
    attempts: int = 15,
    delay: float = 6,
    fetch_transient_client_mail_func: Callable[[dict[str, Any]], dict[str, Any]],
) -> str:
    """自动从收件箱获取 OpenAI 注册验证邮件并解析出验证链接"""
    pattern = re.compile(r'https://[a-zA-Z0-9.-]*openai\.com/[^\s"\'<>]*email-verification[^\s"\'<>]*')
    for _ in range(max(1, attempts)):
        try:
            data = fetch_transient_client_mail_func({
                "source": "all",
                "provider": "auto",
                "sender_filter": "openai",
                "limit": payload.get("limit", 20),
                "emails": [payload.get("email", "")],
                "accounts": payload.get("accounts", []),
                "temp_addresses": payload.get("temp_addresses", []),
                "generic_accounts": payload.get("generic_accounts", []),
            })
            messages = data.get("messages") or []
            sorted_messages = sorted(messages, key=message_sort_value, reverse=True)
            for msg in sorted_messages:
                received_at = _coerce_text(msg.get("received_at"))
                if since and received_at:
                    parsed = parse_message_datetime(received_at)
                    if parsed and parsed.timestamp() + 30 < since:
                        continue

                body_content = _coerce_text(msg.get("html") or msg.get("body") or "")
                match = pattern.search(body_content)
                if match:
                    link = match.group(0)
                    link = link.replace("&amp;", "&")
                    return link
        except Exception:
            pass
        time.sleep(delay)
    return ""


def normalize_phone_digits(value: Any) -> str:
    """把手机号提示压成纯数字，方便做尾号匹配。"""
    return re.sub(r"\D+", "", _coerce_text(value))


def extract_phone_hint_from_text(value: Any) -> str:
    """从页面文案或接口文本里提取手机号尾号提示。"""
    text = _coerce_text(value)
    if not text:
        return ""
    patterns = [
        r"(?:ending\s+in|ends\s+in|last\s+\d*\s*digits?|尾号|末尾|手机|手机号|电话|phone|mobile|sms)[^\d+*xX•]{0,40}(\+?\d[\d\s().-]{1,22}\d|[*xX•]{2,}\s*\d{2,6}|\d{2,6})",
        r"(\+\d[\d\s().-]{6,22}\d)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.I)
        if match:
            digits = normalize_phone_digits(match.group(1))
            if len(digits) >= 2:
                return digits
    return ""


def extract_phone_hint_from_step(data: Any, continue_url: str = "") -> str:
    """从登录步骤数据里归纳手机号提示，兼容 dict/list/string 混合结构。"""
    texts: list[str] = []
    seen = 0

    def visit(value: Any, key_hint: str = "") -> None:
        nonlocal seen
        if seen > 120:
            return
        seen += 1
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = _coerce_text(key)
                if re.search(r"phone|mobile|sms|mfa|factor|verification|otp|channel|手机|号码", key_text, re.I):
                    texts.append(f"{key_text}: {_coerce_text(item)}")
                visit(item, key_text)
        elif isinstance(value, list):
            for item in value[:80]:
                visit(item, key_hint)
        elif isinstance(value, str):
            if key_hint or re.search(r"phone|mobile|sms|mfa|otp|channel|手机|号码|\+\d|尾号|ending\s+in", value, re.I):
                texts.append(value)

    visit(data)
    if continue_url:
        texts.append(continue_url)
    for text in texts:
        hint = extract_phone_hint_from_text(text)
        if hint:
            return hint
    return ""


def phone_pool_entries_from_payload(payload: dict[str, Any]) -> list[dict[str, str]]:
    """把 phone_pool 输入规整成统一条目，方便后续按 hint 匹配。"""
    raw_entries = payload.get("phone_pool") or payload.get("phonePool") or []
    if not isinstance(raw_entries, list):
        return []
    entries: list[dict[str, str]] = []
    for item in raw_entries:
        if not isinstance(item, dict):
            continue
        phone = _coerce_text(item.get("phone") or item.get("phone_number") or item.get("phoneNumber"))
        api_url = _coerce_text(item.get("api_url") or item.get("apiUrl") or item.get("phone_api_url") or item.get("phoneApiUrl"))
        if not phone or not api_url:
            continue
        entries.append({
            "id": _coerce_text(item.get("id")),
            "mode": _coerce_text(item.get("mode")),
            "phone": phone,
            "phone_digits": normalize_phone_digits(phone),
            "api_url": api_url,
            "account_email": _coerce_text(item.get("account_email") or item.get("accountEmail")).lower(),
        })
    return entries


def phone_pool_match_by_hint(entries: list[dict[str, str]], hint: str) -> dict[str, str] | None:
    """按完整号码或尾号从 phone_pool 里找唯一匹配项。"""
    hint_digits = normalize_phone_digits(hint)
    if len(hint_digits) < 2:
        return None
    exact = [entry for entry in entries if entry["phone_digits"] == hint_digits]
    if len(exact) == 1:
        return exact[0]
    if len(hint_digits) >= 4:
        suffix = [entry for entry in entries if entry["phone_digits"].endswith(hint_digits)]
        if len(suffix) == 1:
            return suffix[0]
    if len(hint_digits) >= 2:
        suffix = [entry for entry in entries if entry["phone_digits"].endswith(hint_digits)]
        if len(suffix) == 1:
            return suffix[0]
    return None


def resolve_phone_code_source(payload: dict[str, Any], phone_hint: str = "", *, allow_batch: bool = False) -> dict[str, str]:
    """从登录 payload 和长效手机池中选择本轮短信验证码来源。"""
    entries = phone_pool_entries_from_payload(payload)
    account_email = _coerce_text(payload.get("email")).lower()
    hint = phone_hint or _coerce_text(payload.get("_detected_phone_hint"))
    by_hint = phone_pool_match_by_hint(entries, hint)
    if by_hint:
        return by_hint
    bound = [entry for entry in entries if account_email and entry["account_email"] == account_email]
    if len(bound) == 1:
        return bound[0]
    phone = _coerce_text(payload.get("phone_number") or payload.get("phoneNumber"))
    api_url = _coerce_text(payload.get("phone_api_url") or payload.get("phoneApiUrl"))
    if phone and api_url:
        return {
            "id": _coerce_text(payload.get("phone_binding_id") or payload.get("phoneBindingId")),
            "mode": "payload",
            "phone": phone,
            "phone_digits": normalize_phone_digits(phone),
            "api_url": api_url,
            "account_email": account_email,
        }
    if allow_batch:
        batch = [entry for entry in entries if not entry["account_email"] or entry["mode"] == "batch"]
        if batch:
            return batch[0]
    return {}

def build_phone_number_verification_attempts(
    *,
    referer: str,
    phone: str,
    normalize_auth_url_func: Callable[[str], str] | None = None,
) -> list[dict[str, Any]]:
    """构造提交手机号时可尝试的表单/API endpoint 与请求体。"""
    normalizer = normalize_auth_url_func or (lambda value: value)
    form_url = normalizer(referer)
    form_path = urllib.parse.urlparse(form_url).path
    form_attempt_url = form_url if "/add-phone" in form_path else "https://auth.openai.com/add-phone"
    return [
        {
            "url": form_attempt_url,
            "form_data": {"phoneNumber": phone},
            "json_data": None,
            "is_form": True,
        },
        {
            "url": "https://auth.openai.com/api/accounts/phone-number",
            "form_data": None,
            "json_data": {"phone_number": phone, "phoneNumber": phone},
            "is_form": False,
        },
        {
            "url": "https://auth.openai.com/api/accounts/phone-verification/send",
            "form_data": None,
            "json_data": {"phone_number": phone, "phoneNumber": phone},
            "is_form": False,
        },
    ]


def build_phone_otp_channel_attempts(*, phone: str = "") -> list[dict[str, Any]]:
    """构造选择短信 OTP 通道时可尝试的 endpoint 与 JSON body。"""
    attempts = [
        ("https://auth.openai.com/api/accounts/phone-otp/select-channel", {"channel": "sms"}),
        ("https://auth.openai.com/api/accounts/phone-otp/select-channel", {"type": "sms"}),
        ("https://auth.openai.com/api/accounts/phone-otp/send", {"channel": "sms"}),
        ("https://auth.openai.com/api/accounts/phone-otp/resend", {}),
        ("https://auth.openai.com/api/accounts/add-phone/send", {"channel": "sms"}),
        ("https://auth.openai.com/api/accounts/phone-verification/send", {"channel": "sms"}),
    ]
    built: list[dict[str, Any]] = []
    for url, body in attempts:
        request_body = dict(body)
        if phone and ("/add-phone/" in url or "/phone-verification/" in url):
            request_body.update({"phone_number": phone, "phoneNumber": phone})
        built.append({"url": url, "json_data": request_body})
    return built


def build_phone_verification_code_attempts(
    *,
    code: str,
    referer: str,
    normalize_auth_url_func: Callable[[str], str] | None = None,
) -> list[dict[str, Any]]:
    """构造提交手机验证码时可尝试的表单/API endpoint 与请求体。"""
    normalizer = normalize_auth_url_func or (lambda value: value)
    attempts: list[dict[str, Any]] = []
    form_url = normalizer(referer)
    form_path = urllib.parse.urlparse(form_url).path
    if form_url and ("/phone-verification" in form_path or "/phone-otp" in form_path):
        attempts.append({
            "method": "POST",
            "url": form_url,
            "form_data": {"code": code},
            "json_data": None,
            "is_form": True,
        })
    for url in [
        "https://auth.openai.com/api/accounts/phone-verification/validate",
        "https://auth.openai.com/api/accounts/phone-otp/validate",
        "https://auth.openai.com/api/accounts/sms/validate",
    ]:
        attempts.append({
            "method": "POST",
            "url": url,
            "form_data": None,
            "json_data": {"code": code},
            "is_form": False,
        })
    return attempts


def phone_api_url(
    template: str,
    *,
    phone: str,
    account_email: str,
    since: str = "",
    validate_base_url_func: Callable[[str], None] | None = None,
    now_ts_func: Callable[[], float] | None = None,
) -> str:
    """拼装短信查询 URL，并把远程地址校验留给上层注入。"""
    raw = _coerce_text(template)
    if not raw:
        raise RuntimeError("接码 API URL 不能为空")
    now_ts = now_ts_func or time.time
    replacements = {
        "{phone}": urllib.parse.quote(phone, safe=""),
        "{email}": urllib.parse.quote(account_email, safe=""),
        "{account}": urllib.parse.quote(account_email, safe=""),
        "{since}": urllib.parse.quote(since),
        "{ts}": str(int(now_ts())),
    }
    for token, value in replacements.items():
        raw = raw.replace(token, value)
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("接码 API URL 必须是 http/https 地址")
    if validate_base_url_func is not None:
        validate_base_url_func(raw)
    return raw


def poll_phone_code(
    payload: dict[str, Any],
    *,
    validate_base_url_func: Callable[[str], None] | None = None,
    http_text_func: Callable[..., tuple[int, str]] | None = None,
    now_func: Callable[[], str] | None = None,
    now_ts_func: Callable[[], float] | None = None,
) -> dict[str, Any]:
    """查询短信接口并提取验证码。

    这里不直接依赖具体 HTTP 实现，也不假定当前环境允许访问哪些远程地址；
    上层需要把 URL 校验和文本请求函数显式注入进来，验证域只负责参数规整、
    文本抽取和固定返回结构。
    """
    if http_text_func is None:
        raise RuntimeError("缺少短信查询 HTTP 函数")
    if now_func is None:
        raise RuntimeError("缺少时间函数")
    phone = _coerce_text(payload.get("phone") or payload.get("phone_number") or payload.get("phoneNumber"))
    account_email = _coerce_text(payload.get("account_email") or payload.get("email") or payload.get("account"))
    api_url = _coerce_text(payload.get("api_url") or payload.get("apiUrl"))
    since = _coerce_text(payload.get("since"))
    if not phone:
        raise RuntimeError("手机号不能为空")
    url = phone_api_url(
        api_url,
        phone=phone,
        account_email=account_email,
        since=since,
        validate_base_url_func=validate_base_url_func,
        now_ts_func=now_ts_func,
    )
    status, text = http_text_func(url, timeout=30)
    try:
        raw_payload: Any = json.loads(text)
    except Exception:
        raw_payload = text
    extracted = extract_sms_code_payload(raw_payload)
    code = extracted.get("code", "")
    return {
        "success": True,
        "found": bool(code),
        "code": code,
        "phone": phone,
        "account_email": account_email,
        "message": extracted.get("message", "")[:500],
        "status": status,
        "checked_at": now_func(),
    }


def message_six_digit_codes(message: dict[str, Any]) -> list[str]:
    """从单条邮件结果里找 6 位验证码。"""
    raw_codes = [_coerce_text(code) for code in message.get("codes") or []]
    if not raw_codes:
        raw_codes = _extract_six_digit_codes("\n".join([
            _coerce_text(message.get("subject")),
            _coerce_text(message.get("preview")),
            _coerce_text(message.get("body")),
            _strip_html(_coerce_text(message.get("html_body"))),
        ]))
    return [code for code in raw_codes if re.fullmatch(r"\d{6}", code)]


def count_six_digit_codes(messages: list[dict[str, Any]]) -> int:
    """统计当前邮件结果中一共有多少个 6 位验证码。"""
    return sum(len(message_six_digit_codes(message)) for message in messages)


def find_latest_code(messages: list[dict[str, Any]], *, after_ts: float = 0, skew_seconds: int = 30) -> str:
    """从最新邮件开始往前找验证码，跳过明显早于触发时间的旧邮件。"""
    sorted_messages = sorted(messages, key=message_sort_value, reverse=True)
    for message in sorted_messages:
        received_at = _coerce_text(message.get("received_at"))
        if after_ts and received_at:
            parsed = parse_message_datetime(received_at)
            if parsed and parsed.timestamp() + max(0, skew_seconds) < after_ts:
                continue
        for code in message_six_digit_codes(message):
            return code
    return ""


def fetch_login_verification_code(
    payload: dict[str, Any],
    *,
    since: float = 0,
    attempts: int = 12,
    delay: float = 5,
    fetch_mail_func: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> str:
    """轮询登录验证码。

    上层传入邮件抓取函数，这里只做重试、日志和验证码判定；如果外层没
    提供抓取函数，就直接报错，避免登录域偷偷依赖别的业务实现。
    """
    if fetch_mail_func is None:
        raise RuntimeError("缺少邮件抓取函数")
    job_id = _coerce_text(payload.get("job_id"))
    total_attempts = max(1, attempts)
    last_summary = ""
    for attempt in range(1, total_attempts + 1):
        raise_if_login_job_cancelled(job_id)
        manual_code = manual_email_code_for_payload(payload)
        if manual_code:
            if job_id:
                append_login_log(job_id, "使用手动填写的邮箱验证码", "info", "manual_email_code")
            return manual_code
        data = fetch_mail_func({
            "source": "all",
            "provider": "auto",
            "sender_filter": payload.get("sender_filter", ""),
            "limit": payload.get("limit", 20),
            "emails": [payload.get("email", "")],
            "accounts": payload.get("accounts", []),
            "temp_addresses": payload.get("temp_addresses", []),
            "generic_accounts": payload.get("generic_accounts", []),
        })
        live_messages = data.get("messages", []) if isinstance(data.get("messages"), list) else []
        errors = data.get("errors", []) if isinstance(data.get("errors"), list) else []
        latest = live_messages[0] if live_messages else {}
        latest_subject = _coerce_text(latest.get("subject"))[:80] if isinstance(latest, dict) else ""
        latest_at = _coerce_text(latest.get("received_at") or latest.get("cached_at"))[:32] if isinstance(latest, dict) else ""
        code_count = count_six_digit_codes(live_messages)
        error_summary = "; ".join(_coerce_text(error)[:80] for error in errors[:2])
        last_summary = (
            f"第 {attempt}/{total_attempts} 次，实时取信 {len(live_messages)} 封，"
            f"识别码 {code_count} 个，最新 {latest_subject or '-'}"
            f"{f'（{latest_at}）' if latest_at else ''}"
            f"{f'，错误：{error_summary}' if error_summary else ''}"
        )
        if job_id and (attempt == 1 or attempt == total_attempts or attempt % 4 == 0 or errors):
            append_login_log(job_id, f"查收邮箱：{last_summary}", "info" if live_messages else "warning", "mail_code_poll")
        code = find_latest_code(live_messages, after_ts=since)
        if code:
            if job_id:
                append_login_log(job_id, "已从邮箱取到 6 位验证码", "success", "mail_code_poll")
            return code
        time.sleep(max(1, delay))
    if job_id and last_summary:
        append_login_log(job_id, f"邮箱验证码查收结束，仍未找到可提交的 6 位验证码：{last_summary}", "warning", "mail_code_missing")
    return ""


__all__ = [
    "build_phone_number_verification_attempts",
    "build_phone_otp_channel_attempts",
    "build_phone_verification_code_attempts",
    "collect_sms_candidates",
    "count_six_digit_codes",
    "extract_phone_hint_from_step",
    "extract_phone_hint_from_text",
    "extract_sms_code_payload",
    "fetch_registration_verification_link",
    "fetch_login_verification_code",
    "find_latest_code",
    "message_six_digit_codes",
    "normalize_phone_digits",
    "normalize_sms_field_name",
    "phone_api_url",
    "poll_phone_code",
    "phone_pool_entries_from_payload",
    "phone_pool_match_by_hint",
]
