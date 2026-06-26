"""邮件正文解析与结构化工具。

这一层只处理 MIME 解码、正文抽取、HTML 清洗、链接和验证码提取，
不负责取信、不读写文件，也不发网络请求。
"""
from __future__ import annotations

import base64
import email as email_lib
import html
import re
from email.header import decode_header
from typing import Any, Callable


CODE_PATTERNS = [
    r"(?<!\d)(\d{6})(?!\d)",
    r"(?<![A-Za-z0-9])([A-Z0-9]{6,8})(?![A-Za-z0-9])",
]


def decode_bytes(payload: bytes, charset: str | None = None) -> str:
    """按常见编码尝试解码邮件字节内容。"""
    candidates = []
    if charset:
        candidates.append(charset)
    candidates.extend(["utf-8", "gb18030", "gbk", "big5", "latin-1"])
    seen: set[str] = set()
    for encoding in candidates:
        normalized = encoding.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        try:
            return payload.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode(charset or "utf-8", errors="replace")


def decode_mime_header(value: str) -> str:
    """解码邮件标题、发件人等 MIME header 字段。"""
    pieces: list[str] = []
    for part, enc in decode_header(value):
        if isinstance(part, bytes):
            pieces.append(decode_bytes(part, enc))
        else:
            pieces.append(part)
    return "".join(pieces)


def decode_message_part(part: email_lib.message.Message) -> str:
    """解码单个 MIME part，失败时返回空字符串交给上层兜底。"""
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return decode_bytes(payload, part.get_content_charset())
    fallback = part.get_payload()
    return fallback if isinstance(fallback, str) else ""


def extract_body_parts(msg: email_lib.message.Message) -> tuple[str, str]:
    """从邮件消息中拆出纯文本正文和 HTML 正文。"""
    plain_chunks: list[str] = []
    html_chunks: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type not in ("text/plain", "text/html"):
                continue
            text = decode_message_part(part)
            if not text:
                continue
            if content_type == "text/plain":
                plain_chunks.append(text)
            else:
                html_chunks.append(text)
    else:
        text = decode_message_part(msg)
        if msg.get_content_type() == "text/html":
            html_chunks.append(text)
        else:
            plain_chunks.append(text)
    return "\n".join(plain_chunks), "\n".join(html_chunks)


def extract_body(msg: email_lib.message.Message) -> str:
    """返回优先纯文本、其次 HTML 转文本的正文。"""
    plain, html_body = extract_body_parts(msg)
    return plain or strip_html(html_body)


def normalize_raw_email(raw: str) -> str:
    """把可能被转义或 base64 包裹的原始邮件还原成可解析文本。"""
    text = str(raw or "").strip()
    if not text:
        return ""
    if "\\r\\n" in text and "\r\n" not in text:
        text = text.replace("\\r\\n", "\r\n").replace("\\n", "\n")
    if re.search(r"^[A-Za-z0-9_-]+:", text, flags=re.M):
        return text
    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 24 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        try:
            decoded = base64.b64decode(compact, validate=True)
            decoded_text = decode_bytes(decoded)
            if re.search(r"^[A-Za-z0-9_-]+:", decoded_text, flags=re.M):
                return decoded_text
        except Exception:
            pass
    return text


def parse_raw_email(raw: str) -> tuple[str, str, str, str, str]:
    """解析原始邮件文本，返回标题、发件人、正文、HTML 和日期。"""
    normalized = normalize_raw_email(raw)
    if not normalized:
        return "", "", "", "", ""
    try:
        msg = email_lib.message_from_string(normalized)
    except Exception:
        return "", "", "", "", ""
    plain, html_body = extract_body_parts(msg)
    return (
        decode_mime_header(msg.get("Subject", "")),
        decode_mime_header(msg.get("From", "")),
        plain or strip_html(html_body),
        sanitize_email_html(html_body),
        msg.get("Date", ""),
    )


def sanitize_email_html(value: str) -> str:
    """做轻量 HTML 清洗，去掉脚本和危险事件属性。"""
    text = str(value or "")
    if not text:
        return ""
    text = re.sub(r"<\s*(script|iframe|object|embed|form|input|button|select|textarea)\b.*?</\s*\1\s*>", "", text, flags=re.I | re.S)
    text = re.sub(r"<\s*(script|iframe|object|embed|form|input|button|select|textarea|meta)\b[^>]*>", "", text, flags=re.I | re.S)
    text = re.sub(r"\s+on[a-z]+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", text, flags=re.I)
    text = re.sub(r"\s+(href|src)\s*=\s*(['\"])\s*javascript:[^'\"]*\2", "", text, flags=re.I)
    text = re.sub(r"\s+(href|src)\s*=\s*javascript:[^\s>]+", "", text, flags=re.I)
    return text


def strip_html(text: str) -> str:
    """把 HTML 粗略转成可搜索的纯文本。"""
    text = re.sub(r"<(script|style).*?</\1>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(text)


def extract_links(text: str) -> list[str]:
    """从邮件文本中提取去重后的链接，保持出现顺序。"""
    links = re.findall(r"https?://[^\s<>'\")]+", str(text or ""))
    clean: list[str] = []
    seen: set[str] = set()
    for link in links:
        trimmed = link.rstrip(".,;]")
        if trimmed not in seen:
            seen.add(trimmed)
            clean.append(trimmed)
    return clean


def extract_codes(text: str, code_patterns: list[str] | None = None) -> list[str]:
    """提取验证码并去重，保持旧规则对 6 位数字和字母数字码的兼容。"""
    found: list[str] = []
    seen: set[str] = set()
    for pattern in code_patterns or CODE_PATTERNS:
        for match in re.finditer(pattern, text, flags=re.I):
            code = match.group(1)
            if code.lower() in {"ffffff", "000000"}:
                continue
            if not code.isdigit() and not (re.search(r"[A-Za-z]", code) and re.search(r"\d", code)):
                continue
            if code not in seen:
                seen.add(code)
                found.append(code)
    return found[:10]


def normalize_message(
    *,
    mail_type_labels: dict[str, str],
    normalize_mail_type: Callable[[Any, str], str],
    coerce_text: Callable[[Any], str],
    **kwargs: Any,
) -> dict[str, Any]:
    """把不同来源的邮件整理成前端一致消费的消息结构。"""
    subject = coerce_text(kwargs.get("subject"))
    body_text = strip_html(coerce_text(kwargs.get("body")))
    html_body = sanitize_email_html(coerce_text(kwargs.get("html_body")))
    html_text = strip_html(html_body)
    if not body_text and html_body:
        body_text = html_text
    text = strip_html(f"{subject}\n{body_text}\n{html_text}")
    links = extract_links(text)
    codes = extract_codes(text)
    mail_type = normalize_mail_type("", f"{kwargs.get('sender', '')} {subject} {text}")
    return {
        **kwargs,
        "source": kwargs.get("source", "microsoft"),
        "mail_type": mail_type,
        "mail_type_label": mail_type_labels.get(mail_type, "other"),
        "body": body_text[:6000],
        "html_body": html_body[:200000],
        "preview": " ".join((body_text or subject).split())[:260],
        "codes": codes,
        "links": links[:12],
    }
