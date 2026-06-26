"""邮件协议取信能力。

这一层承接需要访问外部邮箱协议/API 的逻辑。当前先迁入 Microsoft
Graph / Outlook API 取信链路，并通过 runtime 注入 HTTP 与 DNS 能力，
让旧入口可以继续复用原来的网络兜底行为。
"""
from __future__ import annotations

import email as email_lib
import imaplib
import json
import poplib
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from gpt_account_manager.infra import (
    HostHeaderIMAP4SSL,
    http_json as infra_http_json,
    http_request_json as infra_http_request_json,
    network_error_message as infra_network_error_message,
    is_dns_error as infra_is_dns_error,
    urlopen_with_dns_retry as infra_urlopen_with_dns_retry,
)

from .classifier import MAIL_TYPE_LABELS, normalize_mail_type
from .model.entity.account import GenericMailAccount, MailAccount
from .providers.rules import (
    classify_mail_fetch_error as provider_classify_mail_fetch_error,
    microsoft_provider_sequence as provider_microsoft_provider_sequence,
    normalize_generic_mail_mode,
    run_mail_fetch_jobs as provider_run_mail_fetch_jobs,
)
from .parser import (
    decode_mime_header,
    extract_body_parts,
    normalize_message as parser_normalize_message,
    parse_raw_email,
    strip_html,
)
from .service import normalize_generic_account


GRAPH_FOLDERS = ["inbox", "junkemail"]
IMAP_FOLDERS = ["INBOX", "Junk", "Junk Email"]


@dataclass(frozen=True)
class MailProtocolRuntime:
    """邮件协议层的外部 I/O 依赖。

    server.py 兼容入口会传入现有 HTTP/DNS wrapper，保证迁移期间行为冻结；
    直接从邮件域调用时则使用 infra 默认实现。
    """

    http_json: Callable[..., dict[str, Any]] = infra_http_json
    http_request_json: Callable[..., dict[str, Any]] = infra_http_request_json
    http_json_via_ip_fallback: Callable[..., dict[str, Any]] | None = None
    default_http_headers: dict[str, str] | None = None
    normalize_temp_worker_url: Callable[[str], str] = lambda value: str(value or "").strip().rstrip("/")
    urlopen_with_dns_retry: Callable[..., Any] = infra_urlopen_with_dns_retry
    network_error_message: Callable[[str, BaseException], str] = infra_network_error_message
    cached_fallback_ips: Callable[[str], list[str]] = lambda _: []


def _runtime(runtime: MailProtocolRuntime | None = None) -> MailProtocolRuntime:
    """统一补齐 runtime，避免每个函数重复判断空值。"""
    return runtime or MailProtocolRuntime()



def normalize_base_url(value: str) -> str:
    """规整第三方邮箱 API 基础地址，保持旧入口自动补 https 的兼容行为。"""
    clean = str(value or "").strip()
    if clean and not urllib.parse.urlparse(clean).scheme:
        clean = f"https://{clean}"
    return clean.rstrip("/")


def _first_text(*values: Any) -> str:
    """从多个候选字段中取第一个非空文本，兼容不同 API 响应字段名。"""
    for value in values:
        text = _coerce_text(value)
        if text:
            return text
    return ""
def _coerce_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_message(**kwargs: Any) -> dict[str, Any]:
    """复用 parser 的消息结构化规则，保持前端看到的消息字段不变。"""
    return parser_normalize_message(
        mail_type_labels=MAIL_TYPE_LABELS,
        normalize_mail_type=normalize_mail_type,
        coerce_text=_coerce_text,
        **kwargs,
    )


def get_graph_token(account: MailAccount, *, runtime: MailProtocolRuntime | None = None) -> str:
    """用微软 refresh_token 换取 Graph 访问令牌。"""
    runtime = _runtime(runtime)
    attempts = [
        ("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
            "client_id": account.client_id,
            "grant_type": "refresh_token",
            "refresh_token": account.refresh_token,
            "scope": "https://graph.microsoft.com/Mail.Read offline_access",
        }),
        ("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
            "client_id": account.client_id,
            "grant_type": "refresh_token",
            "refresh_token": account.refresh_token,
            "scope": "https://graph.microsoft.com/.default",
        }),
    ]
    last_error = ""
    for url, data in attempts:
        try:
            payload = runtime.http_json(url, method="POST", data=data)
            token = payload.get("access_token")
            if token:
                return token
            last_error = str(payload)
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(f"Graph token failed: {last_error}")


def refresh_microsoft_access_token(
    account: MailAccount,
    attempts: list[tuple[str, dict[str, str]]],
    label: str,
    *,
    runtime: MailProtocolRuntime | None = None,
) -> str:
    """按给定 token endpoint 列表刷新微软访问令牌。"""
    runtime = _runtime(runtime)
    last_error = ""
    for url, data in attempts:
        try:
            payload = runtime.http_json(url, method="POST", data=data)
            token = payload.get("access_token")
            if token:
                return token
            last_error = str(payload)
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(f"{label} token failed: {last_error}")


def fetch_graph_messages(
    account: MailAccount,
    *,
    limit: int,
    sender_filter: str = "",
    runtime: MailProtocolRuntime | None = None,
) -> list[dict[str, Any]]:
    """通过 Microsoft Graph 读取最近邮件并归一化成前端消息结构。"""
    runtime = _runtime(runtime)
    token = get_graph_token(account, runtime=runtime)
    messages: list[dict[str, Any]] = []
    for folder in GRAPH_FOLDERS:
        params = urllib.parse.urlencode({
            "$select": "id,subject,bodyPreview,from,receivedDateTime,webLink",
            "$orderby": "receivedDateTime desc",
            "$top": str(max(limit, 1)),
        })
        url = f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder}/messages?{params}"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })
        try:
            with runtime.urlopen_with_dns_retry(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and folder == "junkemail":
                continue
            text = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Graph fetch failed: {exc.code} {text[:220]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(runtime.network_error_message(url, exc)) from exc
        for item in payload.get("value", []):
            sender = item.get("from", {}).get("emailAddress", {}).get("address", "")
            subject = item.get("subject", "")
            body = item.get("bodyPreview", "")
            if sender_filter and sender_filter.lower() not in f"{sender} {subject} {body}".lower():
                continue
            messages.append(_normalize_message(
                account=account.email,
                provider="graph",
                folder=folder,
                mid=item.get("id", ""),
                sender=sender,
                subject=subject,
                body=body,
                received_at=item.get("receivedDateTime", ""),
                web_link=item.get("webLink", ""),
            ))
    return messages[:limit]


def fetch_outlook_api_messages(
    account: MailAccount,
    *,
    limit: int,
    sender_filter: str = "",
    runtime: MailProtocolRuntime | None = None,
) -> list[dict[str, Any]]:
    """通过旧 Outlook REST API 读取邮件，作为 Graph/IMAP 之外的兼容链路。"""
    runtime = _runtime(runtime)
    token = refresh_microsoft_access_token(account, [
        ("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
            "client_id": account.client_id,
            "grant_type": "refresh_token",
            "refresh_token": account.refresh_token,
        }),
        ("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
            "client_id": account.client_id,
            "grant_type": "refresh_token",
            "refresh_token": account.refresh_token,
            "scope": "offline_access https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read",
        }),
    ], "Outlook API", runtime=runtime)
    messages: list[dict[str, Any]] = []
    for folder in GRAPH_FOLDERS:
        params = urllib.parse.urlencode({
            "$select": "Id,Subject,BodyPreview,From,ReceivedDateTime,WebLink",
            "$orderby": "ReceivedDateTime desc",
            "$top": str(max(limit, 1)),
        })
        url = f"https://outlook.office.com/api/v2.0/me/mailfolders/{folder}/messages?{params}"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })
        try:
            with runtime.urlopen_with_dns_retry(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and folder == "junkemail":
                continue
            text = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Outlook API fetch failed: {exc.code} {text[:220]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(runtime.network_error_message(url, exc)) from exc
        for item in payload.get("value", []):
            sender_info = item.get("From") or item.get("from") or {}
            sender_addr = sender_info.get("EmailAddress") or sender_info.get("emailAddress") or {}
            sender = sender_addr.get("Address") or sender_addr.get("address") or ""
            subject = item.get("Subject") or item.get("subject") or ""
            body = item.get("BodyPreview") or item.get("bodyPreview") or ""
            if sender_filter and sender_filter.lower() not in f"{sender} {subject} {body}".lower():
                continue
            messages.append(_normalize_message(
                account=account.email,
                provider="outlook",
                folder=folder,
                mid=item.get("Id") or item.get("id") or "",
                sender=sender,
                subject=subject,
                body=body,
                received_at=item.get("ReceivedDateTime") or item.get("receivedDateTime") or "",
                web_link=item.get("WebLink") or item.get("webLink") or "",
            ))
    return messages[:limit]

def _usable_secret(value: Any) -> bool:
    """识别可真实用于登录的邮箱密码或授权码。"""
    text = _coerce_text(value)
    if not text:
        return False
    return not (set(text) <= {"*"} or "..." in text)


def open_imap_ssl(server: str):
    """打开微软 IMAP SSL 连接，保持旧入口的超时和 SSL 默认策略。"""
    return imaplib.IMAP4_SSL(server, 993, ssl_context=ssl.create_default_context(), timeout=30)


def open_imap_ssl_port(server: str, port: int):
    """打开普通邮箱 IMAP SSL 连接，端口由账号配置决定。"""
    return imaplib.IMAP4_SSL(server, port, ssl_context=ssl.create_default_context(), timeout=30)


def get_imap_token(account: MailAccount, *, runtime: MailProtocolRuntime | None = None) -> tuple[str, str]:
    """用微软 refresh_token 换取 IMAP XOAUTH2 token 和对应服务器。"""
    runtime = _runtime(runtime)
    attempts = [
        ("https://login.live.com/oauth20_token.srf", {
            "client_id": account.client_id,
            "grant_type": "refresh_token",
            "refresh_token": account.refresh_token,
        }, "outlook.office365.com"),
        ("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", {
            "client_id": account.client_id,
            "grant_type": "refresh_token",
            "refresh_token": account.refresh_token,
            "scope": "offline_access https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read",
        }, "outlook.live.com"),
        ("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
            "client_id": account.client_id,
            "grant_type": "refresh_token",
            "refresh_token": account.refresh_token,
            "scope": "offline_access https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read",
        }, "outlook.office365.com"),
    ]
    last_error = ""
    for url, data, server in attempts:
        try:
            return refresh_microsoft_access_token(account, [(url, data)], "IMAP", runtime=runtime), server
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(f"IMAP token failed: {last_error}")


def append_imap_raw_message(
    messages: list[dict[str, Any]],
    *,
    account_email: str,
    provider: str,
    folder: str,
    mid: str,
    raw: bytes,
) -> None:
    """把 IMAP/POP3 原始邮件字节整理为统一消息并追加到结果集。"""
    msg = email_lib.message_from_bytes(raw)
    subject = decode_mime_header(msg.get("Subject", ""))
    sender = decode_mime_header(msg.get("From", ""))
    body, html_body = extract_body_parts(msg)
    if not body and html_body:
        body = strip_html(html_body)
    messages.append(_normalize_message(
        account=account_email,
        source="generic",
        provider=provider,
        folder=folder,
        mid=mid,
        sender=sender,
        subject=subject,
        body=body,
        html_body=html_body,
        received_at=msg.get("Date", ""),
    ))


def fetch_imap_messages_with_connection(
    imap: imaplib.IMAP4_SSL,
    account: MailAccount,
    auth: str,
    limit: int,
    sender_filter: str,
) -> list[dict[str, Any]]:
    """在已打开的微软 IMAP 连接上执行 XOAUTH2 取信。"""
    messages: list[dict[str, Any]] = []
    imap.authenticate("XOAUTH2", lambda _: auth.encode("utf-8"))
    for folder in IMAP_FOLDERS:
        try:
            status, _ = imap.select(f'"{folder}"', readonly=True)
            if status != "OK":
                continue
            if sender_filter:
                status, ids_raw = imap.uid("search", None, f'(OR FROM "{sender_filter}" TEXT "{sender_filter}")')
            else:
                status, ids_raw = imap.uid("search", None, "ALL")
            if status != "OK" or not ids_raw or not ids_raw[0]:
                continue
            ids = ids_raw[0].split()[-limit:]
            for mid in reversed(ids):
                status, msg_data = imap.uid("fetch", mid, "(RFC822)")
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                msg = email_lib.message_from_bytes(raw)
                subject = decode_mime_header(msg.get("Subject", ""))
                sender = decode_mime_header(msg.get("From", ""))
                body, html_body = extract_body_parts(msg)
                if not body and html_body:
                    body = strip_html(html_body)
                received_at = msg.get("Date", "")
                messages.append(_normalize_message(
                    account=account.email,
                    provider="imap",
                    folder=folder,
                    mid=mid.decode("utf-8", errors="ignore"),
                    imap_id_type="uid",
                    sender=sender,
                    subject=subject,
                    body=body,
                    html_body=html_body,
                    received_at=received_at,
                ))
                if len(messages) >= limit:
                    return messages
        except imaplib.IMAP4.error:
            continue
    return messages


def fetch_imap_messages(
    account: MailAccount,
    *,
    limit: int,
    sender_filter: str = "",
    runtime: MailProtocolRuntime | None = None,
) -> list[dict[str, Any]]:
    """通过微软 IMAP XOAUTH2 读取邮件，保留 DNS 兜底路径。"""
    runtime = _runtime(runtime)
    token, server = get_imap_token(account, runtime=runtime)
    auth = f"user={account.email}\x01auth=Bearer {token}\x01\x01"
    try:
        with open_imap_ssl(server) as imap:
            return fetch_imap_messages_with_connection(imap, account, auth, limit, sender_filter)
    except OSError as exc:
        if infra_is_dns_error(exc):
            for ip in runtime.cached_fallback_ips(server):
                try:
                    with HostHeaderIMAP4SSL(server, ip, 993, timeout=30) as imap:
                        return fetch_imap_messages_with_connection(imap, account, auth, limit, sender_filter)
                except OSError:
                    continue
                except imaplib.IMAP4.error:
                    continue
        raise RuntimeError(runtime.network_error_message(f"imaps://{server}:993", exc)) from exc
    return []


def fetch_generic_imap_messages(
    account: GenericMailAccount,
    *,
    limit: int,
    sender_filter: str = "",
    runtime: MailProtocolRuntime | None = None,
) -> list[dict[str, Any]]:
    """通过普通邮箱 IMAP 账号密码/授权码读取邮件。"""
    runtime = _runtime(runtime)
    account = normalize_generic_account(account)
    if not account.imap_host:
        raise RuntimeError("generic IMAP host missing")
    if not _usable_secret(account.password):
        raise RuntimeError("generic mail password missing")
    messages: list[dict[str, Any]] = []
    try:
        with open_imap_ssl_port(account.imap_host, account.imap_port) as imap:
            imap.login(account.username or account.email, account.password)
            for folder in IMAP_FOLDERS:
                try:
                    status, _ = imap.select(f'"{folder}"', readonly=True)
                    if status != "OK":
                        continue
                    if sender_filter:
                        status, ids_raw = imap.uid("search", None, f'(OR FROM "{sender_filter}" TEXT "{sender_filter}")')
                    else:
                        status, ids_raw = imap.uid("search", None, "ALL")
                    if status != "OK" or not ids_raw or not ids_raw[0]:
                        continue
                    ids = ids_raw[0].split()[-limit:]
                    for mid in reversed(ids):
                        status, msg_data = imap.uid("fetch", mid, "(RFC822)")
                        if status != "OK" or not msg_data or not msg_data[0]:
                            continue
                        append_imap_raw_message(
                            messages,
                            account_email=account.email,
                            provider="imap",
                            folder=folder,
                            mid=mid.decode("utf-8", errors="ignore"),
                            raw=msg_data[0][1],
                        )
                        if len(messages) >= limit:
                            return messages
                except imaplib.IMAP4.error:
                    continue
    except OSError as exc:
        raise RuntimeError(runtime.network_error_message(f"imaps://{account.imap_host}:{account.imap_port}", exc)) from exc
    except imaplib.IMAP4.error as exc:
        raise RuntimeError(f"generic IMAP auth/fetch failed: {exc}") from exc
    return messages


def fetch_generic_pop3_messages(
    account: GenericMailAccount,
    *,
    limit: int,
    sender_filter: str = "",
    runtime: MailProtocolRuntime | None = None,
) -> list[dict[str, Any]]:
    """通过普通邮箱 POP3 账号密码/授权码读取邮件。"""
    runtime = _runtime(runtime)
    account = normalize_generic_account(account)
    if not account.pop3_host:
        raise RuntimeError("generic POP3 host missing")
    if not _usable_secret(account.password):
        raise RuntimeError("generic mail password missing")
    messages: list[dict[str, Any]] = []
    try:
        with poplib.POP3_SSL(account.pop3_host, account.pop3_port, timeout=30) as pop:
            pop.user(account.username or account.email)
            pop.pass_(account.password)
            count = len(pop.list()[1])
            ids = list(range(max(1, count - max(limit * 2, limit) + 1), count + 1))
            for msg_num in reversed(ids):
                _, lines, _ = pop.retr(msg_num)
                raw = b"\r\n".join(lines)
                msg = email_lib.message_from_bytes(raw)
                subject = decode_mime_header(msg.get("Subject", ""))
                sender = decode_mime_header(msg.get("From", ""))
                body, html_body = extract_body_parts(msg)
                combined = f"{sender} {subject} {body} {strip_html(html_body)}".lower()
                if sender_filter and sender_filter.lower() not in combined:
                    continue
                messages.append(_normalize_message(
                    account=account.email,
                    source="generic",
                    provider="pop3",
                    folder="POP3",
                    mid=str(msg_num),
                    sender=sender,
                    subject=subject,
                    body=body or strip_html(html_body),
                    html_body=html_body,
                    received_at=msg.get("Date", ""),
                ))
                if len(messages) >= limit:
                    return messages
    except OSError as exc:
        raise RuntimeError(runtime.network_error_message(f"pop3s://{account.pop3_host}:{account.pop3_port}", exc)) from exc
    except poplib.error_proto as exc:
        raise RuntimeError(f"generic POP3 auth/fetch failed: {exc}") from exc
    return messages
def normalize_cloudmail_messages(payload: Any, account: GenericMailAccount, limit: int) -> list[dict[str, Any]]:
    """把 CloudMail API 响应规整成统一消息列表。"""
    rows = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for candidate in (
            payload.get("data"),
            payload.get("list"),
            payload.get("items"),
            payload.get("rows"),
            payload.get("records"),
            (payload.get("data") or {}).get("list") if isinstance(payload.get("data"), dict) else None,
            (payload.get("data") or {}).get("records") if isinstance(payload.get("data"), dict) else None,
        ):
            if isinstance(candidate, list):
                rows = candidate
                break
    messages: list[dict[str, Any]] = []
    for row in rows[: max(limit * 2, limit)]:
        if not isinstance(row, dict):
            continue
        address = _first_text(row.get("toEmail"), row.get("to_email"), row.get("recipient"), row.get("address"), row.get("email")).lower()
        if address and address != account.email.lower():
            continue
        html_body = _first_text(row.get("content"), row.get("html"), row.get("raw"))
        body = _first_text(row.get("text"), row.get("plainText"), row.get("content_text")) or strip_html(html_body)
        messages.append(_normalize_message(
            account=account.email,
            source="generic",
            provider="cloudmail",
            folder="api",
            mid=_first_text(row.get("emailId"), row.get("id"), row.get("mailId"), row.get("mail_id")),
            sender=_first_text(row.get("sendEmail"), row.get("send_email"), row.get("from"), row.get("sender"), row.get("mailFrom")),
            subject=_first_text(row.get("subject"), row.get("title")),
            body=body,
            html_body=html_body,
            received_at=_first_text(row.get("createTime"), row.get("create_time"), row.get("createdAt"), row.get("created_at"), row.get("receivedDateTime"), row.get("date")),
        ))
        if len(messages) >= limit:
            break
    return messages


def fetch_cloudmail_messages(
    account: GenericMailAccount,
    *,
    limit: int,
    sender_filter: str = "",
    runtime: MailProtocolRuntime | None = None,
) -> list[dict[str, Any]]:
    """通过 CloudMail API 拉取指定邮箱消息。"""
    runtime = _runtime(runtime)
    base_url = normalize_base_url(account.imap_host)
    token = account.password
    if not base_url or not _usable_secret(token):
        raise RuntimeError("Cloud Mail requires API URL and token")
    payload = runtime.http_request_json(
        f"{base_url}/api/public/emailList",
        method="POST",
        json_data={
            "toEmail": account.email,
            "type": 0,
            "isDel": 0,
            "timeSort": "desc",
            "num": 1,
            "size": max(limit, 20),
        },
        headers={"Authorization": token},
        timeout=30,
    )
    messages = normalize_cloudmail_messages(payload, account, limit)
    if sender_filter:
        needle = sender_filter.lower()
        messages = [message for message in messages if needle in f"{message.get('sender', '')} {message.get('subject', '')} {message.get('body', '')}".lower()]
    return messages[:limit]


def normalize_luckmail_messages(payload: Any, account: GenericMailAccount, limit: int) -> list[dict[str, Any]]:
    """把 LuckMail API 响应规整成统一消息列表。"""
    mails = []
    if isinstance(payload, dict):
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        for candidate in (payload.get("mails"), data.get("mails"), payload.get("items"), data.get("items"), payload.get("list"), data.get("list")):
            if isinstance(candidate, list):
                mails = candidate
                break
    elif isinstance(payload, list):
        mails = payload
    if not isinstance(mails, list):
        mails = []
    messages: list[dict[str, Any]] = []
    for row in mails[: max(limit * 2, limit)]:
        if not isinstance(row, dict):
            continue
        html_body = _first_text(row.get("html_body"), row.get("body_html"), row.get("html"))
        body = _first_text(row.get("body"), row.get("body_text"), row.get("text")) or strip_html(html_body)
        messages.append(_normalize_message(
            account=account.email,
            source="generic",
            provider="luckmail",
            folder="api",
            mid=_first_text(row.get("message_id"), row.get("id")),
            sender=_first_text(row.get("from"), row.get("sender")),
            subject=_first_text(row.get("subject"), row.get("title")),
            body=body,
            html_body=html_body,
            received_at=_first_text(row.get("received_at"), row.get("receivedAt"), row.get("created_at")),
        ))
        if len(messages) >= limit:
            break
    return messages


def fetch_luckmail_messages(
    account: GenericMailAccount,
    *,
    limit: int,
    sender_filter: str = "",
    runtime: MailProtocolRuntime | None = None,
) -> list[dict[str, Any]]:
    """通过 LuckMail API token 拉取消息。"""
    runtime = _runtime(runtime)
    base_url = normalize_base_url(account.imap_host) or "https://mails.luckyous.com"
    token = account.password
    headers = {}
    if account.username:
        headers["X-API-Key"] = account.username
    payload = runtime.http_request_json(
        f"{base_url}/api/v1/openapi/email/token/{urllib.parse.quote(token)}/mails",
        headers=headers,
        timeout=30,
    )
    messages = normalize_luckmail_messages(payload, account, limit)
    if sender_filter:
        needle = sender_filter.lower()
        messages = [message for message in messages if needle in f"{message.get('sender', '')} {message.get('subject', '')} {message.get('body', '')}".lower()]
    return messages[:limit]


def normalize_inbucket_messages(payload: Any, account: GenericMailAccount, limit: int) -> list[dict[str, Any]]:
    """把 Inbucket API 响应规整成统一消息列表。"""
    rows: list[Any] = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for candidate in (
            payload.get("messages"),
            payload.get("mails"),
            payload.get("mailbox"),
            payload.get("items"),
            (payload.get("data") or {}).get("messages") if isinstance(payload.get("data"), dict) else None,
            (payload.get("data") or {}).get("items") if isinstance(payload.get("data"), dict) else None,
        ):
            if isinstance(candidate, list):
                rows = candidate
                break
    messages: list[dict[str, Any]] = []
    for row in rows[: max(limit * 2, limit)]:
        if not isinstance(row, dict):
            continue
        html_body = _first_text(row.get("html"), row.get("bodyHtml"), row.get("body_html"))
        body = _first_text(row.get("body"), row.get("text"), row.get("bodyText"), row.get("body_text"), row.get("preview")) or strip_html(html_body)
        sender_value = row.get("from")
        sender = sender_value.get("address") if isinstance(sender_value, dict) else sender_value
        messages.append(_normalize_message(
            account=account.email,
            source="generic",
            provider="inbucket",
            folder="api",
            mid=_first_text(row.get("id"), row.get("messageId"), row.get("message_id"), row.get("mailId")),
            sender=_first_text(sender, row.get("sender"), row.get("fromAddress")),
            subject=_first_text(row.get("subject"), row.get("title")),
            body=body,
            html_body=html_body,
            received_at=_first_text(row.get("date"), row.get("created"), row.get("created_at"), row.get("receivedAt"), row.get("received_at")),
        ))
        if len(messages) >= limit:
            break
    return messages


def fetch_inbucket_messages(
    account: GenericMailAccount,
    *,
    limit: int,
    sender_filter: str = "",
    runtime: MailProtocolRuntime | None = None,
) -> list[dict[str, Any]]:
    """通过 Inbucket 兼容 API 拉取邮箱消息，按旧入口顺序尝试多个路径。"""
    runtime = _runtime(runtime)
    base_url = normalize_base_url(account.imap_host)
    mailbox = _coerce_text(account.username) or account.email.split("@", 1)[0]
    if not base_url:
        raise RuntimeError("Inbucket requires base URL")
    if not mailbox:
        raise RuntimeError("Inbucket mailbox missing")
    attempts = [
        f"{base_url}/api/v1/mailbox/{urllib.parse.quote(mailbox)}",
        f"{base_url}/api/v1/mailbox/{urllib.parse.quote(mailbox)}/messages",
        f"{base_url}/api/mailbox/{urllib.parse.quote(mailbox)}",
        f"{base_url}/api/messages?mailbox={urllib.parse.quote(mailbox)}",
    ]
    last_error = ""
    for url in attempts:
        try:
            payload = runtime.http_request_json(url, timeout=30)
            messages = normalize_inbucket_messages(payload, account, limit)
            if sender_filter:
                needle = sender_filter.lower()
                messages = [message for message in messages if needle in f"{message.get('sender', '')} {message.get('subject', '')} {message.get('body', '')}".lower()]
            return messages[:limit]
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(f"Inbucket API fetch failed: {last_error}")


def fetch_generic_messages(
    account: GenericMailAccount,
    provider: str,
    *,
    limit: int,
    sender_filter: str = "",
    runtime: MailProtocolRuntime | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """按通用邮箱模式选择 IMAP / POP3 / 第三方 API 取信链路。"""
    runtime = _runtime(runtime)
    account = normalize_generic_account(account)
    mode = normalize_generic_mail_mode(provider if provider in {"imap", "pop3", "cloudmail", "luckmail", "inbucket"} else account.mode)
    if mode == "cloudmail":
        return fetch_cloudmail_messages(account, limit=limit, sender_filter=sender_filter, runtime=runtime), "cloudmail"
    if mode == "luckmail":
        return fetch_luckmail_messages(account, limit=limit, sender_filter=sender_filter, runtime=runtime), "luckmail"
    if mode == "inbucket":
        return fetch_inbucket_messages(account, limit=limit, sender_filter=sender_filter, runtime=runtime), "inbucket"
    if mode == "pop3":
        return fetch_generic_pop3_messages(account, limit=limit, sender_filter=sender_filter, runtime=runtime), "pop3"
    errors: list[str] = []
    try:
        return fetch_generic_imap_messages(account, limit=limit, sender_filter=sender_filter, runtime=runtime), "imap"
    except Exception as exc:
        errors.append(f"imap: {exc}")
        if mode == "imap":
            raise
    try:
        return fetch_generic_pop3_messages(account, limit=limit, sender_filter=sender_filter, runtime=runtime), "pop3"
    except Exception as exc:
        errors.append(f"pop3: {exc}")
    raise RuntimeError("; ".join(errors) or "generic mail fetch failed")
def _iso_now() -> str:
    """生成与旧入口一致的 UTC 秒级时间戳。"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def temp_headers(address: Any, *, runtime: MailProtocolRuntime | None = None) -> dict[str, str]:
    """生成临时邮箱 worker 请求头，保留站点密码兼容字段。"""
    runtime = _runtime(runtime)
    headers = {
        **(runtime.default_http_headers or {"Accept": "application/json"}),
        "Authorization": f"Bearer {address.jwt}",
    }
    if address.site_password:
        headers["x-custom-auth"] = address.site_password
    return headers


def fetch_temp_messages(
    address: Any,
    *,
    limit: int,
    sender_filter: str = "",
    runtime: MailProtocolRuntime | None = None,
) -> list[dict[str, Any]]:
    """通过临时邮箱 worker API 拉取邮件并规整成统一消息结构。"""
    runtime = _runtime(runtime)
    if not address.base_url or not address.jwt:
        raise RuntimeError("Temp address requires base_url and jwt")
    base_url = runtime.normalize_temp_worker_url(address.base_url).rstrip("/")
    params = urllib.parse.urlencode({
        "limit": str(max(limit, 1)),
        "offset": "0",
    })
    url = f"{base_url}/api/mails?{params}"
    req = urllib.request.Request(url, headers=temp_headers(address, runtime=runtime))
    try:
        with runtime.urlopen_with_dns_retry(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="ignore")
        if exc.code in {401, 403} and "Invalid address credential" in text:
            raise RuntimeError("临时邮箱 JWT/地址凭证无效：Invalid address credential") from exc
        raise RuntimeError(f"临时邮箱 API 返回 HTTP {exc.code}：{text[:220]}") from exc
    except urllib.error.URLError as exc:
        if infra_is_dns_error(exc):
            if not runtime.http_json_via_ip_fallback:
                raise RuntimeError(runtime.network_error_message(url, exc)) from exc
            try:
                payload = runtime.http_json_via_ip_fallback(url, headers=temp_headers(address, runtime=runtime), timeout=30)
            except urllib.error.HTTPError as fallback_http:
                text = fallback_http.read().decode("utf-8", errors="ignore")
                if fallback_http.code in {401, 403} and "Invalid address credential" in text:
                    raise RuntimeError("临时邮箱 JWT/地址凭证无效：Invalid address credential") from fallback_http
                raise RuntimeError(f"临时邮箱 API 返回 HTTP {fallback_http.code}：{text[:220]}") from fallback_http
            except Exception as fallback_exc:
                raise RuntimeError(f"{runtime.network_error_message(url, exc)}；IP 兜底也失败：{fallback_exc}") from fallback_exc
        else:
            raise RuntimeError(runtime.network_error_message(url, exc)) from exc
    rows = payload.get("results", []) if isinstance(payload, dict) else []
    messages: list[dict[str, Any]] = []
    for item in rows:
        raw = str(item.get("raw") or item.get("raw_blob") or "")
        parsed_subject, parsed_sender, parsed_body, parsed_html, parsed_date = parse_raw_email(raw)
        subject = _first_text(parsed_subject, item.get("subject"))
        sender = _first_text(parsed_sender, item.get("source"), item.get("from"))
        body = _first_text(parsed_body, item.get("body"), item.get("content"), item.get("html"), item.get("text"))
        html_body = _first_text(parsed_html, item.get("html"))
        if not body:
            body = json.dumps(item, ensure_ascii=False)
        if sender_filter and sender_filter.lower() not in f"{sender} {subject} {body}".lower():
            continue
        messages.append(_normalize_message(
            source="temp",
            account=address.email,
            provider="cf-temp",
            folder="inbox",
            mid=str(item.get("id", "")),
            sender=decode_mime_header(sender),
            subject=decode_mime_header(subject),
            body=body,
            html_body=html_body,
            received_at=_first_text(item.get("created_at"), item.get("date"), parsed_date),
            web_link=f"{base_url}/?jwt={urllib.parse.quote(address.jwt)}",
        ))
    return messages[:limit]


def classify_mail_fetch_error(raw: str, source: str = "") -> dict[str, Any]:
    """把协议层取信异常归类成前端可展示的错误字段。"""
    return provider_classify_mail_fetch_error(raw, source)


def apply_mail_fetch_result_fields(target: Any, result: dict[str, Any]) -> None:
    """把单次取信结果回写到账号实体的最近状态字段。"""
    target.last_status = "ok" if result.get("ok") else "error"
    target.last_check_at = _coerce_text(result.get("checked_at") or _iso_now())
    target.last_message_count = int(result.get("message_count") or 0)
    target.last_error = _coerce_text(result.get("error") or "")
    target.last_error_code = _coerce_text(result.get("error_code") or "")
    target.last_error_label = _coerce_text(result.get("error_label") or "")
    target.last_error_hint = _coerce_text(result.get("error_hint") or "")


def mail_fetch_error_result(kind: str, target: Any, message: str, *, elapsed_ms: int = 0) -> dict[str, Any]:
    """构造取信失败结果，并同步回写目标账号状态。"""
    detail = classify_mail_fetch_error(f"{kind}: {message}", kind)
    result = {
        "source": kind,
        "provider": "temp" if kind == "temp" else getattr(target, "mode", "auto"),
        "email": getattr(target, "email", ""),
        "ok": False,
        "checked_at": _iso_now(),
        "elapsed_ms": elapsed_ms,
        "message_count": 0,
        "messages": [],
        "errors": [f"{kind}: {message}"],
        "error": detail["error_detail"],
        "error_code": detail["error_code"],
        "error_label": detail["error_label"],
        "error_hint": detail["error_hint"],
        "retryable": detail["retryable"],
    }
    apply_mail_fetch_result_fields(target, result)
    return result


def microsoft_provider_sequence(provider: str) -> list[str]:
    """生成微软邮箱取信 provider 尝试顺序。"""
    return provider_microsoft_provider_sequence(provider)


def fetch_for_account(
    account: MailAccount,
    provider: str,
    limit: int,
    sender_filter: str,
    *,
    runtime: MailProtocolRuntime | None = None,
) -> dict[str, Any]:
    """执行单个微软邮箱账号的多 provider 取信并回写状态。"""
    runtime = _runtime(runtime)
    started = time.perf_counter()
    errors: list[str] = []
    messages: list[dict[str, Any]] = []
    checked_at = _iso_now()
    used_provider = ""
    providers = microsoft_provider_sequence(provider)
    for current in providers:
        try:
            if current == "graph":
                messages = fetch_graph_messages(account, limit=limit, sender_filter=sender_filter, runtime=runtime)
            elif current == "imap":
                messages = fetch_imap_messages(account, limit=limit, sender_filter=sender_filter, runtime=runtime)
            elif current == "outlook":
                messages = fetch_outlook_api_messages(account, limit=limit, sender_filter=sender_filter, runtime=runtime)
            else:
                raise RuntimeError(f"Unsupported provider: {current}")
            account.last_status = "ok"
            account.last_error = ""
            used_provider = current
            break
        except Exception as exc:
            errors.append(f"{current}: {exc}")
            account.last_status = "error"
            account.last_error = str(exc)[:500]
    account.last_check_at = checked_at
    detail = classify_mail_fetch_error(errors[0] if errors else "", "microsoft") if account.last_status != "ok" else {}
    result = {
        "source": "microsoft",
        "provider": used_provider or provider,
        "email": account.email,
        "ok": account.last_status == "ok",
        "checked_at": checked_at,
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
        "message_count": len(messages),
        "messages": messages,
        "errors": errors,
    }
    if detail:
        result.update({
            "error": detail["error_detail"],
            "error_code": detail["error_code"],
            "error_label": detail["error_label"],
            "error_hint": detail["error_hint"],
            "retryable": detail["retryable"],
        })
    apply_mail_fetch_result_fields(account, result)
    return result


def fetch_for_temp_address(
    address: Any,
    limit: int,
    sender_filter: str,
    *,
    runtime: MailProtocolRuntime | None = None,
) -> dict[str, Any]:
    """执行单个临时邮箱取信并回写状态。"""
    runtime = _runtime(runtime)
    started = time.perf_counter()
    checked_at = _iso_now()
    try:
        messages = fetch_temp_messages(address, limit=limit, sender_filter=sender_filter, runtime=runtime)
        address.last_status = "ok"
        address.last_error = ""
    except Exception as exc:
        messages = []
        address.last_status = "error"
        address.last_error = str(exc)[:500]
    address.last_check_at = checked_at
    detail = classify_mail_fetch_error(address.last_error, "temp") if address.last_status != "ok" else {}
    result = {
        "source": "temp",
        "provider": "temp",
        "email": address.email,
        "ok": address.last_status == "ok",
        "checked_at": checked_at,
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
        "message_count": len(messages),
        "messages": messages,
        "errors": [] if address.last_status == "ok" else [address.last_error],
    }
    if detail:
        result.update({
            "error": detail["error_detail"],
            "error_code": detail["error_code"],
            "error_label": detail["error_label"],
            "error_hint": detail["error_hint"],
            "retryable": detail["retryable"],
        })
    apply_mail_fetch_result_fields(address, result)
    return result


def fetch_for_generic_account(
    account: GenericMailAccount,
    provider: str,
    limit: int,
    sender_filter: str,
    *,
    runtime: MailProtocolRuntime | None = None,
) -> dict[str, Any]:
    """执行单个通用邮箱账号取信并回写状态。"""
    runtime = _runtime(runtime)
    started = time.perf_counter()
    checked_at = _iso_now()
    used_provider = normalize_generic_mail_mode(provider if provider not in {"auto", ""} else account.mode)
    try:
        messages, used_provider = fetch_generic_messages(account, provider, limit=limit, sender_filter=sender_filter, runtime=runtime)
        account.last_status = "ok"
        account.last_error = ""
    except Exception as exc:
        messages = []
        account.last_status = "error"
        account.last_error = str(exc)[:500]
    account.last_check_at = checked_at
    detail = classify_mail_fetch_error(account.last_error, "generic") if account.last_status != "ok" else {}
    result = {
        "source": "generic",
        "provider": used_provider or account.mode or "auto",
        "email": account.email,
        "ok": account.last_status == "ok",
        "checked_at": checked_at,
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
        "message_count": len(messages),
        "messages": messages,
        "errors": [] if account.last_status == "ok" else [account.last_error],
    }
    if detail:
        result.update({
            "error": detail["error_detail"],
            "error_code": detail["error_code"],
            "error_label": detail["error_label"],
            "error_hint": detail["error_hint"],
            "retryable": detail["retryable"],
        })
    apply_mail_fetch_result_fields(account, result)
    return result


def run_mail_fetch_jobs(
    jobs: list[tuple[str, Any, str, int, str]],
    *,
    max_workers: int,
    runtime: MailProtocolRuntime | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    """按固定并发执行多账号取信任务。"""
    runtime = _runtime(runtime)

    def submit_job(kind: str, target: Any, provider: str, limit: int, sender_filter: str) -> dict[str, Any]:
        if kind == "microsoft" and isinstance(target, MailAccount):
            return fetch_for_account(target, provider, limit, sender_filter, runtime=runtime)
        if kind == "temp":
            return fetch_for_temp_address(target, limit, sender_filter, runtime=runtime)
        if kind == "generic" and isinstance(target, GenericMailAccount):
            return fetch_for_generic_account(target, provider, limit, sender_filter, runtime=runtime)
        return mail_fetch_error_result(kind, target, f"unsupported source: {kind}")

    return provider_run_mail_fetch_jobs(
        jobs,
        max_workers=max_workers,
        submit_job=submit_job,
        error_result=mail_fetch_error_result,
        progress_callback=progress_callback,
    )

__all__ = [
    "GRAPH_FOLDERS",
    "IMAP_FOLDERS",
    "MailProtocolRuntime",
    "append_imap_raw_message",
    "apply_mail_fetch_result_fields",
    "classify_mail_fetch_error",
    "fetch_cloudmail_messages",
    "fetch_for_account",
    "fetch_for_generic_account",
    "fetch_for_temp_address",
    "fetch_generic_imap_messages",
    "fetch_generic_messages",
    "fetch_generic_pop3_messages",
    "fetch_graph_messages",
    "fetch_imap_messages",
    "fetch_imap_messages_with_connection",
    "fetch_inbucket_messages",
    "fetch_luckmail_messages",
    "fetch_outlook_api_messages",
    "fetch_temp_messages",
    "get_graph_token",
    "get_imap_token",
    "mail_fetch_error_result",
    "microsoft_provider_sequence",
    "normalize_base_url",
    "normalize_cloudmail_messages",
    "normalize_inbucket_messages",
    "normalize_luckmail_messages",
    "open_imap_ssl",
    "open_imap_ssl_port",
    "refresh_microsoft_access_token",
    "run_mail_fetch_jobs",
    "temp_headers",
]
