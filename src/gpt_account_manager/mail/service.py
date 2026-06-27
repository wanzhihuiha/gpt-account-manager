"""閭欢鍩熻处鍙峰鍏ヤ笌褰掍竴鍖栨湇鍔°€?
杩欎竴灞傚彧澶勭悊璐﹀彿鏂囨湰瑙ｆ瀽銆佸瓧娈靛綊涓€鍖栧拰瀹炰綋鏋勯€狅紝涓嶈鏂囦欢銆佷笉鍙戠綉缁滆姹傦紝
涔熶笉鐩存帴鍙備笌鍙栦俊娴佺▼锛屾柟渚挎妸 mail 鍩熸寜 service / model 缁х画鏀舵嫝銆?"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from typing import Callable
import os
import re
import urllib.parse

from .model.entity.account import GenericMailAccount, MailAccount, TempAddress
from .classifier import MAIL_TYPE_LABELS, normalize_mail_type
from .providers.rules import infer_generic_mail_config, normalize_generic_mail_mode
from gpt_account_manager.storage.workspace import (
    load_json_file as storage_load_json_file,
    write_json_file as storage_write_json_file,
)
from gpt_account_manager.storage.messages import (
    load_messages as storage_load_messages,
    message_key as storage_message_key,
    message_sort_value as storage_message_sort_value,
    save_messages as storage_save_messages,
    upsert_messages as storage_upsert_messages,
)


def _coerce_text(value: Any) -> str:
    """Internal helper."""
    return str(value or "").strip()


def _iso_now() -> str:
    """Internal helper."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _coerce_port(value: Any, default: int) -> int:
    """Internal helper."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 1 <= port <= 65535 else default



def _mail_fetch_max_concurrency() -> int:
    """Internal helper."""
    raw = str(os.environ.get("MAIL_PICKUP_FETCH_CONCURRENCY", "8") or "8").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 8
    return max(1, min(value, 16))


def _run_mail_fetch_jobs(
    jobs: list[tuple[str, MailAccount | TempAddress | GenericMailAccount, str, int, str]],
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    """Internal helper."""
    from .protocol import run_mail_fetch_jobs as protocol_run_mail_fetch_jobs

    return protocol_run_mail_fetch_jobs(
        jobs,
        max_workers=_mail_fetch_max_concurrency(),
        progress_callback=progress_callback,
    )

def _looks_like_provider_token(value: Any) -> bool:
    """Internal helper."""
    return normalize_generic_mail_mode(value) in {"cloudmail", "luckmail", "inbucket"}


def normalize_generic_account(account: GenericMailAccount) -> GenericMailAccount:
    """鎶婇€氱敤閭璐﹀彿琛ラ綈涓哄彲鎸佷箙鍖栧舰鎬併€?
    杩欓噷涓嶇鏂囦欢鎴栫綉缁滐紝鍙仛瀛楁瑙勬暣锛涗竴鏃﹁处鍙风己灏戝繀瑕佷俊鎭紝
    涓婂眰浠嶇劧鍙互缁х画淇濆瓨鍘熷瀵煎叆澶辫触缁撴灉銆?    """
    account.email = _coerce_text(account.email).lower()
    account.password = _coerce_text(account.password)
    account.mode = normalize_generic_mail_mode(account.mode)
    account.username = _coerce_text(account.username)
    if account.mode not in {"cloudmail", "luckmail", "inbucket"}:
        account.username = account.username or account.email
    inferred = infer_generic_mail_config(account.email)
    account.imap_host = _coerce_text(account.imap_host or inferred.get("imap_host"))
    account.pop3_host = _coerce_text(account.pop3_host or inferred.get("pop3_host"))
    if account.mode not in {"cloudmail", "luckmail", "inbucket"}:
        account.imap_host = account.imap_host.lower()
        account.pop3_host = account.pop3_host.lower()
    account.imap_port = _coerce_port(account.imap_port, 993)
    account.pop3_port = _coerce_port(account.pop3_port, 995)
    account.label = _coerce_text(account.label)
    return account


def parse_account_lines(text: str) -> tuple[list[MailAccount], list[str]]:
    """Internal helper."""
    accounts: list[MailAccount] = []
    errors: list[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        clean = line.strip().lstrip("\ufeff")
        if not clean or clean.startswith("#"):
            continue
        if "----" in clean:
            parts = [part.strip() for part in clean.split("----")]
        else:
            parts = [part.strip() for part in clean.split(",")]
        if len(parts) < 4:
            errors.append(f"Line {idx}: expected email----password----client_id----refresh_token")
            continue
        email_addr, password, client_id, refresh_token = parts[:4]
        if "@" not in email_addr or not client_id or not refresh_token:
            errors.append(f"Line {idx}: invalid account fields")
            continue
        accounts.append(MailAccount(
            email=email_addr,
            password=password,
            client_id=client_id,
            refresh_token=refresh_token,
            label=parts[4] if len(parts) >= 5 else "",
        ))
    return accounts, errors


def parse_temp_address_lines(text: str) -> tuple[list[TempAddress], list[str]]:
    """Internal helper."""
    addresses: list[TempAddress] = []
    errors: list[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        clean = line.strip().lstrip("\ufeff")
        if not clean or clean.startswith("#"):
            continue
        if "----" in clean:
            parts = [part.strip() for part in clean.split("----")]
        else:
            parts = [part.strip() for part in clean.split(",")]
        email_addr = parts[0] if parts else ""
        if "@" not in email_addr:
            errors.append(f"Line {idx}: invalid temp email")
            continue
        addresses.append(TempAddress(
            email=email_addr,
            jwt=parts[1] if len(parts) >= 2 else "",
            base_url=parts[2] if len(parts) >= 3 else "",
            site_password=parts[3] if len(parts) >= 4 else "",
            label=parts[4] if len(parts) >= 5 else "",
        ))
    return addresses, errors


def parse_generic_account_lines(text: str) -> tuple[list[GenericMailAccount], list[str]]:
    """Internal helper."""
    accounts: list[GenericMailAccount] = []
    errors: list[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        clean = line.strip().lstrip("\ufeff")
        if not clean or clean.startswith("#"):
            continue
        if "----" in clean:
            parts = [part.strip() for part in clean.split("----")]
        else:
            parts = [part.strip() for part in clean.split(",")]
        email_addr = parts[0] if parts else ""
        password = parts[1] if len(parts) >= 2 else ""
        if "@" not in email_addr:
            errors.append(f"Line {idx}: invalid generic email")
            continue
        if not password:
            errors.append(f"Line {idx}: missing password/token")
            continue
        third = parts[2] if len(parts) >= 3 else ""
        fourth = parts[3] if len(parts) >= 4 else ""
        fifth = parts[4] if len(parts) >= 5 else ""
        sixth = parts[5] if len(parts) >= 6 else ""
        mode = normalize_generic_mail_mode(fourth if fourth and not fourth.isdigit() else fifth)
        if mode == "auto" and third and _looks_like_provider_token(third):
            mode = normalize_generic_mail_mode(third)
            third = ""
        host_value = third if third and not third.isdigit() else ""
        imap_host = host_value if mode != "pop3" else ""
        pop3_host = host_value if mode == "pop3" else ""
        imap_port = _coerce_port(fourth if fourth.isdigit() else "", 993)
        pop3_port = _coerce_port(fourth if fourth.isdigit() else "", 995)
        username = fifth if mode == "luckmail" and fifth else ""
        label = ""
        if fourth.isdigit():
            label = sixth if _looks_like_provider_token(fifth) else fifth
        elif mode in {"cloudmail", "luckmail", "inbucket"}:
            label = sixth if mode == "luckmail" else fifth
        elif fifth:
            label = fifth
        account = GenericMailAccount(
            email=email_addr,
            password=password,
            username=username,
            mode=mode,
            imap_host=imap_host,
            imap_port=imap_port,
            pop3_host=pop3_host,
            pop3_port=pop3_port,
            label=label,
        )
        accounts.append(normalize_generic_account(account))
    return accounts, errors


def load_accounts(path: Path) -> dict[str, MailAccount]:
    """Internal helper."""
    raw = storage_load_json_file(path, {})
    rows = raw.get("accounts", []) if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return {}
    accounts: dict[str, MailAccount] = {}
    allowed = set(MailAccount.__dataclass_fields__.keys())
    for item in rows:
        if not isinstance(item, dict):
            continue
        try:
            clean = {key: item.get(key) for key in allowed if key in item}
            account = MailAccount(**clean)
            accounts[account.email.lower()] = account
        except TypeError:
            continue
    return accounts


def save_accounts(accounts: dict[str, MailAccount], path: Path) -> None:
    """Internal helper."""
    payload = {
        "updated_at": _iso_now(),
        "accounts": [asdict(acc) for acc in sorted(accounts.values(), key=lambda a: a.email.lower())],
    }
    storage_write_json_file(path, payload)


def load_temp_addresses(
    path: Path,
    *,
    default_base_url: str = "",
    normalize_temp_worker_url_func: Callable[[str], str] | None = None,
) -> dict[str, TempAddress]:
    """璇诲彇涓存椂閭 JSON銆?
    base_url 闇€瑕佺粨鍚堣皟鐢ㄦ柟鎻愪緵鐨?worker 榛樿鍊煎拰褰掍竴鍖栧嚱鏁帮紝
    杩欐牱 service 璐熻矗瀛楁瑙勬暣锛屽叿浣撻粯璁ゅ€间粛鐢变笂灞傜幆澧冨喅瀹氥€?    """
    raw = storage_load_json_file(path, {})
    rows = raw.get("addresses", []) if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return {}
    normalize_worker = normalize_temp_worker_url_func or (lambda value: value)
    addresses: dict[str, TempAddress] = {}
    allowed = set(TempAddress.__dataclass_fields__.keys())
    for item in rows:
        if not isinstance(item, dict):
            continue
        try:
            item = dict(item)
            item["base_url"] = normalize_worker(item.get("base_url") or item.get("baseUrl") or default_base_url)
            clean = {key: item.get(key) for key in allowed if key in item}
            address = TempAddress(**clean)
            addresses[address.email.lower()] = address
        except TypeError:
            continue
    return addresses


def save_temp_addresses(addresses: dict[str, TempAddress], path: Path) -> None:
    """Internal helper."""
    payload = {
        "updated_at": _iso_now(),
        "addresses": [asdict(addr) for addr in sorted(addresses.values(), key=lambda a: a.email.lower())],
    }
    storage_write_json_file(path, payload)


def load_generic_accounts(path: Path) -> dict[str, GenericMailAccount]:
    """Internal helper."""
    raw = storage_load_json_file(path, {})
    rows = raw.get("accounts", []) if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return {}
    accounts: dict[str, GenericMailAccount] = {}
    allowed = set(GenericMailAccount.__dataclass_fields__.keys())
    for item in rows:
        if not isinstance(item, dict):
            continue
        try:
            item = dict(item)
            item["mode"] = normalize_generic_mail_mode(item.get("mode") or item.get("provider"))
            item["imap_port"] = _coerce_port(item.get("imap_port") or item.get("imapPort"), 993)
            item["pop3_port"] = _coerce_port(item.get("pop3_port") or item.get("pop3Port"), 995)
            clean = {key: item.get(key) for key in allowed if key in item}
            account = normalize_generic_account(GenericMailAccount(**clean))
            accounts[account.email.lower()] = account
        except TypeError:
            continue
    return accounts


def save_generic_accounts(accounts: dict[str, GenericMailAccount], path: Path) -> None:
    """Internal helper."""
    payload = {
        "updated_at": _iso_now(),
        "accounts": [asdict(acc) for acc in sorted(accounts.values(), key=lambda a: a.email.lower())],
    }
    storage_write_json_file(path, payload)


def _is_masked_secret(value: Any) -> bool:
    """Internal helper."""
    text = _coerce_text(value)
    return bool(text and (set(text) <= {"*"} or "..." in text))


def _usable_secret(value: Any) -> bool:
    """Internal helper."""
    text = _coerce_text(value)
    return bool(text and not _is_masked_secret(text))


def transient_mail_accounts(payload: dict[str, Any]) -> tuple[list[MailAccount], list[str]]:
    """Internal helper."""
    accounts: list[MailAccount] = []
    errors: list[str] = []
    if payload.get("accounts_text"):
        parsed, parsed_errors = parse_account_lines(str(payload.get("accounts_text", "")))
        accounts.extend(parsed)
        errors.extend(parsed_errors)
    for idx, item in enumerate(payload.get("accounts", []), start=1):
        if not isinstance(item, dict):
            errors.append(f"Account {idx}: invalid object")
            continue
        email_addr = _coerce_text(item.get("email"))
        client_id = _coerce_text(item.get("client_id"))
        refresh_token = _coerce_text(item.get("refresh_token"))
        if "@" not in email_addr or not _usable_secret(client_id) or not _usable_secret(refresh_token):
            errors.append(f"Account {idx}: missing email/client_id/refresh_token")
            continue
        accounts.append(MailAccount(
            email=email_addr,
            password=_coerce_text(item.get("password")),
            client_id=client_id,
            refresh_token=refresh_token,
            label=_coerce_text(item.get("label") or item.get("category")),
        ))
    return accounts, errors


def transient_temp_addresses(
    payload: dict[str, Any],
    *,
    default_base_url: str = "",
    default_site_password: str = "",
    normalize_temp_worker_url_func: Callable[[str], str] | None = None,
) -> tuple[list[TempAddress], list[str]]:
    """Internal helper."""
    addresses: list[TempAddress] = []
    errors: list[str] = []
    if payload.get("temp_text"):
        parsed, parsed_errors = parse_temp_address_lines(str(payload.get("temp_text", "")))
        addresses.extend(parsed)
        errors.extend(parsed_errors)
    normalize_worker = normalize_temp_worker_url_func or (lambda value: value)
    for idx, item in enumerate(payload.get("temp_addresses", []), start=1):
        if not isinstance(item, dict):
            errors.append(f"Temp address {idx}: invalid object")
            continue
        email_addr = _coerce_text(item.get("email"))
        if "@" not in email_addr:
            errors.append(f"Temp address {idx}: invalid email")
            continue
        if not _usable_secret(item.get("jwt")):
            errors.append(f"Temp address {idx}: missing jwt")
            continue
        base_url = normalize_worker(_coerce_text(item.get("base_url") or item.get("baseUrl") or default_base_url))
        site_password = _coerce_text(item.get("site_password") or item.get("sitePassword") or default_site_password)
        addresses.append(TempAddress(
            email=email_addr,
            jwt=_coerce_text(item.get("jwt")),
            base_url=base_url,
            site_password=site_password,
            label=_coerce_text(item.get("label") or item.get("category")),
        ))
    return addresses, errors


def transient_generic_accounts(payload: dict[str, Any]) -> tuple[list[GenericMailAccount], list[str]]:
    """Internal helper."""
    accounts: list[GenericMailAccount] = []
    errors: list[str] = []
    if payload.get("generic_text"):
        parsed, parsed_errors = parse_generic_account_lines(str(payload.get("generic_text", "")))
        accounts.extend(parsed)
        errors.extend(parsed_errors)
    for idx, item in enumerate(payload.get("generic_accounts", []), start=1):
        if not isinstance(item, dict):
            errors.append(f"Generic account {idx}: invalid object")
            continue
        email_addr = _coerce_text(item.get("email"))
        password = _coerce_text(item.get("password") or item.get("token"))
        if "@" not in email_addr:
            errors.append(f"Generic account {idx}: invalid email")
            continue
        if not _usable_secret(password):
            errors.append(f"Generic account {idx}: missing password/token")
            continue
        accounts.append(normalize_generic_account(GenericMailAccount(
            email=email_addr,
            password=password,
            username=_coerce_text(item.get("username") or item.get("user")),
            mode=_coerce_text(item.get("mode") or item.get("provider")),
            imap_host=_coerce_text(item.get("imap_host") or item.get("imapHost") or item.get("base_url") or item.get("baseUrl") or item.get("api_url") or item.get("apiUrl")),
            imap_port=_coerce_port(item.get("imap_port") or item.get("imapPort"), 993),
            pop3_host=_coerce_text(item.get("pop3_host") or item.get("pop3Host")),
            pop3_port=_coerce_port(item.get("pop3_port") or item.get("pop3Port"), 995),
            label=_coerce_text(item.get("label") or item.get("category")),
        )))
    return accounts, errors


def import_pickup_accounts(payload: dict[str, Any], accounts_path: Path) -> dict[str, Any]:
    """Internal helper."""
    incoming, errors = parse_account_lines(str(payload.get("text", "")))
    accounts = load_accounts(accounts_path)
    imported = 0
    updated = 0
    skipped = 0
    replace_existing = True
    for account in incoming:
        key = account.email.lower()
        existing = accounts.get(key)
        if existing:
            if not replace_existing:
                skipped += 1
                continue
            account.created_at = existing.created_at
            updated += 1
        else:
            imported += 1
        accounts[key] = account
    if imported or updated:
        save_accounts(accounts, accounts_path)
    return {
        "success": True,
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "accounts": [acc.public() for acc in accounts.values()],
    }


def import_temp_addresses(
    payload: dict[str, Any],
    addresses_path: Path,
    *,
    default_base_url: str = "",
    default_site_password: str = "",
    normalize_temp_worker_url_func: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """Internal helper."""
    incoming, errors = parse_temp_address_lines(str(payload.get("text", "")))
    addresses = load_temp_addresses(
        addresses_path,
        default_base_url=default_base_url,
        normalize_temp_worker_url_func=normalize_temp_worker_url_func,
    )
    imported = 0
    updated = 0
    skipped = 0
    replace_existing = True
    normalize_worker = normalize_temp_worker_url_func or (lambda value: value)
    for address in incoming:
        key = address.email.lower()
        existing = addresses.get(key)
        if existing:
            if not replace_existing:
                skipped += 1
                continue
            address.created_at = existing.created_at
            if not _usable_secret(address.jwt):
                address.jwt = existing.jwt
            if not address.base_url:
                address.base_url = existing.base_url
            if not address.site_password:
                address.site_password = existing.site_password
            updated += 1
        else:
            imported += 1
        address.base_url = normalize_worker(address.base_url or default_base_url)
        address.site_password = address.site_password or default_site_password
        address.updated_at = _iso_now()
        addresses[key] = address
    if imported or updated:
        save_temp_addresses(addresses, addresses_path)
    return {
        "success": True,
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "addresses": [addr.public() for addr in addresses.values()],
    }


def import_generic_accounts(payload: dict[str, Any], accounts_path: Path) -> dict[str, Any]:
    """Internal helper."""
    incoming, errors = parse_generic_account_lines(str(payload.get("text", "")))
    accounts = load_generic_accounts(accounts_path)
    imported = 0
    updated = 0
    skipped = 0
    replace_existing = True
    for account in incoming:
        key = account.email.lower()
        existing = accounts.get(key)
        if existing:
            if not replace_existing:
                skipped += 1
                continue
            account.created_at = existing.created_at
            if not _usable_secret(account.password):
                account.password = existing.password
            if not account.username:
                account.username = existing.username
            if not account.imap_host:
                account.imap_host = existing.imap_host
            if not account.pop3_host:
                account.pop3_host = existing.pop3_host
            updated += 1
        else:
            imported += 1
        account.updated_at = _iso_now()
        accounts[key] = normalize_generic_account(account)
    if imported or updated:
        save_generic_accounts(accounts, accounts_path)
    return {
        "success": True,
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "accounts": [acc.public() for acc in accounts.values()],
    }


def delete_workspace_mail_credentials(
    payload: dict[str, Any],
    accounts_path: Path,
    temp_path: Path,
    generic_path: Path,
) -> dict[str, Any]:
    """Internal helper."""
    emails = [
        _coerce_text(item).lower()
        for item in payload.get("emails", [])
        if "@" in _coerce_text(item)
    ]
    unique = list(dict.fromkeys(emails))
    accounts = load_accounts(accounts_path)
    addresses = load_temp_addresses(temp_path)
    generic_accounts = load_generic_accounts(generic_path)
    deleted_microsoft = 0
    deleted_temp = 0
    deleted_generic = 0
    for email_addr in unique:
        if accounts.pop(email_addr, None) is not None:
            deleted_microsoft += 1
        if addresses.pop(email_addr, None) is not None:
            deleted_temp += 1
        if generic_accounts.pop(email_addr, None) is not None:
            deleted_generic += 1
    if deleted_microsoft:
        save_accounts(accounts, accounts_path)
    if deleted_temp:
        save_temp_addresses(addresses, temp_path)
    if deleted_generic:
        save_generic_accounts(generic_accounts, generic_path)
    return {
        "success": True,
        "emails": unique,
        "deleted": {
            "microsoft": deleted_microsoft,
            "temp": deleted_temp,
            "generic": deleted_generic,
            "total": deleted_microsoft + deleted_temp + deleted_generic,
        },
        "accounts": [acc.public() for acc in accounts.values()],
        "addresses": [addr.public() for addr in addresses.values()],
        "generic_accounts": [acc.public() for acc in generic_accounts.values()],
    }


def _normalize_base_url(value: str) -> str:
    """Internal helper."""
    clean = _coerce_text(value)
    if clean and not re.match(r"^https?://", clean, flags=re.I):
        clean = f"https://{clean}"
    return clean.rstrip("/")


def _validate_configured_base_url(base_url: str) -> None:
    """Internal helper."""
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError("configured temp worker URL must use http or https")
    if not parsed.hostname:
        raise RuntimeError("configured temp worker URL host missing")


def fetch_transient_client_mail(
    payload: dict[str, Any],
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    *,
    default_temp_worker_url: str = "",
    default_temp_site_password: str = "",
    normalize_temp_worker_url_func: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """鎸?payload 缁勮鍙栦俊浠诲姟骞舵墽琛岋紝杩斿洖缁熶竴缁撴灉缁撴瀯銆?
    杩欎竴灞傚彧璐熻矗缂栨帓璐﹀彿閫夋嫨銆佸熀纭€鏍￠獙鍜岀粨鏋滃悎骞讹紝涓嶇洿鎺ヨЕ纰?job
    鐢熷懡鍛ㄦ湡锛屼篃涓嶆妸浠诲姟鐘舵€佸啓鍥炵鐩橈紝鏂逛究鍚庣画鍐嶅崟鐙媶 job 灞傘€?    """
    accounts, account_errors = transient_mail_accounts(payload)
    temp_addresses, temp_errors = transient_temp_addresses(
        payload,
        default_base_url=default_temp_worker_url,
        default_site_password=default_temp_site_password,
        normalize_temp_worker_url_func=normalize_temp_worker_url_func,
    )
    generic_accounts, generic_errors = transient_generic_accounts(payload)
    if temp_addresses and not default_temp_worker_url and any(not address.base_url for address in temp_addresses):
        raise RuntimeError("GPT_ACCOUNT_MANAGER_TEMP_WORKER_URL is required for temp mailbox refresh")
    if temp_addresses:
        for address in temp_addresses:
            normalized = (normalize_temp_worker_url_func or (lambda value: value))(address.base_url or default_temp_worker_url)
            _validate_configured_base_url(normalized)
    for account in generic_accounts:
        if normalize_generic_mail_mode(account.mode) in {"cloudmail", "luckmail", "inbucket"} and account.imap_host:
            _validate_configured_base_url(_normalize_base_url(account.imap_host))

    selected = {email.lower() for email in payload.get("emails", []) if isinstance(email, str)}
    source = _coerce_text(payload.get("source") or "all").lower()
    provider = _coerce_text(payload.get("provider") or "auto").lower()
    sender_filter = _coerce_text(payload.get("sender_filter"))
    limit = max(1, min(int(payload.get("limit", 20) or 20), 50))
    jobs: list[tuple[str, MailAccount | TempAddress | GenericMailAccount, str, int, str]] = []

    if source in {"all", "microsoft"}:
        for account in accounts:
            if selected and account.email.lower() not in selected:
                continue
            jobs.append(("microsoft", account, provider, limit, sender_filter))
    if source in {"all", "temp"}:
        for address in temp_addresses:
            if selected and address.email.lower() not in selected:
                continue
            jobs.append(("temp", address, provider, limit, sender_filter))
    if source in {"all", "generic"}:
        for account in generic_accounts:
            if selected and account.email.lower() not in selected:
                continue
            jobs.append(("generic", account, provider, limit, sender_filter))

    results = _run_mail_fetch_jobs(jobs, progress_callback=progress_callback)
    messages = [message for result in results for message in result.get("messages", [])]
    failed_results = [result for result in results if not result.get("ok")]
    return {
        "results": results,
        "messages": sorted(messages, key=storage_message_sort_value, reverse=True),
        "errors": account_errors + temp_errors + generic_errors,
        "summary": {
            "total": len(results),
            "ok": len(results) - len(failed_results),
            "failed": len(failed_results),
            "messages": len(messages),
        },
        "types": MAIL_TYPE_LABELS,
    }


def fetch_saved_mail(
    payload: dict[str, Any],
    *,
    accounts_path: Path,
    temp_addresses_path: Path,
    generic_accounts_path: Path,
    messages_path: Path,
    workspace_messages_path: Path,
    default_temp_worker_url: str = "",
    normalize_temp_worker_url_func: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """鎸夊凡淇濆瓨璐﹀彿鎵ц鎵归噺鍙栦俊锛屽苟鎶婄紦瀛樹笌鍑嵁鍐欏洖鏈湴鏂囦欢銆?
    杩欐潯閾惧拰鍓嶇涓存椂鍙栦俊涓嶅悓锛氳处鍙锋潵婧愭槸鏈湴鎸佷箙鍖栨枃浠惰€屼笉鏄姹備綋锛屽洜姝や粛灞炰簬
    閭欢鍩熷唴鐨勨€滆处鍙疯杞?-> provider 璋冨害 -> 缂撳瓨鍐欏洖鈥濇祦绋嬶紝涓嶉渶瑕佷笂鍗囧埌
    `app/facade`銆倃orkspace 绾ф秷鎭紦瀛樿矾寰勭敱涓婂眰浼犲叆锛宻ervice 鍙礋璐ｆ墽琛屼笟鍔°€?    """
    accounts = load_accounts(accounts_path)
    temp_addresses = load_temp_addresses(
        temp_addresses_path,
        default_base_url=default_temp_worker_url,
        normalize_temp_worker_url_func=normalize_temp_worker_url_func,
    )
    generic_accounts = load_generic_accounts(generic_accounts_path)

    selected = [email.lower() for email in payload.get("emails", []) if isinstance(email, str)]
    provider = str(payload.get("provider", "auto"))
    sender_filter = str(payload.get("sender_filter", "")).strip()
    limit = max(1, min(int(payload.get("limit", 8)), 30))
    source = str(payload.get("source", "microsoft")).lower()

    targets = [
        account for key, account in accounts.items()
        if not selected or key in selected
    ]
    temp_targets = [
        address for key, address in temp_addresses.items()
        if not selected or key in selected
    ]
    generic_targets = [
        account for key, account in generic_accounts.items()
        if not selected or key in selected
    ]

    jobs: list[tuple[str, MailAccount | TempAddress | GenericMailAccount, str, int, str]] = []
    if source in {"microsoft", "all"}:
        jobs.extend(("microsoft", account, provider, limit, sender_filter) for account in targets)
    if source in {"temp", "all"}:
        jobs.extend(("temp", address, provider, limit, sender_filter) for address in temp_targets)
    if source in {"generic", "all"}:
        jobs.extend(("generic", account, provider, limit, sender_filter) for account in generic_targets)

    results = _run_mail_fetch_jobs(jobs)
    messages = [message for result in results for message in result.get("messages", [])]
    failed_results = [result for result in results if not result.get("ok")]

    storage_upsert_messages(messages, messages_path)
    storage_upsert_messages(messages, workspace_messages_path)
    save_accounts(accounts, accounts_path)
    save_temp_addresses(temp_addresses, temp_addresses_path)
    save_generic_accounts(generic_accounts, generic_accounts_path)

    return {
        "results": results,
        "summary": {
            "total": len(results),
            "ok": len(results) - len(failed_results),
            "failed": len(failed_results),
            "messages": len(messages),
        },
        "cached_count": len(messages),
    }


def filter_messages(messages: list[dict[str, Any]], payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Internal helper."""
    if not messages:
        return []
    query = _coerce_text(payload.get("query")).lower()
    sender = _coerce_text(payload.get("sender")).lower()
    source = _coerce_text(payload.get("source") or "all").lower()
    account = _coerce_text(payload.get("account")).lower()
    mail_type = _coerce_text(payload.get("mail_type") or payload.get("type") or "all").lower()
    category = _coerce_text(payload.get("category") or "all").lower()
    accounts_raw = payload.get("accounts")
    if isinstance(accounts_raw, list):
        accounts = {_coerce_text(item).lower() for item in accounts_raw if _coerce_text(item)}
    else:
        accounts = {
            item.strip().lower()
            for item in _coerce_text(accounts_raw).split(",")
            if item.strip()
        }
    filtered: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        message_account = _coerce_text(message.get("account") or message.get("recipient") or message.get("email")).lower()
        haystack = " ".join(_coerce_text(message.get(key)) for key in [
            "account", "sender", "subject", "preview", "body", "folder", "provider", "mail_type_label",
        ]).lower()
        if query and query not in haystack:
            continue
        if sender and sender not in _coerce_text(message.get("sender")).lower():
            continue
        if source != "all" and source != _coerce_text(message.get("source")).lower():
            continue
        normalized_message_type = normalize_mail_type(
            message.get("mail_type"),
            " ".join(_coerce_text(message.get(key)) for key in [
                "sender", "subject", "preview", "body", "html_body", "mail_type_label",
            ]),
        )
        if mail_type != "all" and mail_type != normalized_message_type:
            continue
        if category != "all" and category != _coerce_text(message.get("category")).lower():
            continue
        if accounts:
            if message_account not in accounts:
                continue
        elif account and account != message_account:
            continue
        filtered.append(message)
    return sorted(filtered, key=storage_message_sort_value, reverse=True)


def cached_messages_response(path: Path, payload: dict[str, Any], *, limit: int = 80, offset: int = 0) -> dict[str, Any]:
    """Internal helper."""
    try:
        limit = max(1, min(int(limit or 80), 500))
    except (TypeError, ValueError):
        limit = 80
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    messages = filter_messages(storage_load_messages(path), payload)
    return {
        "success": True,
        "messages": messages[offset:offset + limit],
        "count": len(messages),
        "offset": offset,
        "limit": limit,
        "types": MAIL_TYPE_LABELS,
    }


def remove_cached_message(message: dict[str, Any], path: Path) -> bool:
    """Internal helper."""
    key = storage_message_key(message)
    messages = storage_load_messages(path)
    kept = [item for item in messages if storage_message_key(item) != key]
    if len(kept) == len(messages):
        return False
    storage_save_messages(kept, path)
    return True


def delete_cached_mail_message(message: dict[str, Any], path: Path) -> dict[str, Any]:
    """Internal helper."""
    if not isinstance(message, dict):
        raise RuntimeError("缺少要删除的邮件")
    email_addr = _coerce_text(message.get("account"))
    if "@" not in email_addr:
        raise RuntimeError("邮件缺少所属邮箱，无法定位缓存")
    cache_removed = remove_cached_message(message, path)
    return {
        "success": True,
        "deleted": cache_removed,
        "cache_removed": cache_removed,
        "message": "缓存邮件删除处理完成。",
    }


def delete_cached_mail_messages(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    """Internal helper."""
    messages = storage_load_messages(path)
    raw_messages = payload.get("messages")
    if isinstance(raw_messages, list) and raw_messages:
        targets = [item for item in raw_messages if isinstance(item, dict)]
    else:
        filter_payload = payload.get("filter")
        if not isinstance(filter_payload, dict):
            raise RuntimeError("缺少待删除的消息列表或过滤条件")
        targets = filter_messages(messages, filter_payload)
    target_keys = {storage_message_key(item) for item in targets}
    if not target_keys:
        return {
            "success": True,
            "deleted": 0,
            "cache_removed": 0,
            "message": "没有匹配到需要清理的缓存邮件。",
        }
    kept = [item for item in messages if storage_message_key(item) not in target_keys]
    deleted = len(messages) - len(kept)
    if deleted:
        storage_save_messages(kept, path)
    return {
        "success": True,
        "deleted": deleted,
        "cache_removed": deleted,
        "message": "缓存邮件批量清理完成。",
    }


def delete_stored_mail_message(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    """Internal helper."""
    if isinstance(payload.get("messages"), list) or isinstance(payload.get("filter"), dict):
        return delete_cached_mail_messages(payload, path)
    return delete_cached_mail_message(payload.get("message") or {}, path)
