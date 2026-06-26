"""邮件账号实体。

本模块只描述邮件域账号在本地运行时需要保存的字段和脱敏展示方式，
不负责读写文件、不负责取信，也不直接触发外部网络请求。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _iso_now() -> str:
    """生成实体默认时间戳，格式保持与旧入口一致。"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _mask_secret(value: str, keep: int = 4) -> str:
    """对外展示实体时隐藏密钥；空值直接返回空字符串作为失败兜底。"""
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"


@dataclass
class MailAccount:
    """Microsoft 邮箱账号实体。

    这里只保存账号凭据和最近一次取信状态；真正的 OAuth、Graph、IMAP
    请求会继续放在邮件 service/job 或 infra 中处理。
    """

    email: str
    client_id: str
    refresh_token: str
    password: str = ""
    label: str = ""
    created_at: str = field(default_factory=_iso_now)
    updated_at: str = field(default_factory=_iso_now)
    last_check_at: str = ""
    last_status: str = "idle"
    last_error: str = ""
    last_error_code: str = ""
    last_error_label: str = ""
    last_error_hint: str = ""
    last_message_count: int = 0

    def public(self) -> dict[str, Any]:
        """返回前端可展示的账号快照，并在输出前统一脱敏敏感字段。"""
        data = asdict(self)
        data["password"] = _mask_secret(self.password)
        data["refresh_token"] = _mask_secret(self.refresh_token)
        data["client_id"] = _mask_secret(self.client_id, keep=8)
        return data


@dataclass
class TempAddress:
    """临时邮箱账号实体。

    临时邮箱只记录访问 worker 所需的凭据和展示状态；接口调用、失败重试
    和消息标准化不放在实体里，避免模型层带上 I/O 职责。
    """

    email: str
    jwt: str = ""
    base_url: str = ""
    site_password: str = ""
    label: str = ""
    created_at: str = field(default_factory=_iso_now)
    updated_at: str = field(default_factory=_iso_now)
    last_check_at: str = ""
    last_status: str = "idle"
    last_error: str = ""
    last_error_code: str = ""
    last_error_label: str = ""
    last_error_hint: str = ""
    last_message_count: int = 0

    def public(self) -> dict[str, Any]:
        """返回前端可展示的临时邮箱快照，并隐藏 worker 访问凭据。"""
        data = asdict(self)
        data["jwt"] = _mask_secret(self.jwt)
        data["site_password"] = _mask_secret(self.site_password)
        return data


@dataclass
class GenericMailAccount:
    """通用邮箱账号实体。

    该实体覆盖 IMAP、POP3 以及云邮箱类模式，只保存连接参数和状态；
    协议判断与服务器推断仍由邮件域服务函数处理。
    """

    email: str
    password: str = ""
    username: str = ""
    mode: str = "auto"
    imap_host: str = ""
    imap_port: int = 993
    pop3_host: str = ""
    pop3_port: int = 995
    label: str = ""
    created_at: str = field(default_factory=_iso_now)
    updated_at: str = field(default_factory=_iso_now)
    last_check_at: str = ""
    last_status: str = "idle"
    last_error: str = ""
    last_error_code: str = ""
    last_error_label: str = ""
    last_error_hint: str = ""
    last_message_count: int = 0

    def public(self) -> dict[str, Any]:
        """返回前端可展示的通用邮箱快照，并隐藏邮箱登录密码。"""
        data = asdict(self)
        data["password"] = _mask_secret(self.password)
        return data
