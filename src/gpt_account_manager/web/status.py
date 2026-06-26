"""Web 状态与升级接口的流程装配。

这里承接 health / public-config / upgrade 这组 Web 状态接口；文件读写、时间和随机 ID
仍由兼容入口注入，避免 web 域反向依赖旧脚本或具体存储实现。
"""
from __future__ import annotations

from typing import Any, Callable

from .payloads import (
    build_health_payload,
    build_public_config_payload,
    build_public_top_links,
    build_upgrade_request_record,
    build_upgrade_request_response,
    build_upgrade_status_payload,
)


def health_payload(
    *,
    app_version: str,
    started_at: str,
    now: str,
    host: str,
    port: int,
    admin_token_set: bool,
    public_store_url: str,
    public_relay_url: str,
    public_pool_url: str,
    temp_worker_url: str,
    public_pool_api_url: bool,
    private_urls_allowed: bool,
    cpa_private_remote_allowed: bool,
    login_strategy: str,
    playwright_fallback: bool,
    accounts_file: Any,
    temp_addresses_file: Any,
    generic_accounts_file: Any,
    messages_file: Any,
    workspace_root: Any,
    root: Any,
    static_dir: Any,
    data_dir: Any,
    file_item_count_func: Callable[[Any, str], int],
) -> dict[str, Any]:
    """组装对外 health 响应，并把文件计数统一收口到 Web 状态层。"""
    return build_health_payload(
        app_name="gpt-account-manager",
        app_version=app_version,
        started_at=started_at,
        now=now,
        host=host,
        port=port,
        admin_token_set=admin_token_set,
        public_store_url=public_store_url,
        public_relay_url=public_relay_url,
        public_pool_url=public_pool_url,
        temp_worker_url=temp_worker_url,
        public_pool_api_url=public_pool_api_url,
        private_urls_allowed=private_urls_allowed,
        cpa_private_remote_allowed=cpa_private_remote_allowed,
        login_strategy=login_strategy,
        playwright_fallback=playwright_fallback,
        data_counts={
            "microsoft_accounts": file_item_count_func(accounts_file, "accounts"),
            "temp_addresses": file_item_count_func(temp_addresses_file, "addresses"),
            "generic_accounts": file_item_count_func(generic_accounts_file, "accounts"),
            "messages": file_item_count_func(messages_file, "messages"),
        },
        workspace_root=str(workspace_root),
        root=str(root),
        static_dir=str(static_dir),
        data_dir=str(data_dir),
    )


def public_top_links(
    *,
    public_store_url: str,
    public_relay_url: str,
    public_pool_url: str,
    normalize_base_url_func: Callable[[str], str],
) -> list[dict[str, str]]:
    """把公开站点候选地址转成前端首页链接。"""
    return build_public_top_links(
        [
            ("商城", public_store_url),
            ("中转站", public_relay_url),
            ("公益站", public_pool_url),
        ],
        normalize_base_url_func,
    )


def public_config_payload(
    *,
    title: str,
    version: str,
    store_url: str,
    relay_url: str,
    public_pool_url: str,
    public_pool_api_configured: bool,
    top_links: list[dict[str, str]],
) -> dict[str, Any]:
    """组装公开配置响应，保持旧前端字段不变。"""
    return build_public_config_payload(
        title=title,
        version=version,
        store_url=store_url,
        relay_url=relay_url,
        public_pool_url=public_pool_url,
        top_links=top_links,
        public_pool_api_configured=public_pool_api_configured,
    )


def upgrade_status_payload(
    *,
    app_version: str,
    request_file: Any,
    result_file: Any,
    load_json_file_func: Callable[[Any, Any], Any],
) -> dict[str, Any]:
    """读取升级请求/结果快照，并组装状态接口响应。"""
    request = load_json_file_func(request_file, {})
    result = load_json_file_func(result_file, {})
    return build_upgrade_status_payload(
        app_version=app_version,
        request_file=str(request_file),
        result_file=str(result_file),
        request=request if isinstance(request, dict) else {},
        result=result if isinstance(result, dict) else {},
    )


def create_upgrade_request(
    payload: dict[str, Any] | None = None,
    *,
    app_version: str,
    request_file: Any,
    result_file: Any,
    now: str,
    request_id: str,
    load_json_file_func: Callable[[Any, Any], Any],
    write_json_file_func: Callable[[Any, Any], None],
) -> dict[str, Any]:
    """创建升级请求，并保持旧接口的幂等返回语义。"""
    existing = load_json_file_func(request_file, {})
    current_status = upgrade_status_payload(
        app_version=app_version,
        request_file=request_file,
        result_file=result_file,
        load_json_file_func=load_json_file_func,
    )
    if isinstance(existing, dict) and existing.get("status") in {"requested", "running"}:
        return build_upgrade_request_response(
            request=existing,
            status_payload=current_status,
            already_pending=True,
        )
    request = build_upgrade_request_record(
        request_id=request_id,
        requested_at=now,
        current_version=app_version,
        target=str((payload or {}).get("target") or "origin/main").strip(),
    )
    write_json_file_func(request_file, request)
    return build_upgrade_request_response(
        request=request,
        status_payload=upgrade_status_payload(
            app_version=app_version,
            request_file=request_file,
            result_file=result_file,
            load_json_file_func=load_json_file_func,
        ),
        already_pending=False,
    )


__all__ = [
    "create_upgrade_request",
    "health_payload",
    "public_config_payload",
    "public_top_links",
    "upgrade_status_payload",
]
