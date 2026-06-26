"""Web 响应装配函数。

这一层只负责把既有数据拼成 HTTP 响应所需的字典结构，
不直接读取文件、不直接发请求，便于后续把 Handler 继续拆薄。
"""
from __future__ import annotations

from typing import Any, Callable


def _coerce_text(value: Any) -> str:
    """把值收敛成可拼接字符串，供纯响应装配复用。"""
    return str(value or "").strip()


def success_payload() -> dict[str, Any]:
    """返回最基础的成功响应外壳。"""
    return {"success": True}


def error_payload(error: str) -> dict[str, Any]:
    """返回最基础的失败响应外壳。

    这里假定上层已经确定状态码和错误文本；web 层只保证 `success/error`
    这组字段稳定，避免 Handler 在简单失败路径里反复拼相同字典。
    """
    return {
        "success": False,
        "error": error,
    }


def plain_error_payload(error: str) -> dict[str, Any]:
    """返回只带 `error` 字段的兼容失败响应。

    旧接口里仍有一部分返回没有 `success` 标记，这里保持原样，避免前端或
    旧调用方依赖这个最小结构时被本轮结构重构意外影响。
    """
    return {"error": error}


def coded_error_payload(
    error: str,
    error_code: str,
    *,
    error_hint: str = "",
    retryable: bool | None = None,
) -> dict[str, Any]:
    """返回带错误码的失败响应。

    这一层只负责把上层已经决定好的错误文本、错误码和附加提示拼成统一
    JSON；具体异常分类、是否可重试的判断仍留在对应业务流程里完成。
    """
    payload = {
        "success": False,
        "error": error,
        "error_code": error_code,
    }
    if error_hint:
        payload["error_hint"] = error_hint
    if retryable is not None:
        payload["retryable"] = retryable
    return payload


def build_health_payload(
    *,
    app_name: str,
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
    data_counts: dict[str, int],
    workspace_root: str,
    root: str,
    static_dir: str,
    data_dir: str,
) -> dict[str, Any]:
    """组装健康检查页的数据快照。

    文件计数、路径和值都由上层先准备好，这里只做结构拼接，
    这样 web 层就能稳定只负责对外输出，不再自己碰存储细节。
    """
    return {
        "ok": True,
        "app": app_name,
        "version": app_version,
        "started_at": started_at,
        "now": now,
        "host": host,
        "port": port,
        "admin_token_set": admin_token_set,
        "urls": {
            "store": public_store_url,
            "relay": public_relay_url,
            "public_pool": public_pool_url,
            "temp_worker": temp_worker_url,
        },
        "features": {
            "public_pool_api": public_pool_api_url,
            "private_urls_allowed": private_urls_allowed,
            "cpa_private_remote_allowed": cpa_private_remote_allowed,
            "login_strategy": login_strategy,
            "playwright_fallback": playwright_fallback,
        },
        "data_counts": data_counts,
        "storage": {
            "workspace_scoped": True,
            "workspace_root": workspace_root,
        },
        "paths": {
            "root": root,
            "static": static_dir,
            "data": data_dir,
        },
    }


def build_public_config_payload(
    *,
    title: str,
    version: str,
    store_url: str,
    relay_url: str,
    public_pool_url: str,
    top_links: list[dict[str, str]],
    public_pool_api_configured: bool,
) -> dict[str, Any]:
    """组装公开配置页返回值。

    这里不直接碰环境变量或路由，只把上层已经整理好的公开站点
    信息拼成前端可消费的 JSON。
    """
    return {
        "title": title,
        "version": version,
        "store_url": store_url,
        "relay_url": relay_url,
        "public_pool_url": public_pool_url,
        "top_links": top_links,
        "public_pool_api_configured": public_pool_api_configured,
    }


def build_public_top_links(
    candidates: list[tuple[str, str]],
    normalize_base_url: Callable[[str], str],
) -> list[dict[str, str]]:
    """把公开站点候选地址收敛成前端可直接渲染的链接列表。"""
    links: list[dict[str, str]] = []
    for label, url in candidates:
        normalized = normalize_base_url(url)
        if normalized:
            links.append({"label": label, "url": normalized})
    return links


def build_upgrade_status_payload(
    *,
    app_version: str,
    request_file: str,
    result_file: str,
    request: dict[str, Any],
    result: dict[str, Any],
    agent_mode: str = "host-timer",
    agent_enabled_by: str = "deploy/gpt-account-manager-upgrade-agent.timer",
) -> dict[str, Any]:
    """组装升级状态返回值。

    上层先把 request/result 从本地文件读出来，这里只负责把它们
    拼成一致的 API 结构，避免 web 层继续掺杂文件读写细节。
    """
    return {
        "success": True,
        "version": app_version,
        "request_file": request_file,
        "result_file": result_file,
        "agent": {
            "mode": agent_mode,
            "enabled_by": agent_enabled_by,
        },
        "request": request,
        "result": result,
    }


def build_upgrade_request_record(
    *,
    request_id: str,
    requested_at: str,
    current_version: str,
    target: str,
    note: str = "host upgrade agent will run git pull and docker compose rebuild",
) -> dict[str, Any]:
    """组装升级请求落盘记录。

    这里不生成随机 ID、不写文件，也不判断是否已有待处理请求；web 层只把
    上层已经决定好的字段收敛成稳定 JSON，便于旧入口继续保留幂等判断和 I/O。
    """
    return {
        "id": request_id,
        "status": "requested",
        "requested_at": requested_at,
        "current_version": current_version,
        "target": _coerce_text(target) or "origin/main",
        "note": note,
    }


def build_upgrade_request_response(
    *,
    request: dict[str, Any],
    status_payload: dict[str, Any],
    already_pending: bool,
) -> dict[str, Any]:
    """组装升级请求接口返回值。

    这里不关心请求是刚创建还是命中了既有待处理记录，只负责保证接口继续
    返回既有的 `success/already_pending/request/status` 四段结构。
    """
    return {
        "success": True,
        "already_pending": already_pending,
        "request": request,
        "status": status_payload,
    }


def lightweight_mail_fetch_result(
    result: dict[str, Any],
    *,
    normalize_mail_type_func: Callable[[Any, str], str],
) -> dict[str, Any]:
    """压缩单条取信结果，保留前端要看的摘要字段。

    Web 层只负责结果摘要装配，邮件类型归一化能力由上层以注入函数的方式提供。
    """
    clean = dict(result)
    messages = clean.get("messages") if isinstance(clean.get("messages"), list) else []
    codes: list[str] = []
    has_verification_code = False
    for message in messages:
        if not isinstance(message, dict):
            continue
        message_codes = [_coerce_text(code) for code in message.get("codes", []) if _coerce_text(code)]
        codes.extend(message_codes)
        message_text = " ".join(
            _coerce_text(message.get(key))
            for key in ["sender", "subject", "preview", "body", "html_body", "mail_type_label"]
        )
        # 这里只做结果摘要，不改邮件分类规则；分类仍由上层注入的 mail 域能力完成。
        if message_codes or normalize_mail_type_func(message.get("mail_type"), message_text) == "verification":
            has_verification_code = True
    clean["message_count"] = int(clean.get("message_count") or len(messages))
    clean["codes"] = list(dict.fromkeys(codes))[:10]
    clean["first_code"] = clean["codes"][0] if clean["codes"] else ""
    clean["has_verification_code"] = has_verification_code
    clean["messages"] = []
    return clean


def lightweight_fetch_result(
    result: dict[str, Any],
    *,
    cached_count: int = 0,
    normalize_mail_type_func: Callable[[Any, str], str],
) -> dict[str, Any]:
    """压缩批量取信结果，保留轮询和列表页需要的摘要字段。

    这里只做批量结果的纯装配，避免 web 层直接依赖业务域的分类规则。
    """
    clean = dict(result)
    clean["results"] = [
        lightweight_mail_fetch_result(item, normalize_mail_type_func=normalize_mail_type_func)
        if isinstance(item, dict) else item
        for item in (clean.get("results") or [])
    ]
    clean["messages"] = []
    clean["cached_messages"] = cached_count
    return clean


def delete_transient_client_mail_message_payload() -> dict[str, Any]:
    """给前端返回临时邮箱删除的固定说明。

    这里不做任何删除动作，只说明前端缓存已经清理、远端真实邮箱不受影响；
    这类响应适合留在 web 层，避免旧脚本继续夹杂页面文案。
    """
    return {
        "success": True,
        "deleted": False,
        "cache_removed": False,
        "message": "当前浏览器缓存已在前端清理，不会删除远端真实邮箱邮件",
    }


def disabled_cpa_refresh_path_payload(kind: str) -> dict[str, Any]:
    """返回已停用凭证刷新入口的固定错误说明。

    这里只负责页面/接口文案装配，不决定哪些路由停用；具体停用判断仍留给
    Handler，这样 web 层可以先把重复响应收口，再逐步把路由逻辑下沉。
    """
    messages = {
        "companion_wait_code": "Companion 扩展路径已停用；凭证刷新只走 CPA OAuth 协议登录。",
        "manual_oauth": "手动 OAuth 路径已停用；凭证刷新只走 CPA OAuth 协议登录。",
        "local_oauth": "本机浏览器 OAuth 路径已停用；凭证刷新只走 CPA OAuth 协议登录。",
    }
    return {
        "success": False,
        "error": messages.get(kind, "当前路径已停用。"),
    }


def account_list_payload(accounts: list[Any]) -> dict[str, Any]:
    """组装 Microsoft/通用邮箱账号列表响应。

    这里假定上层已经拿到了账号实体列表；web 层只负责调用实体的公开视图，
    避免 Handler 在多个路由里重复写相同的列表推导。
    """
    return {"accounts": [account.public() for account in accounts]}


def temp_address_list_payload(addresses: list[Any]) -> dict[str, Any]:
    """组装临时邮箱列表响应，保持既有 `addresses` 字段名不变。"""
    return {"addresses": [address.public() for address in addresses]}


def refresh_results_payload(results: list[dict[str, Any]]) -> dict[str, Any]:
    """组装刷新结果列表响应。"""
    return {"results": results}


def login_history_payload(history: list[dict[str, Any]]) -> dict[str, Any]:
    """组装登录历史列表响应。"""
    return {"history": history}


def deleted_account_list_payload(deleted_count: int, accounts: list[Any]) -> dict[str, Any]:
    """组装账号删除后的剩余列表响应。"""
    return {
        "deleted": deleted_count,
        "accounts": [account.public() for account in accounts],
    }


def deleted_temp_address_list_payload(deleted_count: int, addresses: list[Any]) -> dict[str, Any]:
    """组装临时邮箱删除后的剩余列表响应。"""
    return {
        "deleted": deleted_count,
        "addresses": [address.public() for address in addresses],
    }


def message_search_payload(messages: list[dict[str, Any]], mail_type_labels: dict[str, str]) -> dict[str, Any]:
    """组装消息搜索响应。

    搜索过滤和 limit 截断继续由上层完成，这里只保证返回字段结构稳定，
    方便 Handler 不再重复维护 `messages/count/types` 这组固定外壳。
    """
    return {
        "messages": messages,
        "count": len(messages),
        "types": mail_type_labels,
    }


def imported_account_list_payload(
    *,
    imported: int,
    skipped: int,
    updated: int,
    errors: list[Any],
    accounts: list[Any],
) -> dict[str, Any]:
    """组装账号导入后的汇总响应。"""
    return {
        "imported": imported,
        "skipped": skipped,
        "updated": updated,
        "errors": errors,
        "accounts": [account.public() for account in accounts],
    }


def imported_temp_address_list_payload(
    *,
    imported: int,
    skipped: int,
    updated: int,
    errors: list[Any],
    addresses: list[Any],
) -> dict[str, Any]:
    """组装临时邮箱导入后的汇总响应。"""
    return {
        "imported": imported,
        "skipped": skipped,
        "updated": updated,
        "errors": errors,
        "addresses": [address.public() for address in addresses],
    }
