"""登录域里的 OpenAI 客户端 helper。

这里先收纳单条凭证级别的刷新和探测逻辑：只负责调用 OpenAI /
ChatGPT 接口、整理错误字段和输出稳定状态，不直接落盘，也不编排
CPA 上传、生命周期回写或更大的登录主流程。
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Callable

from .oauth import access_token_expires_at, access_token_plan_type, classify_oauth_error, normal_plan_type


def _coerce_text(value: Any) -> str:
    """把任意值收敛成非空字符串判断用的文本。"""
    return str(value or "").strip()


def _first_text(*values: Any) -> str:
    """保持旧脚本的优先级，返回第一个非空文本。"""
    for value in values:
        text = _coerce_text(value)
        if text:
            return text
    return ""


def lifecycle_status_label(status: str) -> str:
    """把生命周期状态翻译成前端和日志可读的中文标签。"""
    return {
        "active": "可用",
        "refreshed": "已刷新",
        "rt_rotated": "已刷新并轮换 RT",
        "rt_invalid": "RT 失效",
        "session_expired": "会话失效",
        "banned": "封禁/停用",
        "risk_blocked": "风控/受限",
        "usage_limit_reached": "额度耗尽",
        "needs_login": "需要重新授权",
        "probe_failed": "探测失败",
        "not_openai_auth": "非 OpenAI 凭证",
        "mail_ok": "邮箱可用",
        "mail_dead": "邮箱不可用",
    }.get(status, status or "未知")


def lifecycle_source_auth(source: dict[str, Any]) -> dict[str, Any]:
    """从多种兼容输入里提取 auth 主体。

    生命周期刷新现在还同时兼容 `auth_file`、`authFile`、`session_json`
    和直接传整段对象；这里先把入口规整掉，避免上层编排反复写同样分支。
    """
    auth = source.get("auth_file") if isinstance(source.get("auth_file"), dict) else {}
    if not auth and isinstance(source.get("authFile"), dict):
        auth = source["authFile"]
    if not auth and isinstance(source.get("session_json"), dict):
        auth = source["session_json"]
    if not auth:
        auth = source
    return auth if isinstance(auth, dict) else {}


def normalize_lifecycle_item(item: dict[str, Any]) -> dict[str, Any]:
    """把刷新候选项规整成统一字段集合。

    这里只做兼容字段归并，不做网络探测、auth 转换或 CPA 上传；这样
    生命周期主流程后续下沉时，可以先复用统一输入，再单独拆编排动作。
    """
    auth = lifecycle_source_auth(item)
    tokens = auth.get("tokens") if isinstance(auth.get("tokens"), dict) else {}
    credentials = auth.get("credentials") if isinstance(auth.get("credentials"), dict) else {}
    token = auth.get("token") if isinstance(auth.get("token"), dict) else {}
    row = item.get("row") if isinstance(item.get("row"), dict) else {}
    email_addr = _first_text(
        item.get("email"),
        auth.get("email"),
        auth.get("account"),
        auth.get("name"),
        credentials.get("email"),
        row.get("email"),
        row.get("account"),
    )
    name = _first_text(item.get("name"), row.get("name"), auth.get("name"), email_addr)
    return {
        "email": email_addr,
        "name": name,
        "source": _coerce_text(item.get("source") or auth.get("source") or "manual"),
        "row": row,
        "auth_index": _first_text(item.get("auth_index"), row.get("auth_index"), auth.get("auth_index")),
        "access_token": _first_text(
            item.get("access_token"),
            item.get("accessToken"),
            auth.get("access_token"),
            auth.get("accessToken"),
            tokens.get("access_token"),
            tokens.get("accessToken"),
            token.get("access_token"),
            credentials.get("access_token"),
        ),
        "refresh_token": _first_text(
            item.get("chatgpt_refresh_token"),
            item.get("openai_refresh_token"),
            item.get("codex_refresh_token"),
            item.get("refresh_token"),
            item.get("refreshToken"),
            auth.get("chatgpt_refresh_token"),
            auth.get("openai_refresh_token"),
            auth.get("codex_refresh_token"),
            auth.get("refresh_token"),
            auth.get("refreshToken"),
            tokens.get("refresh_token"),
            tokens.get("refreshToken"),
            token.get("refresh_token"),
            credentials.get("refresh_token"),
        ),
        "session_token": _first_text(
            item.get("session_token"),
            item.get("sessionToken"),
            auth.get("session_token"),
            auth.get("sessionToken"),
            tokens.get("session_token"),
            tokens.get("sessionToken"),
            token.get("session_token"),
            credentials.get("session_token"),
        ),
        "id_token": _first_text(
            item.get("id_token"),
            item.get("idToken"),
            auth.get("id_token"),
            auth.get("idToken"),
            tokens.get("id_token"),
            tokens.get("idToken"),
            token.get("id_token"),
            credentials.get("id_token"),
        ),
        "original_auth": auth,
    }


def lifecycle_summary(results: list[dict[str, Any]], uploaded: int = 0) -> dict[str, Any]:
    """汇总生命周期刷新结果，供列表页和批量接口直接复用。"""
    return {
        "total": len(results),
        "active": sum(1 for item in results if item.get("ok")),
        "refreshed": sum(1 for item in results if item.get("status") in {"refreshed", "rt_rotated", "active"}),
        "invalid": sum(1 for item in results if item.get("status") in {"rt_invalid", "session_expired"}),
        "banned": sum(1 for item in results if item.get("status") == "banned"),
        "risk": sum(1 for item in results if item.get("status") == "risk_blocked"),
        "needs_login": sum(1 for item in results if item.get("status") == "needs_login"),
        "failed": sum(1 for item in results if not item.get("ok")),
        "uploaded": uploaded,
    }


def empty_lifecycle_result(normalized: dict[str, Any]) -> dict[str, Any]:
    """构造生命周期刷新前的默认结果骨架。

    这个结果代表“目前还没有任何可用凭证可刷”，后续主流程只需要在各分支
    上做增量更新，避免把默认状态、默认提示和基础字段散落在主流程里。
    """
    return {
        "email": normalized["email"],
        "name": normalized["name"],
        "source": normalized["source"],
        "auth_index": normalized["auth_index"],
        "status": "needs_login",
        "status_label": lifecycle_status_label("needs_login"),
        "message": "缺少 ChatGPT/Codex refresh_token、session_token 或 access_token",
        "ok": False,
        "plan_type": "",
        "access_token_updated": False,
        "refresh_token_rotated": False,
        "auth_file": None,
    }


def build_lifecycle_token_session_payload(
    *,
    email: str,
    access_token: str,
    refresh_token: str,
    id_token: str,
    session_token: str,
    expires_at: str,
) -> dict[str, Any]:
    """按生命周期刷新流程需要的字段组装 token 载荷。

    这里不关心这些 token 是从 refresh_token 刷新出来，还是从已有
    access_token 探测后回填出来；上层只需要给出最终字段值，就能得到
    一份后续 `session_to_cpa_auth` 可消费的统一载荷。
    """
    return {
        "email": email,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "session_token": session_token,
        "expires_at": expires_at,
    }


def build_lifecycle_session_payload_from_session_json(
    session_json: dict[str, Any],
    normalized: dict[str, Any],
    email: str,
) -> dict[str, Any]:
    """把 session 接口返回值补齐成生命周期后续可复用的载荷。

    ChatGPT session 接口返回的数据字段并不稳定，生命周期流程又需要保留
    原先已有的 refresh/session/id token；这里先把这些默认值补齐，避免
    主流程在 session 分支里重复维护同一组 `setdefault` 细节。
    """
    payload = dict(session_json)
    payload.setdefault("session_token", normalized["session_token"])
    payload.setdefault("refresh_token", normalized["refresh_token"])
    payload.setdefault("id_token", normalized["id_token"])
    payload.setdefault("email", email)
    return payload


def build_lifecycle_session_token_outcome(
    *,
    status: int,
    data: dict[str, Any],
    raw: str,
    normalized: dict[str, Any],
    email: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """根据 session_token 探测结果生成生命周期分支输出。

    这里仅负责把 session 接口的 HTTP 结果翻译成“后续 session_payload”
    和“当前 result 该怎么更新”两部分数据，不触碰网络请求本身，也不处理
    后续的 CPA auth 转换与上传。
    """
    if status == 200 and _first_text(data.get("accessToken"), data.get("access_token")):
        return (
            build_lifecycle_session_payload_from_session_json(data, normalized, email),
            {
                "status": "refreshed",
                "message": "session_token 已刷新出新的 access_token",
                "ok": True,
                "access_token_updated": True,
            },
        )
    if status == 401:
        return None, {"status": "session_expired", "message": "session_token 已失效", "ok": False}
    if status == 403:
        return None, {"status": "risk_blocked", "message": "session_token 探测触发风控或被拒绝", "ok": False}
    return None, {
        "status": "probe_failed",
        "message": _first_text(data.get("error"), data.get("message"), raw, f"HTTP {status}"),
        "ok": False,
    }


def build_lifecycle_refresh_token_outcome(
    *,
    status: int,
    data: dict[str, Any],
    raw: str,
    normalized: dict[str, Any],
    email: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """根据 refresh_token 刷新结果生成生命周期分支输出。

    这里仅负责把 RT 刷新接口的返回值翻译成“后续 session_payload”和
    “当前 result 的更新字段”，不发请求，也不处理刷新成功后的 CPA auth
    兼容转换。这样主流程可以继续只保留编排和异常兜底。
    """
    access_token = _coerce_text(data.get("access_token"))
    if access_token:
        new_refresh_token = _coerce_text(data.get("refresh_token")) or normalized["refresh_token"]
        refresh_token_rotated = new_refresh_token != normalized["refresh_token"]
        return (
            build_lifecycle_token_session_payload(
                email=email,
                access_token=access_token,
                refresh_token=new_refresh_token,
                id_token=_first_text(data.get("id_token"), normalized["id_token"]),
                session_token=normalized["session_token"],
                expires_at=access_token_expires_at(access_token),
            ),
            {
                "status": "rt_rotated" if refresh_token_rotated else "refreshed",
                "message": "refresh_token 已刷新出新的 access_token",
                "ok": True,
                "access_token_updated": True,
                "refresh_token_rotated": refresh_token_rotated,
            },
        )
    status_name, message = classify_oauth_error(status, data, raw)
    return None, {
        "status": status_name,
        "message": message,
        "ok": False,
    }


def build_lifecycle_access_token_outcome(
    *,
    probe: dict[str, Any],
    normalized: dict[str, Any],
    email: str,
    expires_at: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """根据 access_token 探测结果生成生命周期分支输出。

    这里复用既有 probe 结果，只负责把“当前结果字段怎么更新”和
    “后续 session_to_cpa_auth 需要的 token 载荷”拆出来；探测请求本身
    以及后续 CPA auth 转换，仍留给上层主流程处理。
    """
    result_update = {
        "status": _coerce_text(probe.get("status")),
        "message": _coerce_text(probe.get("message")),
        "ok": bool(probe.get("credential_ok")) or _coerce_text(probe.get("status")) == "active",
        "plan_type": _coerce_text(probe.get("plan_type")),
    }
    if not result_update["ok"]:
        return None, result_update
    return (
        build_lifecycle_token_session_payload(
            email=email,
            access_token=normalized["access_token"],
            refresh_token=normalized["refresh_token"],
            id_token=normalized["id_token"],
            session_token=normalized["session_token"],
            expires_at=expires_at,
        ),
        result_update,
    )


def build_lifecycle_auth_probe_result_update(
    *,
    auth_file: dict[str, Any],
    probe: dict[str, Any],
    current_result: dict[str, Any],
) -> dict[str, Any]:
    """根据 auth_file 和二次 probe 结果回填生命周期输出。

    这里假设上层已经完成 `session_to_cpa_auth` 转换，并且已经拿到了二次
    access_token 探测结果；本 helper 只负责把这些已知结果翻译成最终返回值，
    避免主流程反复散落 `plan_type`、封禁态和额度态的字段回填细节。
    """
    result_update: dict[str, Any] = {
        "probe": probe,
        "auth_file": auth_file,
        "email": auth_file.get("email") or current_result.get("email"),
        "name": auth_file.get("name") or current_result.get("name"),
        "expires_at": auth_file.get("expired", ""),
    }
    if probe.get("status") in {"active", "risk_blocked", "banned", "session_expired", "usage_limit_reached"}:
        result_update["plan_type"] = probe.get("plan_type") or auth_file.get("plan_type") or current_result.get("plan_type") or ""
        if probe.get("status") == "banned":
            result_update.update({"status": probe.get("status"), "message": probe.get("message"), "ok": False})
        elif probe.get("status") == "usage_limit_reached":
            result_update.update({"status": probe.get("status"), "message": probe.get("message"), "ok": True})
    return result_update


def openai_error_fields(data: dict[str, Any], raw: str) -> dict[str, Any]:
    """从 OpenAI 错误响应里抽取稳定字段。

    这里只做错误对象的整形，方便上层统一判断额度耗尽、风控和授权失败；
    是否重试、是否继续落盘都由上层流程决定。
    """
    err_obj = data.get("error") if isinstance(data, dict) else {}
    if not isinstance(err_obj, dict):
        err_obj = {}
    return {
        "code": _first_text(err_obj.get("code"), data.get("code") if isinstance(data, dict) else ""),
        "type": _first_text(err_obj.get("type"), data.get("type") if isinstance(data, dict) else ""),
        "message": _first_text(err_obj.get("message"), data.get("message") if isinstance(data, dict) else "", raw),
        "plan_type": normal_plan_type(_first_text(err_obj.get("plan_type"), data.get("plan_type") if isinstance(data, dict) else "")),
        "resets_at": err_obj.get("resets_at"),
        "resets_in_seconds": err_obj.get("resets_in_seconds"),
    }


def usage_limit_message(fields: dict[str, Any]) -> str:
    """把额度耗尽信息拼成统一中文提示。"""
    plan = fields.get("plan_type") or "unknown"
    parts = [f"OpenAI 已接受凭证，但账号额度已用完（{plan}）"]
    resets_at = fields.get("resets_at")
    try:
        reset_seconds = int(resets_at)
    except (TypeError, ValueError):
        reset_seconds = 0
    if reset_seconds > 0:
        reset_time = datetime.fromtimestamp(reset_seconds, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        parts.append(f"重置时间：{reset_time}")
    resets_in = fields.get("resets_in_seconds")
    try:
        wait_seconds = int(resets_in)
    except (TypeError, ValueError):
        wait_seconds = 0
    if wait_seconds > 0:
        hours = wait_seconds // 3600
        minutes = (wait_seconds % 3600) // 60
        if hours:
            parts.append(f"约 {hours} 小时 {minutes} 分钟后重置")
        else:
            parts.append(f"约 {minutes} 分钟后重置")
    return "；".join(parts)


def merge_session_with_oauth(session: dict[str, Any], oauth_payload: dict[str, Any]) -> dict[str, Any]:
    """把 ChatGPT session 和 OAuth token 响应合并成统一会话载荷。

    这里不发网络请求，也不决定后续是否写 CPA auth_file；只负责保持旧脚本
    的字段优先级，把 access/refresh/id token 和 expires_at 规整成后续流程
    可直接消费的一份 session 结构。
    """
    merged = dict(session or {})
    merged["access_token"] = _coerce_text(oauth_payload.get("access_token")) or _first_text(
        session.get("access_token"),
        session.get("accessToken"),
    )
    merged["accessToken"] = merged["access_token"]
    merged["refresh_token"] = _coerce_text(oauth_payload.get("refresh_token"))
    merged["refreshToken"] = merged["refresh_token"]
    merged["id_token"] = _coerce_text(oauth_payload.get("id_token")) or _first_text(
        session.get("id_token"),
        session.get("idToken"),
    )
    if merged["id_token"]:
        merged["idToken"] = merged["id_token"]
    if oauth_payload.get("expires_in"):
        try:
            expires_at = datetime.fromtimestamp(
                time.time() + int(oauth_payload["expires_in"]),
                timezone.utc,
            ).isoformat(timespec="seconds")
            merged["expires_at"] = expires_at
            merged["expires"] = expires_at
        except Exception:
            pass
    merged["oauth_token_type"] = _coerce_text(oauth_payload.get("token_type"))
    merged["oauth_scope"] = _coerce_text(oauth_payload.get("scope"))
    return merged


def refresh_openai_with_rt(
    refresh_token: str,
    *,
    token_url: str,
    client_id: str,
    refresh_scope: str,
    http_request_form_json_func: Callable[..., tuple[int, dict[str, Any], str]],
) -> tuple[int, dict[str, Any], str]:
    """用 refresh_token 向 OpenAI 换取新 access_token。

    这里固定 grant 参数，但不关心代理、DNS 和默认请求头细节；
    这些网络策略继续由上层注入的 HTTP helper 保持兼容。
    """
    return http_request_form_json_func(
        token_url,
        form_data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "scope": refresh_scope,
        },
        headers={"Accept": "application/json"},
        timeout=45,
    )


def exchange_openai_oauth_code(
    code: str,
    code_verifier: str,
    *,
    token_url: str,
    client_id: str,
    redirect_uri: str,
    user_agent: str,
    proxy_url: str,
    http_request_form_json_func: Callable[..., tuple[int, dict[str, Any], str]],
) -> tuple[int, dict[str, Any], str]:
    """用 OAuth authorization code 换取 OpenAI token 响应。

    这里只负责固定授权码兑换所需的表单字段；代理、请求头默认值和网络
    错误翻译仍由注入的 HTTP helper 负责，保持旧链路的行为不变。
    """
    return http_request_form_json_func(
        token_url,
        form_data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        headers={
            "Accept": "application/json",
            "User-Agent": user_agent,
        },
        timeout=60,
        proxy_url=proxy_url,
    )


def refresh_openai_with_session_token(
    session_token: str,
    *,
    session_url: str,
    http_get_json_status_func: Callable[..., tuple[int, dict[str, Any], str]],
) -> tuple[int, dict[str, Any], str]:
    """用 ChatGPT session_token 拉取新的会话 JSON。"""
    cookie = f"__Secure-next-auth.session-token={session_token}; __Secure-authjs.session-token={session_token}"
    return http_get_json_status_func(
        session_url,
        headers={
            "Accept": "application/json",
            "Cookie": cookie,
            "Referer": "https://chatgpt.com/",
        },
        timeout=45,
    )


def probe_openai_access_token(
    access_token: str,
    *,
    check_url: str,
    http_get_json_status_func: Callable[..., tuple[int, dict[str, Any], str]],
) -> dict[str, Any]:
    """探测 access_token 是否仍然可用，并收敛成稳定状态。

    这里只对 OpenAI 返回的状态码做翻译，帮助上层区分“需要重新登录”
    “额度耗尽”“风控拦截”和“暂时探测失败”，不负责决定后续补偿动作。
    """
    if not access_token:
        return {"status": "needs_login", "message": "缺少 access_token"}
    status, data, raw = http_get_json_status_func(
        check_url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Referer": "https://chatgpt.com/",
        },
        timeout=35,
    )
    result: dict[str, Any] = {
        "http_status": status,
        "status": "unknown",
        "plan_type": access_token_plan_type(access_token),
        "message": f"HTTP {status}",
    }
    if status == 200:
        account = data.get("accounts", {}).get("default") if isinstance(data.get("accounts"), dict) else {}
        entitlement = account.get("entitlement") if isinstance(account, dict) else {}
        plan = ""
        if isinstance(entitlement, dict):
            plan = normal_plan_type(entitlement.get("subscription_plan"))
            if not plan and entitlement.get("has_active_subscription") is False:
                plan = "free"
        result.update({
            "status": "active",
            "plan_type": plan or result["plan_type"] or "unknown",
            "message": "账号可用",
        })
    elif status == 401:
        result.update({"status": "session_expired", "message": "access_token 已过期或被撤销"})
    elif status == 403:
        text = json.dumps(data, ensure_ascii=False) if data else raw
        lowered = text.lower()
        state = "banned" if any(word in lowered for word in ["banned", "deactivated", "disabled", "封禁", "停用"]) else "risk_blocked"
        result.update({"status": state, "message": "账号封禁/停用或触发风控"})
    elif status == 429:
        fields = openai_error_fields(data, raw)
        lowered = " ".join(_coerce_text(fields.get(key)).lower() for key in ("code", "type", "message"))
        if "usage_limit_reached" in lowered or "usage limit has been reached" in lowered:
            result.update({
                "status": "usage_limit_reached",
                "plan_type": fields.get("plan_type") or result["plan_type"] or "free",
                "message": usage_limit_message(fields),
                "credential_ok": True,
                "usable": False,
                "resets_at": fields.get("resets_at"),
                "resets_in_seconds": fields.get("resets_in_seconds"),
            })
        else:
            result.update({"status": "probe_failed", "message": f"OpenAI 探测暂不可用：HTTP {status}"})
    elif status in {500, 502, 503, 504}:
        result.update({"status": "probe_failed", "message": f"OpenAI 探测暂不可用：HTTP {status}"})
    else:
        result.update({"status": "probe_failed", "message": f"OpenAI 探测失败：HTTP {status}"})
    return result


__all__ = [
    "build_lifecycle_access_token_outcome",
    "build_lifecycle_auth_probe_result_update",
    "build_lifecycle_refresh_token_outcome",
    "build_lifecycle_session_token_outcome",
    "build_lifecycle_session_payload_from_session_json",
    "build_lifecycle_token_session_payload",
    "empty_lifecycle_result",
    "exchange_openai_oauth_code",
    "lifecycle_summary",
    "lifecycle_source_auth",
    "lifecycle_status_label",
    "merge_session_with_oauth",
    "normalize_lifecycle_item",
    "openai_error_fields",
    "probe_openai_access_token",
    "refresh_openai_with_rt",
    "refresh_openai_with_session_token",
    "usage_limit_message",
]
