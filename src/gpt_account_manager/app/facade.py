"""应用层跨域编排入口。

这里承接需要串联 `login` 和 `cpa` 两个业务域的薄编排，不直接做文件、
网络或本地持久化 I/O；真正的 I/O 继续通过注入函数由外层兼容入口执行。
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from gpt_account_manager.login.api import (
    LoginFlowError,
    access_token_email,
    build_synthetic_id_token,
    jwt_payload,
    merge_session_with_oauth,
)


def _coerce_text(value: Any) -> str:
    """把跨域编排里要复用的值收敛成非空文本。"""
    return str(value or "").strip()


def _first_text(*values: Any) -> str:
    """保持旧脚本优先级，返回第一个非空文本。"""
    for value in values:
        text = _coerce_text(value)
        if text:
            return text
    return ""


def session_to_cpa_auth(
    session: dict[str, Any],
    fallback: dict[str, Any] | None = None,
    *,
    require_refresh_token: bool = False,
) -> dict[str, Any]:
    """把 ChatGPT session 规整成 CPA 可识别的 auth 文件。

    这是登录域结果和 CPA 域凭证格式之间的应用层转换：只读取 session /
    fallback 里的字段并补齐兼容字段，不做上传、落盘或网络探测，避免这段
    跨域装配继续堆在 `server.py`。
    """
    fallback = fallback or {}
    access_token = _first_text(
        session.get("accessToken"),
        session.get("access_token"),
        session.get("tokens", {}).get("accessToken") if isinstance(session.get("tokens"), dict) else "",
        session.get("tokens", {}).get("access_token") if isinstance(session.get("tokens"), dict) else "",
        session.get("token", {}).get("accessToken") if isinstance(session.get("token"), dict) else "",
        session.get("token", {}).get("access_token") if isinstance(session.get("token"), dict) else "",
        session.get("credentials", {}).get("access_token") if isinstance(session.get("credentials"), dict) else "",
    )
    if not access_token:
        raise RuntimeError("Session JSON 缺少 accessToken")

    session_token = _first_text(
        session.get("sessionToken"),
        session.get("session_token"),
        session.get("tokens", {}).get("sessionToken") if isinstance(session.get("tokens"), dict) else "",
        session.get("tokens", {}).get("session_token") if isinstance(session.get("tokens"), dict) else "",
    )
    refresh_token = _first_text(
        session.get("refreshToken"),
        session.get("refresh_token"),
        session.get("tokens", {}).get("refreshToken") if isinstance(session.get("tokens"), dict) else "",
        session.get("tokens", {}).get("refresh_token") if isinstance(session.get("tokens"), dict) else "",
    )
    if require_refresh_token and not refresh_token:
        raise RuntimeError("已登录 ChatGPT，但没有拿到 OpenAI OAuth refresh_token，不能作为可刷新 CPA 凭证")

    raw_id_token = _first_text(
        session.get("idToken"),
        session.get("id_token"),
        session.get("tokens", {}).get("idToken") if isinstance(session.get("tokens"), dict) else "",
        session.get("tokens", {}).get("id_token") if isinstance(session.get("tokens"), dict) else "",
    )
    id_token = raw_id_token
    payload = jwt_payload(access_token)
    id_payload = jwt_payload(id_token)
    auth = payload.get("https://api.openai.com/auth") if isinstance(payload.get("https://api.openai.com/auth"), dict) else {}
    id_auth = id_payload.get("https://api.openai.com/auth") if isinstance(id_payload.get("https://api.openai.com/auth"), dict) else {}
    profile = payload.get("https://api.openai.com/profile") if isinstance(payload.get("https://api.openai.com/profile"), dict) else {}
    user = session.get("user") if isinstance(session.get("user"), dict) else {}
    account = session.get("account") if isinstance(session.get("account"), dict) else {}

    email_addr = _first_text(
        user.get("email"),
        session.get("email"),
        session.get("credentials", {}).get("email") if isinstance(session.get("credentials"), dict) else "",
        profile.get("email"),
        id_payload.get("email"),
        payload.get("email"),
        fallback.get("email"),
    )
    account_id = _first_text(
        account.get("id"),
        session.get("account_id"),
        session.get("chatgptAccountId"),
        session.get("chatgpt_account_id"),
        auth.get("chatgpt_account_id"),
        id_auth.get("chatgpt_account_id"),
        fallback.get("auth_index"),
    )
    plan_type = _first_text(
        account.get("planType"),
        session.get("planType"),
        session.get("plan_type"),
        auth.get("chatgpt_plan_type"),
        id_auth.get("chatgpt_plan_type"),
    )

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        expires_at = datetime.fromtimestamp(exp, timezone.utc).isoformat(timespec="seconds")
    else:
        expires_at = _first_text(session.get("expires"), session.get("expiresAt"), session.get("expires_at"))
    if not id_token:
        id_token = build_synthetic_id_token(email_addr, account_id, plan_type, expires_at)

    return {
        key: value for key, value in {
            "type": "codex",
            "account_id": account_id,
            "chatgpt_account_id": account_id,
            "email": email_addr,
            "name": _first_text(email_addr, fallback.get("name"), "ChatGPT Account"),
            "plan_type": plan_type,
            "chatgpt_plan_type": plan_type,
            "id_token": id_token,
            "id_token_synthetic": not raw_id_token,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "session_token": session_token,
            "last_refresh": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "expired": expires_at,
        }.items() if value not in {"", None}
    }


def complete_oauth_code_payload(
    payload: dict[str, Any],
    code: str,
    code_verifier: str,
    *,
    request_proxy_url_func: Callable[[dict[str, Any] | None], str],
    exchange_openai_oauth_code_func: Callable[..., tuple[int, dict[str, Any], str]],
    protocol_compact_error_func: Callable[[Any], str],
    session_to_cpa_auth_func: Callable[..., dict[str, Any]],
    append_refresh_result_func: Callable[..., Any],
    replace_cpa_auth_file_func: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """完成 OAuth code -> session -> CPA auth 的跨域编排。

    这里把“登录域 token 换取 + 会话规整”和“CPA 域 auth 上传/结果拼装”
    串成一条薄链路，避免 `server.py` 继续同时堆放两个业务域的细节。
    真实的 HTTP 请求、本地写回和 CPA 上传都通过注入函数执行，应用层本身
    不直接碰 I/O。
    """
    if not code:
        raise RuntimeError("缺少 OAuth authorization code")
    if not code_verifier:
        raise RuntimeError("缺少 code_verifier，请重新生成授权链接")

    proxy_url = request_proxy_url_func(payload)
    status, data, raw = exchange_openai_oauth_code_func(code, code_verifier, proxy_url=proxy_url)
    if status != 200:
        compact = protocol_compact_error_func(data) or raw[:260]
        raise RuntimeError(f"OpenAI OAuth token exchange 失败：HTTP {status} - {compact}")
    if not _coerce_text(data.get("refresh_token")):
        raise RuntimeError("OpenAI OAuth token exchange 成功，但返回里没有 refresh_token")

    session = merge_session_with_oauth({}, data)
    email_addr = _coerce_text(payload.get("email")) or access_token_email(session.get("access_token", ""))
    if email_addr:
        session["email"] = email_addr
        session["user"] = {**(session.get("user") if isinstance(session.get("user"), dict) else {}), "email": email_addr}

    auth_file = session_to_cpa_auth_func(
        session,
        payload.get("row") if isinstance(payload.get("row"), dict) else {"email": email_addr},
        require_refresh_token=True,
    )
    append_refresh_result_func(
        auth_file,
        email=auth_file.get("email") or email_addr,
        job_id=_coerce_text(payload.get("job_id")),
    )

    row = payload.get("row") if isinstance(payload.get("row"), dict) else {}
    base_url = _coerce_text(payload.get("base_url") or payload.get("baseUrl") or row.get("cpa_base_url") or row.get("base_url"))
    management_key = _coerce_text(
        payload.get("management_key")
        or payload.get("managementKey")
        or row.get("cpa_management_key")
        or row.get("management_key")
    )
    if payload.get("require_cpa_update") and not (base_url and management_key):
        raise RuntimeError("缺少 CPA 地址或管理密钥，无法直接导出到 CPA")

    if base_url and management_key:
        cpa_name = _first_text(
            payload.get("name"),
            row.get("cpa_name"),
            row.get("name"),
            row.get("auth_index"),
            auth_file.get("name"),
            auth_file.get("email"),
        )
        result = replace_cpa_auth_file_func({
            "base_url": base_url,
            "management_key": management_key,
            "name": cpa_name,
            "auth_file": auth_file,
        })
        if not result.get("success"):
            raise RuntimeError(result.get("error") or "CPA 上传失败")
        result["auth_file"] = auth_file
        result["cpa_update"] = True
        result["local_oauth"] = True
        if isinstance(result.get("result"), dict):
            result["result"]["auth_file"] = auth_file
            result["result"]["local_oauth"] = True
        return result

    return {
        "success": True,
        "cpa_update": False,
        "auth_file": auth_file,
        "result": {
            "email": auth_file.get("email"),
            "name": auth_file.get("name"),
            "auth_file": auth_file,
            "message": "已生成 OAuth RT；未配置 CPA，未上传",
            "local_oauth": True,
        },
    }


def finalize_cpa_login_success(
    *,
    payload: dict[str, Any],
    session_payload: dict[str, Any],
    auth_file: dict[str, Any],
    replace_cpa_auth_file_func: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """把登录成功后的跨域收尾结果规整成最终返回值。

    这里假设上层已经完成登录、拿到 `session_payload/auth_file`，应用层只负责
    根据 `login_only`、`cpa_callback_only` 和 CPA 上传配置拼最终成功结果。
    真正的日志、任务状态流转和本地持久化仍由调用方掌控。
    """
    has_cpa = bool(_coerce_text(payload.get("base_url")) and _coerce_text(payload.get("management_key")))
    reg_password = session_payload.get("registration_password") if isinstance(session_payload, dict) else None

    if session_payload.get("cpa_callback_only"):
        result: dict[str, Any] = {
            "success": True,
            "cpa_update": True,
            "auth_file": auth_file,
            "result": {
                "email": auth_file.get("email"),
                "name": auth_file.get("name"),
                "auth_file": auth_file,
                "action": "cpa_oauth_callback",
                "message": "CPA OAuth 回调已提交",
                "ok": True,
                "cpa_oauth_result": session_payload.get("cpa_oauth_result"),
            },
        }
        if reg_password:
            result["registration_password"] = reg_password
            result["result"]["registration_password"] = reg_password
        return result

    if payload.get("login_only") and not has_cpa:
        result = {
            "success": True,
            "login_only": True,
            "auth_file": auth_file,
            "result": {
                "email": auth_file.get("email"),
                "name": auth_file.get("name"),
                "auth_file": auth_file,
                "action": "login_success",
                "message": "登录成功",
                "ok": True,
            },
        }
        if reg_password:
            result["registration_password"] = reg_password
            result["result"]["registration_password"] = reg_password
        return result

    cpa_payload = {
        "base_url": payload.get("base_url"),
        "management_key": payload.get("management_key"),
        "name": payload.get("name") or auth_file.get("email"),
        "auth_file": auth_file,
    }
    result = replace_cpa_auth_file_func(cpa_payload)
    if not result.get("success"):
        raise RuntimeError(result.get("error") or "CPA 上传失败")
    result["auth_file"] = auth_file
    if isinstance(result.get("result"), dict):
        result["result"]["auth_file"] = auth_file

    if payload.get("login_only"):
        result["login_only"] = True
    if reg_password:
        result["registration_password"] = reg_password
        if isinstance(result.get("result"), dict):
            result["result"]["registration_password"] = reg_password
    return result


def finalize_cpa_login_job_success(
    *,
    job_id: str,
    payload: dict[str, Any],
    session_payload: dict[str, Any],
    session_to_cpa_auth_func: Callable[..., dict[str, Any]],
    append_refresh_result_func: Callable[..., Any],
    replace_cpa_auth_file_func: Callable[[dict[str, Any]], dict[str, Any]],
    append_login_log_func: Callable[[str, str, str, str], None],
    workspace_file_func: Callable[[str, str], Path],
    coerce_text_func: Callable[[Any], str],
    finalize_cpa_login_success_func: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """收口 CPA 登录成功后的跨域收尾编排。

    这里把 `run_cpa_login_job(...)` 成功路径里最容易独立的后半段搬到应用层：
    session 转 auth、刷新结果持久化、CPA 上传前提示，以及最终成功日志选择。
    真实 I/O 仍通过注入函数执行，旧脚本只保留任务状态推进和异常分类。
    """
    auth_file = session_to_cpa_auth_func(
        session_payload,
        payload.get("row") if isinstance(payload.get("row"), dict) else {},
        require_refresh_token=not bool(payload.get("session_json")) and not bool(session_payload.get("cpa_callback_only")),
    )
    append_login_log_func(job_id, "Session 已转换为 CPA auth", "success", "convert")
    try:
        append_refresh_result_func(
            auth_file,
            email=auth_file.get("email") or payload.get("email"),
            job_id=job_id,
            path=workspace_file_func(payload.get("_workspace_id", "public"), "refresh_results.json"),
        )
        append_login_log_func(job_id, "已保存登录凭证至服务器", "info", "persist_success")
    except Exception as exc:
        append_login_log_func(job_id, f"持久化凭证失败: {str(exc)}", "warning", "persist_failed")

    if not session_payload.get("cpa_callback_only") and bool(coerce_text_func(payload.get("base_url")) and coerce_text_func(payload.get("management_key"))):
        append_login_log_func(job_id, "正在上传凭证至 CPA...", "info", "uploading")

    result = finalize_cpa_login_success_func(
        payload=payload,
        session_payload=session_payload,
        auth_file=auth_file,
        replace_cpa_auth_file_func=replace_cpa_auth_file_func,
    )

    if session_payload.get("cpa_callback_only"):
        append_login_log_func(job_id, "CPA 已通过 OAuth callback 自行更新凭证，跳过本地 auth JSON 覆盖", "success", "done")
    elif payload.get("login_only") and not bool(coerce_text_func(payload.get("base_url")) and coerce_text_func(payload.get("management_key"))):
        append_login_log_func(job_id, "账号登录完成（未配置 CPA，跳过上传）", "success", "done")
    elif payload.get("login_only"):
        append_login_log_func(job_id, "账号登录完成并已自动上传更新 CPA", "success", "done")
    else:
        append_login_log_func(job_id, "已上传 CPA auth，并完成探测", "success", "upload")
    return result


def resolve_cpa_login_session_payload(
    *,
    job_id: str,
    payload: dict[str, Any],
    require_login_proxy_url_func: Callable[[dict[str, Any]], str],
    coerce_text_func: Callable[[Any], str],
    append_login_log_func: Callable[[str, str, str, str], None],
    probe_egress_trace_func: Callable[[str], dict[str, Any]],
    sleep_func: Callable[[float], None],
    run_chatgpt_login_with_protocol_func: Callable[[str, dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """解析 CPA 登录任务所需的 session 来源。

    这里统一处理三种入口：直接传入 `session_json`、拒绝错误的 signup 模式，
    或按既有协议登录链路先做代理出口探测再去换取 session。这样
    `run_cpa_login_job(...)` 不再自己堆放这段跨 `login/infra` 的准备编排。
    """
    session_payload = payload.get("session_json") if isinstance(payload.get("session_json"), dict) else None
    if session_payload:
        append_login_log_func(job_id, "使用传入 Session JSON 转换 CPA", "info", "session")
        return session_payload
    if payload.get("mode") == "signup":
        raise RuntimeError("当前凭证刷新只走已有账号协议登录；注册新账号不是这条刷新链路。")

    proxy_url = require_login_proxy_url_func(payload)
    proxy_label = "已启用代理" if proxy_url else "未启用代理"
    append_login_log_func(job_id, f"使用 CPA OAuth 协议登录（{proxy_label}）", "info", "strategy")
    proxy_session = coerce_text_func(payload.get("proxy_session") or payload.get("proxySession") or payload.get("job_id") or payload.get("jobId"))
    if proxy_session:
        append_login_log_func(job_id, f"本轮代理粘性会话：{proxy_session[-8:]}", "info", "egress")
    try:
        trace = probe_egress_trace_func(proxy_url)
        ip = trace.get("ip") or "-"
        loc = trace.get("loc") or "-"
        colo = trace.get("colo") or "-"
        append_login_log_func(job_id, f"当前后端出口：ip={ip}，地区={loc}，节点={colo}（{proxy_label}）", "info", "egress")
        try:
            sleep_func(0.8)
            confirm_trace = probe_egress_trace_func(proxy_url)
            confirm_ip = confirm_trace.get("ip") or ""
            if confirm_ip and ip != "-" and confirm_ip != ip:
                raise LoginFlowError(
                    f"代理出口不稳定：同一账号会话检测到 {ip} -> {confirm_ip}",
                    code="proxy_ip_unstable",
                    hint="同一个账号的一轮 OAuth 需要稳定出口。已在发码前停止，请换一个新的代理 session 后重试。",
                    retryable=True,
                )
        except Exception as confirm_exc:
            if isinstance(confirm_exc, LoginFlowError):
                raise
            raise LoginFlowError(
                f"代理出口复检失败：{str(confirm_exc)[:140]}",
                code="proxy_ip_unstable",
                hint="同一个账号的一轮 OAuth 需要稳定出口。已在发码前停止，请换一个新的代理 session 后重试。",
                retryable=True,
            ) from confirm_exc
    except Exception as exc:
        if isinstance(exc, LoginFlowError):
            raise
        append_login_log_func(job_id, f"出口探测失败：{str(exc)[:180]}", "warning", "egress")
    return run_chatgpt_login_with_protocol_func(job_id, {**payload, "login_strategy": "protocol"})


def finalize_cpa_login_job_failure(
    *,
    job_id: str,
    exc: Exception,
    classify_login_exception_func: Callable[[Exception], dict[str, Any]],
    append_login_log_func: Callable[[str, str, str, str], None],
    set_login_job_status_func: Callable[..., None],
) -> None:
    """收口 CPA 登录任务的失败分类和终态更新。"""
    details = classify_login_exception_func(exc)
    message = details["message"][:800]
    append_login_log_func(job_id, message, "error", details.get("code") or "failed")
    if details.get("hint") and details.get("hint") != message:
        append_login_log_func(job_id, details["hint"], "warning", "hint")
    set_login_job_status_func(
        job_id,
        "failed",
        error=message,
        error_code=details.get("code"),
        error_hint=details.get("hint"),
        retryable=details.get("retryable", True),
        http_status=details.get("status"),
    )


def finalize_refresh_lifecycle_success(
    *,
    session_payload: dict[str, Any],
    normalized: dict[str, Any],
    email: str,
    current_result: dict[str, Any],
    session_to_cpa_auth_func: Callable[..., dict[str, Any]],
    probe_openai_access_token_func: Callable[[str], dict[str, Any]],
    build_lifecycle_auth_probe_result_update_func: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """完成生命周期刷新成功后的跨域收尾编排。

    各凭证分支如何生成 `session_payload` 已由 `login.service` 负责；这里仅在
    刷新已经成功后，串联 CPA auth 兼容转换、二次 access_token 探测，以及
    最终结果字段回填，避免这段 `login -> cpa` 的收尾逻辑继续留在 `server.py`。
    """
    fallback = dict(normalized.get("row") or {})
    fallback.setdefault("email", email)
    fallback.setdefault("name", normalized.get("name"))
    auth_file = session_to_cpa_auth_func(session_payload, fallback)
    original_auth = normalized.get("original_auth")
    if isinstance(original_auth, dict) and original_auth:
        auth_file = {**original_auth, **auth_file}
    probe = probe_openai_access_token_func(_coerce_text(auth_file.get("access_token")))
    return build_lifecycle_auth_probe_result_update_func(
        auth_file=auth_file,
        probe=probe,
        current_result=current_result,
    )


def refresh_lifecycle_item(
    item: dict[str, Any],
    *,
    normalize_lifecycle_item_func: Callable[[dict[str, Any]], dict[str, Any]],
    empty_lifecycle_result_func: Callable[[dict[str, Any]], dict[str, Any]],
    refresh_openai_with_rt_func: Callable[[str], tuple[int, dict[str, Any], str]],
    build_lifecycle_refresh_token_outcome_func: Callable[..., tuple[dict[str, Any] | None, dict[str, Any]]],
    refresh_openai_with_session_token_func: Callable[[str], tuple[int, dict[str, Any], str]],
    build_lifecycle_session_token_outcome_func: Callable[..., tuple[dict[str, Any] | None, dict[str, Any]]],
    probe_openai_access_token_func: Callable[[str], dict[str, Any]],
    build_lifecycle_access_token_outcome_func: Callable[..., tuple[dict[str, Any] | None, dict[str, Any]]],
    access_token_expires_at_func: Callable[[str], str],
    finalize_refresh_lifecycle_success_func: Callable[..., dict[str, Any]],
    lifecycle_status_label_func: Callable[[str], str],
) -> dict[str, Any]:
    """刷新单条生命周期记录，并在成功后做跨域收尾编排。

    这里把原来散在 `server.py` 的“选择 refresh/session/access token 分支”
    与“成功后转成 CPA auth 再回填结果”整合到应用层。真实的 token 刷新请求、
    session 探测和二次 probe 仍通过注入函数执行，避免 facade 直接承担 I/O。
    """
    normalized = normalize_lifecycle_item_func(item)
    email_addr = normalized["email"]
    result: dict[str, Any] = empty_lifecycle_result_func(normalized)

    session_payload: dict[str, Any] | None = None
    if normalized["refresh_token"]:
        status, data, raw = refresh_openai_with_rt_func(normalized["refresh_token"])
        session_payload, refresh_token_result_update = build_lifecycle_refresh_token_outcome_func(
            status=status,
            data=data,
            raw=raw,
            normalized=normalized,
            email=email_addr,
        )
        result.update(refresh_token_result_update)
    elif normalized["session_token"]:
        status, data, raw = refresh_openai_with_session_token_func(normalized["session_token"])
        session_payload, session_result_update = build_lifecycle_session_token_outcome_func(
            status=status,
            data=data,
            raw=raw,
            normalized=normalized,
            email=email_addr,
        )
        result.update(session_result_update)
    elif normalized["access_token"]:
        probe = probe_openai_access_token_func(normalized["access_token"])
        session_payload, access_token_result_update = build_lifecycle_access_token_outcome_func(
            probe=probe,
            normalized=normalized,
            email=email_addr,
            expires_at=access_token_expires_at_func(normalized["access_token"]),
        )
        result.update(access_token_result_update)

    if session_payload:
        try:
            result.update(
                finalize_refresh_lifecycle_success_func(
                    session_payload=session_payload,
                    normalized=normalized,
                    email=email_addr,
                    current_result=result,
                )
            )
        except Exception as exc:
            result.update({
                "status": "probe_failed",
                "message": f"刷新成功但转换 CPA auth 失败：{str(exc)[:220]}",
                "ok": False,
            })

    result["status_label"] = lifecycle_status_label_func(result["status"])
    return result


def refresh_lifecycle(
    payload: dict[str, Any],
    *,
    refresh_lifecycle_item_func: Callable[[dict[str, Any]], dict[str, Any]],
    lifecycle_summary_func: Callable[[list[dict[str, Any]], int], dict[str, Any]],
) -> dict[str, Any]:
    """批量刷新生命周期候选项。

    这一层只负责兼容 `items/auth_file/session_json/max_items` 的批量包装规则，
    以及把单条刷新结果汇总成既有响应结构；真正的单条刷新编排仍由
    `refresh_lifecycle_item_func` 承担。
    """
    items = payload.get("items")
    if not isinstance(items, list):
        items = []
    if isinstance(payload.get("auth_file"), dict):
        items.append({"auth_file": payload["auth_file"], "row": payload.get("row") if isinstance(payload.get("row"), dict) else {}})
    if isinstance(payload.get("session_json"), dict):
        items.append({"session_json": payload["session_json"], "row": payload.get("row") if isinstance(payload.get("row"), dict) else {}})
    if not items:
        return {"success": True, "results": [], "summary": lifecycle_summary_func([], 0)}

    max_items = max(1, min(int(payload.get("max_items") or payload.get("maxItems") or len(items) or 1), 100))
    results = [refresh_lifecycle_item_func(item) for item in items[:max_items] if isinstance(item, dict)]
    return {"success": True, "results": results, "summary": lifecycle_summary_func(results, 0)}


def refresh_cpa_lifecycle(
    payload: dict[str, Any],
    *,
    cpa_candidates_func: Callable[[dict[str, Any]], tuple[str, str, int, list[dict[str, Any]], int]],
    cpa_probe_status_func: Callable[[str, str, dict[str, Any]], dict[str, Any]],
    cpa_download_auth_file_func: Callable[[str, str, str], dict[str, Any]],
    refresh_lifecycle_item_func: Callable[[dict[str, Any]], dict[str, Any]],
    cpa_upload_auth_file_func: Callable[[str, str, str, dict[str, Any]], dict[str, Any]],
    lifecycle_summary_func: Callable[[list[dict[str, Any]], int], dict[str, Any]],
    lifecycle_status_label_func: Callable[[str], str],
) -> dict[str, Any]:
    """批量刷新 CPA 候选，并按需把成功结果回传到 CPA。

    这里负责承接原来 `server.py` 里“候选筛选 -> 可选 401 探测 -> 下载 auth ->
    调用生命周期刷新 -> 可选上传成功结果”的跨域批量编排。真实的 CPA 网络请求、
    单条生命周期刷新和最终汇总仍通过注入函数完成，应用层只保留流程胶水。
    失败路径也保持旧语义：下载或上传单条凭据失败时只回写该条结果，不中断整批。
    """
    base_url, management_key, max_items, candidates, _available_total = cpa_candidates_func(payload)
    upload_success = bool(payload.get("upload_success") or payload.get("uploadSuccess"))
    only_401 = bool(payload.get("only_401", True))
    rows = candidates
    if only_401:
        # 只把探测后仍是 401 的候选留给后续刷新，避免把正常账号也卷进重刷链路。
        probe_rows = [cpa_probe_status_func(base_url, management_key, item) for item in candidates]
        by_name = {_coerce_text(item.get("name")).lower(): item for item in probe_rows}
        rows = []
        for item in candidates:
            name = _coerce_text(item.get("name") or item.get("id"))
            probe = by_name.get(name.lower())
            if probe and probe.get("status_code") != 401:
                continue
            rows.append({**item, **(probe or {})})

    results: list[dict[str, Any]] = []
    uploaded = 0
    for row in rows[:max_items]:
        name = _coerce_text(row.get("name") or row.get("id"))
        auth_file: dict[str, Any] = {}
        if name:
            try:
                auth_file = cpa_download_auth_file_func(base_url, management_key, name)
            except Exception as exc:
                # 单条下载失败时沿用旧接口语义：记失败结果并继续下一条，不整批抛错。
                results.append({
                    "name": name,
                    "email": _coerce_text(row.get("email") or row.get("account")),
                    "status": "probe_failed",
                    "status_label": lifecycle_status_label_func("probe_failed"),
                    "message": f"下载 CPA auth 失败：{str(exc)[:220]}",
                    "ok": False,
                    "auth_file": None,
                })
                continue
        merged = {"auth_file": auth_file or row, "row": row, "name": name or _coerce_text(row.get("email"))}
        result = refresh_lifecycle_item_func(merged)
        result["name"] = name or result.get("name")
        if upload_success and result.get("ok") and isinstance(result.get("auth_file"), dict):
            upload = cpa_upload_auth_file_func(base_url, management_key, name or result.get("name", ""), result["auth_file"])
            result["upload"] = upload
            if upload.get("uploaded"):
                uploaded += 1
                result["action"] = "uploaded"
                result["message"] = f"{result.get('message', '刷新成功')}，已推送 CPA"
            else:
                # 上传失败要把单条结果降级成失败，避免前端误以为刷新已经完整闭环。
                result["ok"] = False
                result["status"] = "probe_failed"
                result["message"] = upload.get("error") or "推送 CPA 失败"
        results.append(result)

    return {
        "success": True,
        "results": results,
        "summary": lifecycle_summary_func(results, uploaded),
    }


def login_mail_credential_counts(
    payload: dict[str, Any],
    *,
    usable_secret_func: Callable[[Any], bool],
) -> dict[str, int]:
    """统计当前请求里可用的邮箱取码凭据数量。

    这里不区分凭据来自请求体还是后续工作区注水，只按既有规则统计三类邮箱
    凭据是否“可直接用来取码”。它同时服务登录 job 和前台取信入口，属于
    `login` 请求上下文与 `mail` 凭据结构之间的薄编排，不直接做任何 I/O。
    """
    microsoft = 0
    for item in payload.get("accounts", []):
        if not isinstance(item, dict):
            continue
        if usable_secret_func(item.get("client_id")) and usable_secret_func(item.get("refresh_token")):
            microsoft += 1
    temp = 0
    for item in payload.get("temp_addresses", []):
        if not isinstance(item, dict):
            continue
        if usable_secret_func(item.get("jwt")):
            temp += 1
    generic = 0
    for item in payload.get("generic_accounts", []):
        if not isinstance(item, dict):
            continue
        if usable_secret_func(item.get("password") or item.get("token")):
            generic += 1
    return {"microsoft": microsoft, "temp": temp, "generic": generic, "total": microsoft + temp + generic}


def hydrate_login_mail_credentials(
    payload: dict[str, Any],
    workspace_id: str = "public",
    *,
    coerce_text_func: Callable[[Any], str],
    usable_secret_func: Callable[[Any], bool],
    workspace_file_func: Callable[[str, str], Any],
    load_accounts_func: Callable[[Any], dict[str, Any]],
    load_temp_addresses_func: Callable[[Any], dict[str, Any]],
    load_generic_accounts_func: Callable[[Any], dict[str, Any]],
    login_mail_credential_counts_func: Callable[[dict[str, Any]], dict[str, int]],
    default_temp_worker_url: str,
) -> dict[str, int]:
    """按邮箱把工作区里已有的取码凭据注入到当前请求体。

    这条链会同时读取 `login` 请求里的目标邮箱、`workspace` 下的持久化凭据，
    并回填 `mail` 三类账号数组，所以放在 `app/facade` 做跨域注水最合适。
    真实的文件定位和 JSON 读取继续通过注入函数完成，应用层只负责匹配、
    合并和保持旧返回结构。失败路径保持宽松：没有目标邮箱、没有存量凭据或
    某类凭据仍是掩码时，都直接跳过该条，不把整次请求变成异常。
    """
    selected_emails = [
        coerce_text_func(item).lower()
        for item in payload.get("emails", [])
        if "@" in coerce_text_func(item)
    ]
    email_addr = coerce_text_func(payload.get("email")).lower()
    if "@" in email_addr:
        selected_emails.append(email_addr)
    selected_emails = list(dict.fromkeys(selected_emails))
    if not selected_emails:
        return {"microsoft": 0, "temp": 0, "generic": 0, "added": 0, "updated": 0}

    accounts = [item for item in payload.get("accounts", []) if isinstance(item, dict)]
    temp_addresses = [item for item in payload.get("temp_addresses", []) if isinstance(item, dict)]
    generic_accounts = [item for item in payload.get("generic_accounts", []) if isinstance(item, dict)]
    added = 0
    updated = 0

    stored_accounts = load_accounts_func(workspace_file_func(workspace_id, "accounts.json"))
    stored_temp_addresses = load_temp_addresses_func(workspace_file_func(workspace_id, "temp_addresses.json"))
    stored_generic_accounts = load_generic_accounts_func(workspace_file_func(workspace_id, "generic_accounts.json"))

    def same_email(item: dict[str, Any], target: str) -> bool:
        return coerce_text_func(item.get("email")).lower() == target

    # 先补齐 Microsoft OAuth 凭据，保证协议登录链路能优先拿到 refresh_token。
    for target_email in selected_emails:
        if any(same_email(item, target_email) and usable_secret_func(item.get("client_id")) and usable_secret_func(item.get("refresh_token")) for item in accounts):
            continue
        stored = stored_accounts.get(target_email)
        if stored and usable_secret_func(getattr(stored, "client_id", "")) and usable_secret_func(getattr(stored, "refresh_token", "")):
            stored_item = {
                "email": stored.email,
                "password": stored.password,
                "client_id": stored.client_id,
                "refresh_token": stored.refresh_token,
                "label": stored.label,
            }
            replaced = False
            for index, item in enumerate(accounts):
                if same_email(item, target_email):
                    accounts[index] = {**item, **stored_item}
                    replaced = True
                    updated += 1
                    break
            if not replaced:
                accounts.append(stored_item)
                added += 1

    # 再补临时邮箱 JWT，供邮箱验证码轮询在请求体缺口场景下继续复用旧取码入口。
    for target_email in selected_emails:
        if any(same_email(item, target_email) and usable_secret_func(item.get("jwt")) for item in temp_addresses):
            continue
        stored_temp = stored_temp_addresses.get(target_email)
        if stored_temp and usable_secret_func(getattr(stored_temp, "jwt", "")):
            stored_item = {
                "email": stored_temp.email,
                "jwt": stored_temp.jwt,
                "base_url": stored_temp.base_url or default_temp_worker_url,
                "site_password": stored_temp.site_password,
                "label": stored_temp.label,
            }
            replaced = False
            for index, item in enumerate(temp_addresses):
                if same_email(item, target_email):
                    temp_addresses[index] = {**item, **stored_item}
                    replaced = True
                    updated += 1
                    break
            if not replaced:
                temp_addresses.append(stored_item)
                added += 1

    # 最后补普通邮箱账号，保持三类邮箱凭据都按原来的 payload 字段回填。
    for target_email in selected_emails:
        if any(same_email(item, target_email) and usable_secret_func(item.get("password") or item.get("token")) for item in generic_accounts):
            continue
        stored_generic = stored_generic_accounts.get(target_email)
        if stored_generic and usable_secret_func(getattr(stored_generic, "password", "")):
            stored_item = {
                "email": stored_generic.email,
                "password": stored_generic.password,
                "username": stored_generic.username,
                "mode": stored_generic.mode,
                "imap_host": stored_generic.imap_host,
                "imap_port": stored_generic.imap_port,
                "pop3_host": stored_generic.pop3_host,
                "pop3_port": stored_generic.pop3_port,
                "label": stored_generic.label,
            }
            replaced = False
            for index, item in enumerate(generic_accounts):
                if same_email(item, target_email):
                    generic_accounts[index] = {**item, **stored_item}
                    replaced = True
                    updated += 1
                    break
            if not replaced:
                generic_accounts.append(stored_item)
                added += 1

    # 三类账号数组都要原地写回 payload，后续登录/取信入口继续按旧字段读取。
    payload["accounts"] = accounts
    payload["temp_addresses"] = temp_addresses
    payload["generic_accounts"] = generic_accounts
    counts = login_mail_credential_counts_func(payload)
    return {**counts, "added": added, "updated": updated}


def prepare_cpa_login_job_start(
    payload: dict[str, Any],
    workspace_id: str = "public",
    *,
    coerce_text_func: Callable[[Any], str],
    first_text_func: Callable[..., str],
    require_login_proxy_url_func: Callable[[dict[str, Any]], str],
    normalize_workspace_id_func: Callable[[Any], str],
    normalize_cpa_base_url_func: Callable[[str], str],
    generate_job_id_func: Callable[[], str],
    now_func: Callable[[], str],
    hydrate_login_mail_credentials_func: Callable[[dict[str, Any], str], dict[str, int]],
    login_mail_credential_counts_func: Callable[[dict[str, Any]], dict[str, int]],
    default_cpa_base_url: str,
) -> dict[str, Any]:
    """准备 CPA 登录任务的入队参数和初始 job 视图。

    这一层只负责“请求参数规整 -> 可选注入工作区邮箱凭据 -> 生成 job 初始结构”
    这段跨 `login/mail/workspace` 的准备流程，不直接操作内存任务表，也不启动
    线程。这样 `server.py` 仍掌控运行时副作用，而跨域准备逻辑可以离开旧脚本。
    失败路径继续沿用旧入口：邮箱、代理或 CPA 必填项不满足时，直接抛出
    原有 `RuntimeError`，不 silently fallback。
    """
    email_addr = coerce_text_func(payload.get("email"))
    if "@" not in email_addr:
        raise RuntimeError("请选择带邮箱的账号")

    # 这里保持旧规则：在真正入队前先校验当前请求是否满足登录代理要求。
    require_login_proxy_url_func(payload)

    login_only = bool(payload.get("login_only") or payload.get("loginOnly"))
    if not login_only and not coerce_text_func(payload.get("base_url") or payload.get("baseUrl")):
        raise RuntimeError("CPA 地址不能为空")
    if not login_only and not coerce_text_func(payload.get("management_key") or payload.get("managementKey")):
        raise RuntimeError("CPA 管理密钥不能为空")

    prepared_payload = dict(payload)
    job_id = generate_job_id_func()
    if coerce_text_func(prepared_payload.get("mode") or "login").lower() != "signup":
        # 旧链路默认强制邮箱验证码登录；这里继续保留对应默认值和清空密码规则。
        prepared_payload.setdefault("force_email_code", True)
        prepared_payload.setdefault("email_code_login", True)
        if str(first_text_func(prepared_payload.get("force_email_code"), prepared_payload.get("email_code_login"))).lower() in {"1", "true", "yes", "on"}:
            prepared_payload["password"] = ""

    prepared_payload["_workspace_id"] = normalize_workspace_id_func(workspace_id)
    prepared_payload["login_only"] = login_only
    prepared_payload["base_url"] = normalize_cpa_base_url_func(
        coerce_text_func(prepared_payload.get("base_url") or prepared_payload.get("baseUrl")) or default_cpa_base_url
    )
    prepared_payload["management_key"] = coerce_text_func(prepared_payload.get("management_key") or prepared_payload.get("managementKey"))
    prepared_payload["job_id"] = job_id

    # 这里只生成入队前的静态 job 视图；真正的任务入表、日志和线程启动仍在外层。
    job = {
        "job_id": job_id,
        "status": "queued",
        "state": "queued",
        "email": email_addr,
        "name": coerce_text_func(prepared_payload.get("name")),
        "logs": [],
        "result": None,
        "error": "",
        "created_at": now_func(),
        "updated_at": now_func(),
        "started_at": now_func(),
        "workspace_id": prepared_payload["_workspace_id"],
        "login_only": login_only,
        "site_url": prepared_payload.get("base_url") if not login_only or coerce_text_func(prepared_payload.get("base_url")) else "",
    }

    # 允许时先用工作区存量凭据补齐请求体；如果没有可用凭据，就保持原请求继续。
    mail_credential_summary: dict[str, int] = {}
    if prepared_payload.pop("_allow_stored_mail_credentials", False):
        mail_credential_summary = hydrate_login_mail_credentials_func(prepared_payload, prepared_payload["_workspace_id"])
    mail_credential_counts = login_mail_credential_counts_func(prepared_payload)
    return {
        "payload": prepared_payload,
        "job": job,
        "mail_credential_summary": mail_credential_summary,
        "mail_credential_counts": mail_credential_counts,
    }


__all__ = [
    "complete_oauth_code_payload",
    "finalize_cpa_login_success",
    "finalize_cpa_login_job_failure",
    "finalize_cpa_login_job_success",
    "finalize_refresh_lifecycle_success",
    "hydrate_login_mail_credentials",
    "login_mail_credential_counts",
    "prepare_cpa_login_job_start",
    "refresh_cpa_lifecycle",
    "refresh_lifecycle",
    "refresh_lifecycle_item",
    "resolve_cpa_login_session_payload",
]
