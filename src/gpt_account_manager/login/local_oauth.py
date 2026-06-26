"""本机 OAuth 回调支路。

这里专门收口工具端生成授权链接、缓存本机 OAuth 流程状态，以及监听
`/auth/callback` 的本地 HTTP 回调。真正的 code -> token -> CPA 收口
仍由上层注入，避免这个模块反向依赖旧的 `server.py` 主流程。
"""
from __future__ import annotations

import html
import os
import secrets
import threading
import urllib.parse
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .oauth_flow import generate_openai_code_verifier


LOCAL_OAUTH_FLOWS: dict[str, dict[str, Any]] = {}
LOCAL_OAUTH_LOCK = threading.Lock()
LOCAL_OAUTH_SERVER: ThreadingHTTPServer | None = None
LOCAL_OAUTH_THREAD: threading.Thread | None = None
LOCAL_OAUTH_PORT = int(os.environ.get("MAIL_PICKUP_LOCAL_OAUTH_PORT", "1455") or 1455)

_LOCAL_OAUTH_NOW_FUNC: Callable[[], str] | None = None
_LOCAL_OAUTH_COMPLETE_FUNC: Callable[[dict[str, Any], str, str], dict[str, Any]] | None = None


def _coerce_text(value: Any) -> str:
    return str(value or "").strip()


def _iso_now() -> str:
    if _LOCAL_OAUTH_NOW_FUNC:
        return _LOCAL_OAUTH_NOW_FUNC()
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _complete_flow(payload: dict[str, Any], code: str, code_verifier: str) -> dict[str, Any]:
    if _LOCAL_OAUTH_COMPLETE_FUNC is None:
        raise RuntimeError("本机 OAuth 回调处理器尚未初始化")
    return _LOCAL_OAUTH_COMPLETE_FUNC(payload, code, code_verifier)


def _configure_local_oauth_runtime(
    *,
    now_func: Callable[[], str],
    complete_oauth_code_payload_func: Callable[[dict[str, Any], str, str], dict[str, Any]],
) -> None:
    """把旧入口里的时间函数和 token 收口函数注入进来。"""
    global _LOCAL_OAUTH_NOW_FUNC, _LOCAL_OAUTH_COMPLETE_FUNC
    _LOCAL_OAUTH_NOW_FUNC = now_func
    _LOCAL_OAUTH_COMPLETE_FUNC = complete_oauth_code_payload_func


def create_local_oauth_flow(
    payload: dict[str, Any],
    *,
    now_func: Callable[[], str],
    complete_oauth_code_payload_func: Callable[[dict[str, Any], str, str], dict[str, Any]],
    build_authorize_url_func: Callable[[str, str], str],
    redirect_uri: str,
) -> dict[str, Any]:
    """创建一条本机 OAuth 流程，并确保本地回调 server 已经起来。"""
    _configure_local_oauth_runtime(
        now_func=now_func,
        complete_oauth_code_payload_func=complete_oauth_code_payload_func,
    )
    start_local_oauth_callback_server(
        now_func=now_func,
        complete_oauth_code_payload_func=complete_oauth_code_payload_func,
    )
    state = secrets.token_urlsafe(32)
    code_verifier = generate_openai_code_verifier()
    authorize_url = build_authorize_url_func(state, code_verifier)
    with LOCAL_OAUTH_LOCK:
        LOCAL_OAUTH_FLOWS[state] = {
            "state": state,
            "code_verifier": code_verifier,
            "payload": payload,
            "status": "pending",
            "created_at": _iso_now(),
            "updated_at": _iso_now(),
            "authorize_url": authorize_url,
            "result": None,
            "error": "",
        }
    return {
        "success": True,
        "state": state,
        "code_verifier": code_verifier,
        "authorize_url": authorize_url,
        "redirect_uri": redirect_uri,
        "callback_port": LOCAL_OAUTH_PORT,
    }


def get_local_oauth_flow(state: str) -> dict[str, Any]:
    """查询本机 OAuth 流程状态，供前端轮询展示。"""
    with LOCAL_OAUTH_LOCK:
        flow = LOCAL_OAUTH_FLOWS.get(_coerce_text(state))
        if not flow:
            raise RuntimeError("本机 OAuth 流程不存在或已过期")
        return {
            "success": True,
            "flow": {
                "state": flow.get("state"),
                "status": flow.get("status"),
                "created_at": flow.get("created_at"),
                "updated_at": flow.get("updated_at"),
                "authorize_url": flow.get("authorize_url"),
                "result": flow.get("result"),
                "error": flow.get("error", ""),
            },
        }


def parse_localhost_oauth_callback(callback_url: str, expected_state: str = "") -> dict[str, str]:
    """解析 localhost OAuth 回调地址，并校验 code/state 是否可用。"""
    raw = _coerce_text(callback_url)
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception as exc:
        raise RuntimeError("localhost OAuth 回调地址格式无效") from exc
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"localhost", "127.0.0.1"}:
        raise RuntimeError("只接受真实的 localhost / 127.0.0.1 OAuth 回调地址")
    query = urllib.parse.parse_qs(parsed.query)
    error = _coerce_text((query.get("error") or [""])[0]) or _coerce_text((query.get("error_description") or [""])[0])
    if error:
        raise RuntimeError(f"OAuth 授权失败：{error}")
    code = _coerce_text((query.get("code") or [""])[0])
    state = _coerce_text((query.get("state") or [""])[0])
    if not code or not state:
        raise RuntimeError("localhost OAuth 回调地址缺少 code 或 state")
    if expected_state and expected_state != state:
        raise RuntimeError("localhost 回调中的 state 与本轮 CPA 授权链接不一致，请重新生成授权链接")
    return {
        "url": urllib.parse.urlunparse(parsed),
        "code": code,
        "state": state,
    }


def handle_local_oauth_callback(path: str) -> tuple[int, str]:
    """处理 localhost 回调，把成功/失败结果写回流程状态。"""
    parsed = urllib.parse.urlparse(path)
    query = urllib.parse.parse_qs(parsed.query)
    state = _coerce_text((query.get("state") or [""])[0])
    code = _coerce_text((query.get("code") or [""])[0])
    error = _coerce_text((query.get("error") or [""])[0]) or _coerce_text((query.get("error_description") or [""])[0])
    with LOCAL_OAUTH_LOCK:
        flow = LOCAL_OAUTH_FLOWS.get(state)
    if not flow:
        return 400, "授权回调未匹配到工具中的流程，请回到工具重新生成链接。"
    if error:
        with LOCAL_OAUTH_LOCK:
            flow["status"] = "failed"
            flow["error"] = error
            flow["updated_at"] = _iso_now()
        return 400, f"OpenAI OAuth 授权失败：{error}"
    try:
        result = _complete_flow(flow.get("payload") or {}, code, _coerce_text(flow.get("code_verifier")))
        with LOCAL_OAUTH_LOCK:
            flow["status"] = "success"
            flow["result"] = result
            flow["error"] = ""
            flow["updated_at"] = _iso_now()
        return 200, "授权完成，refresh_token 已换取并导出到 CPA。可以关闭这个页面，回到工具查看结果。"
    except Exception as exc:
        with LOCAL_OAUTH_LOCK:
            flow["status"] = "failed"
            flow["error"] = str(exc)[:500]
            flow["updated_at"] = _iso_now()
        return 500, f"授权回调处理失败：{str(exc)[:500]}"


class LocalOAuthCallbackHandler(BaseHTTPRequestHandler):
    """本机 OAuth callback 的最小 HTTP handler。"""

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if urllib.parse.urlparse(self.path).path != "/auth/callback":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        status, message = handle_local_oauth_callback(self.path)
        body = (
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>OAuth 回调</title>"
            "<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0f172a;color:#e5e7eb;display:grid;place-items:center;min-height:100vh;margin:0}"
            "main{max-width:720px;padding:32px;border:1px solid #334155;border-radius:12px;background:#111827}"
            "h1{font-size:22px}p{line-height:1.7;color:#cbd5e1}</style></head>"
            f"<body><main><h1>{'授权完成' if status < 400 else '授权失败'}</h1><p>{html.escape(message)}</p></main></body></html>"
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_local_oauth_callback_server(
    *,
    now_func: Callable[[], str],
    complete_oauth_code_payload_func: Callable[[dict[str, Any], str, str], dict[str, Any]],
) -> None:
    """启动 localhost 回调 server；已有实例时直接复用。"""
    global LOCAL_OAUTH_SERVER, LOCAL_OAUTH_THREAD
    _configure_local_oauth_runtime(
        now_func=now_func,
        complete_oauth_code_payload_func=complete_oauth_code_payload_func,
    )
    with LOCAL_OAUTH_LOCK:
        if LOCAL_OAUTH_SERVER:
            return
        server = ThreadingHTTPServer(("127.0.0.1", LOCAL_OAUTH_PORT), LocalOAuthCallbackHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        LOCAL_OAUTH_SERVER = server
        LOCAL_OAUTH_THREAD = thread


__all__ = [
    "LOCAL_OAUTH_FLOWS",
    "LOCAL_OAUTH_LOCK",
    "LOCAL_OAUTH_PORT",
    "LocalOAuthCallbackHandler",
    "create_local_oauth_flow",
    "get_local_oauth_flow",
    "handle_local_oauth_callback",
    "parse_localhost_oauth_callback",
    "start_local_oauth_callback_server",
]
