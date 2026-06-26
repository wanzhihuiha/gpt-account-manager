"""登录域的 OAuth 授权链接构造。

这里只放纯字符串/哈希转换，不碰网络和浏览器。这样上层在生成
授权链接、PKCE challenge 和登录入口 URL 时，都能复用同一处纯逻辑。
"""
from __future__ import annotations

import base64
import hashlib
import urllib.parse


def oauth_base64url(data: bytes) -> str:
    """把二进制内容编码成 OAuth 常用的 base64url 文本。"""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def generate_openai_code_verifier() -> str:
    """生成 OpenAI OAuth 所需的 code_verifier。"""
    import secrets

    return secrets.token_hex(64)


def openai_code_challenge(code_verifier: str) -> str:
    """由 code_verifier 计算 PKCE challenge，供授权链接使用。"""
    return oauth_base64url(hashlib.sha256(code_verifier.encode("ascii")).digest())


def build_openai_oauth_authorize_url(
    state: str,
    code_challenge: str,
    *,
    client_id: str,
    redirect_uri: str,
    scope: str,
    authorize_base_url: str,
) -> str:
    """拼装 OpenAI OAuth 授权地址，只负责字符串拼接。"""
    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    })
    return f"{authorize_base_url}?{params}"


def build_chatgpt_login_url(email_addr: str = "", *, login_url: str) -> str:
    """拼装 ChatGPT 登录页地址，必要时附带邮箱提示。"""
    if not email_addr:
        return login_url
    separator = "&" if "?" in login_url else "?"
    return f"{login_url}{separator}{urllib.parse.urlencode({'email': email_addr})}"


__all__ = [
    "build_chatgpt_login_url",
    "build_openai_oauth_authorize_url",
    "generate_openai_code_verifier",
    "oauth_base64url",
    "openai_code_challenge",
]
