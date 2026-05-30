# GPT账号管理助手

GPT账号管理助手是一个浏览器优先的 GPT 账号运营工具，用于统一处理 Outlook / Microsoft OAuth 邮箱、临时邮箱 JWT、邮件验证码检索、本地邮件缓存、CPA 凭证仓管、OAuth 凭证刷新和 CPA / Sub2API auth JSON 导出。

立即使用入口：<https://mail.wsphl.cfd/>

GitHub: <https://github.com/margetrp-hub/gpt-account-manager>

本项目的核心边界是：普通用户在前台导入自己的邮箱凭证并完成收信、查码、删除本地缓存、推送刷新队列；管理员页面只作为站点维护、临时邮箱提取、CPA 仓管和公益池整理工具，不是普通用户收信流程的前置条件。

## 技术架构

- 单进程 Python HTTP 服务：基于 `ThreadingHTTPServer` 提供静态页面、客户端 API、管理员 API、CPA 仓管 API 和健康检查。
- 浏览器优先的数据模型：前台账号、邮箱、分类、邮件缓存、忽略列表和 CPA 设置默认保存在当前浏览器 `localStorage`，用户收信不依赖管理员预置账号。
- 独立收信链路：Microsoft 邮箱走 Graph / OAuth / IMAP 相关接口；临时邮箱走 Cloudflare Temp Email Worker 兼容 API；两条链路独立配置、独立错误分类。
- CPA 仓管链路：通过管理端点扫描 401 / 失效凭证，支持本地修复、删除目标 CPA auth file、推送账号到凭证刷新队列。
- OAuth 刷新链路：后端协议状态机完成 OpenAI OAuth authorization-code 流程，生成 CPA / Sub2API 可用的 auth JSON；刷新过程强制显式代理，避免把 VPS 本机出口误当成用户浏览器出口。
- 前后端分层：页面是原生 HTML/CSS/JS，后端只负责请求代理、协议登录、格式转换、CPA 对接和私有管理接口。
- 部署模型：推荐 Nginx 对外，Python 服务监听 `127.0.0.1:8765`；自检和管理员接口需要 admin token/cookie。

## Technical Overview

GPT Account Manager is a browser-first GPT account operations assistant for Outlook / Microsoft OAuth mailboxes, temp-mail JWT accounts, verification-code retrieval, local mail cache management, CPA credential warehousing, OAuth credential refresh, and CPA / Sub2API auth JSON export.

Use it online: <https://mail.wsphl.cfd/>

GitHub: <https://github.com/margetrp-hub/gpt-account-manager>

The main boundary is intentional: normal users import their own mailbox credentials on the front page and can receive mail without an administrator preloading accounts. Admin pages are operator tools for extraction, cleanup, CPA management, and public-pool workflows.

Architecture:

- Single-process Python HTTP service built on `ThreadingHTTPServer` for static pages, client APIs, admin APIs, CPA APIs, and private health checks.
- Browser-first persistence: imported accounts, mailboxes, groups, local message cache, ignored/deleted message keys, and CPA settings live in browser `localStorage` unless the user explicitly calls a server/admin workflow.
- Separate mail pipelines: Microsoft accounts use the Microsoft Graph / OAuth / IMAP path; temp-mail accounts use a Cloudflare Temp Email Worker-compatible API. These paths stay separately configured and separately diagnosed.
- CPA warehouse pipeline: scans target CPA/CLIProxyAPI credentials, classifies invalid auth files, supports deletion/repair, and can send selected accounts into the refresh queue.
- OAuth refresh pipeline: a backend protocol state machine completes the OpenAI OAuth authorization-code flow and emits CPA / Sub2API-compatible auth JSON. Refresh requires an explicit proxy URL so the backend exit is controlled instead of silently using the VPS default route.
- Frontend/backend split: native HTML/CSS/JS pages call a Python backend that handles request proxying, protocol login, format conversion, CPA integration, and private operator APIs.
- Deployment model: Nginx terminates public traffic; the Python service binds to `127.0.0.1:8765`; health and admin surfaces are protected by admin token/cookie.

## References

Thanks to these open-source projects and friends' work for ideas around ChatGPT session handling, CPA/Sub2API auth conversion, and operational tooling:

- [maowuzz/chatgpt-session-forge](https://github.com/maowuzz/chatgpt-session-forge)
- [gtxx3600/GPTSession2CPAandSub2API](https://github.com/gtxx3600/GPTSession2CPAandSub2API)

This repository does not vendor or copy those projects directly; it keeps its own browser-first account workflow and CPA warehouse implementation.

## What It Does

- Import Outlook accounts: `email----password----client_id----refresh_token----category(optional)`.
- Import temp mail accounts: `email----JWT----category(optional)`.
- Auto-detect common TXT / JSON / CSV imports before saving.
- Receive mail from Microsoft Graph / IMAP or a temp-mail Worker API.
- Keep user-imported mailbox credentials in the current browser by default.
- Cache received messages locally so users can search, copy codes, and hide/delete local messages.
- Group mailboxes, mark banned/deactivated accounts, and push selected accounts to the credential refresh queue.
- Provide a CPA warehouse page for scanning/cleaning invalid CPA credentials.
- Provide an admin-only temp-mail JWT extractor and optional public-pool export.

## Page Map

- `/` - account management console for normal users.
- `/refresh.html` - credential refresh queue.
- `/warehouse.html` - CPA warehouse and invalid-account cleanup.
- `/converter.html` - local ChatGPT session converter.
- `/login.html` - admin token login, stores an HttpOnly cookie and remembers the token in this browser.
- `/admin.html` - admin helper for batch temp-mail JWT extraction.
- `/health.html` - private deployment self-check; requires admin token/cookie on public servers.

## Data Boundary

The front page is browser-first. User-imported Outlook credentials, temp-mail JWTs, categories, local mail cache, ignored/deleted message keys, and CPA warehouse settings are stored in `localStorage` unless the user explicitly uses a server-side helper.

For normal client APIs, the browser creates a `ctgptm.workspaceId` value and sends it as `X-Workspace-Id`. Server-side helper data is written under `data/workspaces/<workspace-id>/`, including imported pickup credentials, temp-mail JWT sync results, credential refresh results, and login history. This keeps different browser users on the same VPS from reading or reusing each other's server-side helper data.

Admin `/api/*` and `/admin-api/*` endpoints remain operator/global surfaces protected by `MAIL_PICKUP_ADMIN_TOKEN`. Release zips intentionally do not include `data/`, logs, or `node_modules`.

## Compatibility Note

Some internal environment variables, localStorage keys, and the default VPS service path still use the historical `CTGPTM` / `ctgptm-mail-assistant` prefix. They are kept for compatibility with existing browsers and VPS deployments, not as the public project name.

## Quick Start

```bash
python3 server.py
```

Open:

```text
http://127.0.0.1:8765/
```

For local Windows development:

```powershell
cd D:\wiki\tools\gpt-account-manager
py -3 server.py
```

## VPS Environment

Set a real admin token before exposing admin pages or APIs.

```bash
MAIL_PICKUP_HOST=127.0.0.1
MAIL_PICKUP_PORT=8765
MAIL_PICKUP_ADMIN_TOKEN=replace-with-a-long-random-token
GPT_ACCOUNT_MANAGER_APP_TITLE=GPT账号管理助手
GPT_ACCOUNT_MANAGER_TEMP_WORKER_URL=https://maip.wsphl.cfd
# GPT_ACCOUNT_MANAGER_TEMP_SITE_PASSWORD=
GPT_ACCOUNT_MANAGER_STORE_URL=https://shop.ohlaoo.com/
GPT_ACCOUNT_MANAGER_RELAY_URL=https://ohlaoo.com/
GPT_ACCOUNT_MANAGER_PUBLIC_POOL_URL=https://ohlaoo.com/
# GPT_ACCOUNT_MANAGER_PUBLIC_POOL_API_URL=https://your-public-pool.example/api/import
# GPT_ACCOUNT_MANAGER_PUBLIC_POOL_TOKEN=optional-pool-token
MAIL_PICKUP_LOGIN_STRATEGY=protocol
MAIL_PICKUP_NODE_BIN=node
# MAIL_PICKUP_FETCH_CONCURRENCY=8
# MAIL_PICKUP_CHATGPT_LOGIN_URL=https://chatgpt.com/auth/login
# OPENAI_OAUTH_REDIRECT_URI=http://localhost:1455/auth/callback
# OPENAI_OAUTH_REFRESH_SCOPE=openid profile email
# MAIL_PICKUP_CPA_ALLOW_REMOTE=1
```

Automatic ChatGPT login must finish the OpenAI OAuth authorization-code flow and receive a real `refresh_token`; otherwise the refresh job is treated as failed instead of saving a half-usable session. Credential refresh requires an explicit proxy URL in the UI/API, for example `http://USER:PASS@host:port` or `socks5://USER:PASS@host:port`; do not use `127.0.0.1` on a VPS unless the proxy service is also running on that VPS. Protocol login uses Node.js for `openai_sentinel_token.cjs`. If you use `socks4://` or `socks5://` proxy during refresh, the VPS Python environment also needs PySocks:

```bash
sudo apt-get update
sudo apt-get install -y python3-socks
cd /opt/ctgptm-mail-assistant
sudo npm install --omit=dev --cache /tmp/ctgptm-npm-cache --no-audit --no-fund
```

## systemd Deploy

```bash
sudo unzip -o gpt-account-manager-*.zip -d /opt/ctgptm-mail-assistant
sudo chown -R www-data:www-data /opt/ctgptm-mail-assistant
sudo systemctl restart ctgptm-mail-assistant
sudo systemctl status ctgptm-mail-assistant --no-pager
```

Recommended reverse proxy:

```nginx
location / {
    proxy_pass http://127.0.0.1:8765;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## API Boundary

- `POST /client-api/fetch` receives credentials from the current browser request and returns messages. It does not save user mailboxes on the server.
- `POST /client-api/messages/delete` deletes/hides local cached messages for the browser workflow. It does not delete remote mailbox messages.
- `POST /client-api/cpa/scan-401` scans a CPA/CLIProxyAPI management endpoint for invalid credentials. The management key is forwarded for this request and not stored by this tool.
- `POST /client-api/cpa/repair-401` deletes invalid CPA auth files from the target CPA endpoint.
- `POST /admin-api/extract-jwts` requires `MAIL_PICKUP_ADMIN_TOKEN` and is only for Cloudflare Temp Email Worker admin extraction.

## Open Source Notes

Before publishing, review `SECURITY.md`, replace project-specific public URLs if needed, and add screenshots for the front page, refresh page, warehouse page, and admin login page.
