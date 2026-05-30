# 安全说明

## 凭证存储

普通用户的数据默认保存在当前浏览器：

- Outlook 密码 / client_id / refresh_token
- 临时邮箱地址 JWT
- 邮箱分组
- 本地邮件缓存
- 已忽略或已删除的本地邮件 key
- CPA 仓管地址和 management key

这些值优先存放在 `localStorage`。正常的前台收信流程不会把用户邮箱资料写入服务端全局账号池。

当普通用户调用服务端辅助 API 时，浏览器会发送 `ctgptm.workspaceId` 生成的 `X-Workspace-Id`。服务端辅助数据按工作区写入 `data/workspaces/<workspace-id>/`，避免多个浏览器用户共用同一台 VPS 时互相读到对方的邮箱、JWT、刷新结果或登录记录。

## 服务端密钥

公开部署时必须设置 `MAIL_PICKUP_ADMIN_TOKEN`。管理员页面、管理员 API、自检接口都应通过 token 或 `/login.html` 写入的 cookie 访问。

管理员接口是全局运维面。除非你明确希望某个用户访问全局管理池，否则不要分享管理员 token。

不要提交真实值：

- `MAIL_PICKUP_ADMIN_TOKEN`
- `GPT_ACCOUNT_MANAGER_TEMP_SITE_PASSWORD`
- `GPT_ACCOUNT_MANAGER_PUBLIC_POOL_TOKEN`
- CPA management key
- Outlook refresh token
- 临时邮箱 JWT
- 代理账号和密码

## 公开部署

建议使用 HTTPS，并让 Python 服务只绑定 `127.0.0.1`，由 Nginx 或其它反向代理对外提供服务。不要直接暴露 Python 原始端口，除非你清楚这样做的风险。

设置 `MAIL_PICKUP_ADMIN_TOKEN` 后，`/health`、`/network-health` 和 `/health.html` 都应视为私有入口。

## 邮件删除

前端删除动作只删除或隐藏本地缓存邮件，并记录忽略 key，避免同一封缓存邮件反复出现。它不会删除 Microsoft 或临时邮箱服务商里的远端真实邮件。

## 发布前检查

发布前至少执行：

```bash
rg -n "refresh_token|access_token|id_token|MAIL_PICKUP_ADMIN_TOKEN|Bearer |rt_|eyJ|password" .
```

命中的内容应该只是字段名、占位符或文档示例。发现真实凭证时，先从仓库和历史提交里清理干净再发布。
