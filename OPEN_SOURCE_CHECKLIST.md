# 开源发布检查清单

推送到 GitHub 前，按这个清单过一遍。

## 应该保留

- `server.py`
- `openai_sentinel_token.cjs`
- `static/`
- `deploy/`
- `.env.example`
- `.gitignore`
- `README.md`
- `SECURITY.md`
- `CHANGELOG.md`
- `package.json`
- `package-lock.json`

## 不应该提交

- `data/`
- `.cache/`
- `.ssh/`
- `node_modules/`
- `output/`
- `release/`
- `extensions/`
- `__pycache__/`
- `*.zip`
- `*.log`
- 真实 `.env` 文件

## 密钥扫描

推送前扫描：

```bash
rg -n "refresh_token|access_token|id_token|MAIL_PICKUP_ADMIN_TOKEN|Bearer |rt_|eyJ|password" .
```

预期命中只应该是占位符、字段名或文档示例。真实邮箱凭证、JWT、CPA management key、代理密码、管理员 token 都不能进入仓库。

## 运行时数据

应用会在 `data/` 下创建运行时文件。这些文件可能包含邮箱凭证、邮件缓存、登录调试截图和导出的 auth file。源码仓库最多保留 `data/.keep`。
