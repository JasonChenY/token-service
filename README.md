# token-service

腾讯云临时凭证签发服务。通过 STS `AssumeRole` 为多用户签发临时密钥三件套（`TENCENTCLOUD_SECRET_ID` / `TENCENTCLOUD_SECRET_KEY` / `TENCENTCLOUD_TOKEN`），支持 REST 微服务和 MCP 工具两种接入方式，内置凭证缓存和 OAuth2 resource server 模式。

---

## 项目能力

### 非 RS 模式（默认）

调用方传入 `username`（由调用方保证已做过权限验证），服务直接用它作为 `RoleSessionName` 调 STS `AssumeRole` 换取临时凭证。适合服务端脚本、CI/CD、内部工具等已有自己鉴权机制的场景。

### RS 模式（OAuth2 Resource Server）

开启 `OPENID_RESOURCE_SERVER=true` 后，服务变为标准的 OAuth2 resource server（RFC 6750 + RFC 9728）：

- 请求必须携带 `Authorization: Bearer <access_token>`。
- 无 token 时返回 `401 + WWW-Authenticate: Bearer resource_metadata=<本 RS 的 /.well-known/oauth-protected-resource>`，客户端按 RFC 9728 → RFC 8414 自动发现 Keycloak 的真实 `authorization_endpoint`，走授权码流程换 token。
- 有 token 时，服务用**机密（confidential）client** 调 Keycloak `introspection_endpoint`（`client_secret_basic` 认证）校验 token，`username` 取自 introspection 响应。
- 所有端点（`introspection_endpoint`、`authorization_endpoint` 等）**全部从 AS 的 `.well-known` 动态发现**，不硬编码厂商路径。

错误码区分：
- `401`：token 缺失或无效（`TokenInvalid`）
- `502`：Keycloak/introspection 不可达（`ASUnavailable`），不误导客户端去重新登录

---

## 接入方式

### REST 微服务

| 路径 | 方法 | 说明 |
|------|------|------|
| `/credentials` | GET / POST | 签发临时凭证 |
| `/healthz` | GET | 健康检查 |
| `/.well-known/oauth-protected-resource` | GET | RFC 9728 资源元数据（RS 模式） |
| `/mcp` | — | MCP streamable-http 端点 |

**非 RS 模式**

```bash
curl -X POST https://ags-mcp-server.eit217.cn:8443/credentials \
     -H 'X-API-Key: any' -H 'Content-Type: application/json' \
     -d '{"username": "alice", "duration": 3600}'
```

**RS 模式**

```bash
# 无 token → 401，含 resource_metadata，客户端据此发现 Keycloak
curl -i https://ags-mcp-server.eit217.cn:8443/credentials

# 有 token → introspection 校验 → 返回临时凭证
curl -X POST https://ags-mcp-server.eit217.cn:8443/credentials \
     -H 'Authorization: Bearer <access_token>' \
     -H 'Content-Type: application/json' \
     -d '{"duration": 3600}'
```

响应（200）：

```json
{
  "TENCENTCLOUD_SECRET_ID": "AKIDxxxx",
  "TENCENTCLOUD_SECRET_KEY": "xxxx",
  "TENCENTCLOUD_TOKEN": "xxxx",
  "Expiration": "2026-09-19T13:00:00Z",
  "ExpiredTime": 1758286800,
  "cached": false,
  "session": "alice"
}
```

### MCP 工具

把 streamable-http 端点指向 `https://<host>:<port>/mcp`，初始化后 `tools/list` 可见 `get_temporary_credentials`：

```json
{
  "name": "get_temporary_credentials",
  "arguments": {
    "username": "alice",
    "duration": 3600
  }
}
```

RS 模式下无须传 `username`，服务从请求的 `Authorization: Bearer` 头经 introspection 取用户名。

---

## 启动方式

### 依赖安装

```bash
pip install mcp uvicorn gunicorn tencentcloud-sdk-python python-dotenv
```

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `TENCENTCLOUD_SECRET_ID` | — | **必填**，永久密钥 SecretId（子账号） |
| `TENCENTCLOUD_SECRET_KEY` | — | **必填**，永久密钥 SecretKey |
| `ROLE_ARN` | `qcs::cam::uin/3321337994:roleName/ags-sandbox-role` | 被扮演角色的 ARN |
| `REGION` | `ap-shanghai` | STS 地域 |
| `DEFAULT_DURATION_SECONDS` | `7200` | 临时凭证默认有效期（秒） |
| `REFRESH_MARGIN_SECONDS` | `300` | 临期提前刷新阈值（秒） |
| `LISTEN_HOST` / `LISTEN_PORT` | `0.0.0.0` / `8080` | 监听地址 |
| `TLS_CERT` / `TLS_KEY` | — | 证书和私钥路径，同时配置则启用 HTTPS |
| `DEBUG` | `false` | `true` 时跳过 gunicorn，用 uvicorn `--reload` 调试 |
| `OPENID_RESOURCE_SERVER` | `false` | 开启 OAuth2 RS 模式 |
| `OAUTH2_AS_ISSUER` | `https://keycloak.eit217.cn/realms/eit217` | AS issuer，端点从 `.well-known` 派生 |
| `RESOURCE_URL` | — | 本 RS 对外规范 URL（如 `https://ags-mcp-server.eit217.cn:8443`），用于 RFC 9728 元数据 |
| `OAUTH2_CLIENT_ID` | `ags-mcp-server` | 机密 client id，RS 模式必填 |
| `OAUTH2_CLIENT_SECRET` | — | 机密 client secret，RS 模式必填 |
| `OAUTH2_AS_USERNAME_FIELD` | `preferred_username` | introspection 响应里取 username 的字段 |

永久密钥写在同目录 `.env` 即可，服务启动时自动加载：

```bash
# .env
TENCENTCLOUD_SECRET_ID=AKIDxxxxxxxx
TENCENTCLOUD_SECRET_KEY=xxxxxxxx
```

### 本地调试

```bash
# HTTP，Flask-like 快速启动
DEBUG=true python token_service.py

# HTTPS 调试
DEBUG=true TLS_CERT=/path/cert.pem TLS_KEY=/path/key.pem python token_service.py
```

### Docker（非 RS 模式）

```bash
docker build -t token-service:latest .

docker run -d --name token-service \
  -p 8080:8080 \
  --env-file .env \
  -e ROLE_ARN='qcs::cam::uin/3321337994:roleName/ags-sandbox-role' \
  -e REGION=ap-shanghai \
  --restart unless-stopped \
  token-service:latest
```

### Docker（RS 模式 + HTTPS）

```bash
docker run -d --name token-service \
  --restart unless-stopped \
  -p 8443:8443 \
  --env-file .env \
  -e ROLE_ARN='qcs::cam::uin/3321337994:roleName/ags-sandbox-role' \
  -e REGION=ap-shanghai \
  -e LISTEN_PORT=8443 \
  -e TLS_CERT=/certs/fullchain.pem \
  -e TLS_KEY=/certs/privkey.pem \
  -e OPENID_RESOURCE_SERVER=true \
  -e OAUTH2_AS_ISSUER=https://keycloak.eit217.cn/realms/eit217 \
  -e RESOURCE_URL=https://ags-mcp-server.eit217.cn:8443 \
  -e OAUTH2_CLIENT_ID=ags-mcp-server \
  -e OAUTH2_CLIENT_SECRET=<secret> \
  -v /path/to/certs:/certs:ro \
  token-service:latest
```

> 生产环境不要把 `OAUTH2_CLIENT_SECRET` 写进镜像或代码；用 `--env-file`、secrets manager 或 k8s secret 注入。

---

## CAM 权限配置

服务通过 STS `AssumeRole` 获取临时凭证，需要以下 CAM 配置。

### 第一步：创建角色 `ags-sandbox-role`

在 CAM 控制台创建角色（角色载体：腾讯云账号）。

**信任策略**（限定哪个子账号可以扮演）：

```json
{
  "version": "2.0",
  "statement": [
    {
      "action": "name/sts:AssumeRole",
      "effect": "allow",
      "principal": { "qcs": ["qcs::cam::uin/3321337994:root"] },
      "condition": {
        "string_equal": {
          "qcs:assume_principal_arn": [
            "qcs::cam::uin/3321337994:uin/100010947274"
          ]
        }
      }
    }
  ]
}
```

> 创建角色时选「其他主账号」并输入子账号 UIN，控制台会自动生成带 `condition` 的信任策略。

**权限策略 `ags-sandbox-policy`**（角色能操作的沙箱资源）：

```json
{
  "version": "2.0",
  "statement": [
    {
      "effect": "allow",
      "action": [
        "ags:DescribeSandboxInstanceList",
        "ags:AcquireSandboxInstanceToken",
        "ags:StartSandboxInstance",
        "ags:StopSandboxInstance",
        "ags:PauseSandboxInstance",
        "ags:ResumeSandboxInstance",
        "ags:UpdateSandboxInstance"
      ],
      "resource": ["*"]
    }
  ]
}
```

> 不限制操作类型可直接使用系统策略 `QcloudAGSFullAccess`。

**`cam:PassRole` 策略**（角色需要把 AGS 服务角色 `chenyong-ags` 传递给 Agent Runtime）：

```json
{
  "version": "2.0",
  "statement": [
    {
      "effect": "allow",
      "action": ["cam:PassRole"],
      "resource": ["qcs::cam::uin/3321337994:roleName/chenyong-ags"]
    }
  ]
}
```

> 关键：`cam:PassRole` 必须配在角色 `ags-sandbox-role` 上，而不是子账号上。临时凭证的有效身份是角色，子账号上的权限不参与鉴权。

### 第二步：给子账号加"可扮演该角色"权限

新建自定义策略 `assume-ags-sandbox-role` 并关联到子账号：

```json
{
  "version": "2.0",
  "statement": [
    {
      "effect": "allow",
      "action": ["sts:AssumeRole"],
      "resource": ["qcs::cam::uin/3321337994:roleName/ags-sandbox-role"]
    }
  ]
}
```

### 两个角色的关系

```
子账号 100010947274
  │  sts:AssumeRole
  ▼
ags-sandbox-role  ──────────────────────────────────────┐
  权限：ags:* + cam:PassRole(chenyong-ags)               │
  │  PassRole(创建 AGS 实例时把 chenyong-ags 传给服务)   │
  ▼                                                      │
chenyong-ags（AGS 服务角色）                             │
  权限：TCR / COS / VPC 等（AGS 服务用来访问资源）◄──────┘
```

- 子账号只保留一条 `sts:AssumeRole`。
- 临时凭证触发的所有权限检查（`ags:*`、`cam:PassRole`）都必须配在 `ags-sandbox-role` 上。

### Keycloak 配置（RS 模式）

服务使用**机密 client** 调 introspection，需要在 Keycloak realm 里：

1. 创建或选中 client `ags-mcp-server`，打开 **Client authentication**（confidential）。
2. 在 Credentials 页面拷贝 **Client secret**，填入 `OAUTH2_CLIENT_SECRET`。
3. 确保该 client 有权调用 introspection 端点（默认机密 client 即可）。

终端用户走授权码（PKCE）的那个 client 和 RS 做 introspection 用的 client 可以是同一个，也可以分开——取决于你的 Keycloak 设计。

---

## 注意事项

- 本服务依赖调用方做权限校验；`username` 仅用作 STS `RoleSessionName`，可用于后续调用审计，但不限制临时凭证的具体操作范围。
- 无法在服务侧限制客户端拿到临时 token 后能创建什么类型的沙箱、创建几个、是否强制休眠等，这些限制需在 CAM 策略或 AGS 侧实现。
- 服务使用进程内内存缓存（按 `session_name + duration` 键），重启后清空；多副本部署时各自独立，如需跨副本共享缓存请接入 Redis。
