#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""多用户临时凭证服务(Flask/WSGI → Starlette/ASGI + MCP)。

携带 apikey 调用接口,返回一组腾讯云临时凭证:
  TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY / TENCENTCLOUD_TOKEN

同一个 ASGI 应用同时提供两类入口:
- REST:GET/POST /credentials、GET /healthz、GET /.well-known/oauth-protected-resource
  (行为、状态码、响应体、响应头与旧版完全一致,供 curl / 非 MCP 客户端使用)。
- MCP:streamable-http 传输,端点 /mcp,暴露工具:
    * get_temporary_credentials —— 签发(带缓存)临时凭证三件套

两种鉴权模式(REST 与 MCP 工具共用同一套逻辑):
- 默认(非 RS):username 由调用方传入(REST:body/args;MCP:工具参数),直接用作
  RoleSessionName;apikey 暂不校验。
- OAuth2 resource server(可选,OPENID_RESOURCE_SERVER=true 时启用):请求须携带
  `Authorization: Bearer <access_token>`(REST 走 HTTP 头;MCP 工具经 ctx.headers 取同一头);
  无 token 时返回 401 + WWW-Authenticate: Bearer resource_metadata=<本 RS 的 /.well-known/
  oauth-protected-resource>(RFC 6750 + RFC 9728)。客户端据此发现 AS,再从 AS 的
  .well-known 读到真实 authorization_endpoint 自行走授权码流程——本服务不硬编码
  任何 AS 端点。资源服务器用「机密(confidential)client」调 AS introspection(RFC 7662,
  端点亦从 .well-known 发现)校验 token,client_secret_basic 认证,需配
  OAUTH2_CLIENT_ID + OAUTH2_CLIENT_SECRET;username 取自 introspection 响应
  (默认 preferred_username)。默认 AS 为 Keycloak issuer=https://keycloak.eit217.cn/realms/eit217。

约定:
- token 有效期(DurationSeconds)不传时默认 7200s。
- 命中缓存则直接返回未过期的临时凭证,临期(REFRESH_MARGIN_SECONDS)前自动重新 AssumeRole。
- 永久密钥、ROLE_ARN / REGION 均通过环境变量 / .env 配置。

环境变量(可写在同目录 .env):
  TENCENTCLOUD_SECRET_ID     永久密钥 SecretId          (必填)
  TENCENTCLOUD_SECRET_KEY    永久密钥 SecretKey         (必填)
  ROLE_ARN                   被扮演角色 ARN             (选填,有默认值)
  REGION                     STS 地域                   (选填,默认 ap-shanghai)
  DEFAULT_DURATION_SECONDS   默认有效期                 (选填,默认 7200)
  REFRESH_MARGIN_SECONDS     临期提前刷新阈值           (选填,默认 300)
  LISTEN_HOST / LISTEN_PORT  监听地址                   (选填,默认 0.0.0.0:8080)
  TLS_CERT / TLS_KEY         证书与私钥路径              (选填,同时配置则启用 HTTPS)
  DEBUG                      调试模式,uvicorn --reload   (选填,默认 false)
  OPENID_RESOURCE_SERVER     开启 OAuth2 RS 模式         (选填,默认 false)
  OAUTH2_AS_ISSUER           AS issuer                   (选填,默认 https://keycloak.eit217.cn/realms/eit217)
  RESOURCE_URL               本 RS 对外规范 URL           (RS 模式建议配,用于 RFC9728 资源元数据)
  OAUTH2_CLIENT_ID           机密 client id(introspection) (RS 模式必填,默认 ags-mcp-server)
  OAUTH2_CLIENT_SECRET       机密 client secret(introspection) (RS 模式必填)
  OAUTH2_AS_USERNAME_FIELD   从 introspection 响应取 username 的字段 (选填,默认 preferred_username)

依赖:
  pip install mcp uvicorn gunicorn tencentcloud-sdk-python python-dotenv
  (starlette / anyio / sse-starlette 等由 mcp 间接带入)

运行:
  python token_service.py                       # 本地调试(DEBUG=true 时带 reload)
  gunicorn -k uvicorn.workers.UvicornWorker \
      --workers 1 --bind 0.0.0.0:8080 token_service:app   # 生产

调用 REST(非 RS 模式):
  curl -X POST http://127.0.0.1:8080/credentials \
       -H 'X-API-Key: any' -H 'Content-Type: application/json' \
       -d '{"username": "alice", "duration": 3600}'

调用 REST(RS 模式):
  curl -X POST http://127.0.0.1:8080/credentials \
       -H 'Authorization: Bearer <access_token>' \
       -H 'Content-Type: application/json' -d '{"duration": 3600}'

调用 MCP:客户端把 streamable-http 端点指向 http(s)://<host>:<port>/mcp,
初始化后 tools/list 可见 get_temporary_credentials;tools/call 调
get_temporary_credentials(RS 模式无须传 username,鉴权走 Bearer 头)。
"""

import base64
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import anyio
from dotenv import load_dotenv
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from starlette.requests import Request
from starlette.responses import JSONResponse

from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.sts.v20180813 import models, sts_client

load_dotenv()

# ---------- 配置:全部可通过环境变量 / .env 覆盖 ----------
SECRET_ID = os.environ.get("TENCENTCLOUD_SECRET_ID", "")
SECRET_KEY = os.environ.get("TENCENTCLOUD_SECRET_KEY", "")
ROLE_ARN = os.environ.get("ROLE_ARN", "qcs::cam::3321337994:roleName/ags-sandbox-role")
REGION = os.environ.get("REGION", "ap-shanghai")
DEFAULT_DURATION_SECONDS = int(os.environ.get("DEFAULT_DURATION_SECONDS", "7200"))
REFRESH_MARGIN_SECONDS = int(os.environ.get("REFRESH_MARGIN_SECONDS", "300"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
# TLS:同时配置 TLS_CERT 与 TLS_KEY 时,调试模式(uvicorn)启用 HTTPS;
# 生产模式(gunicorn)由 entrypoint.sh 读取同名环境变量。
TLS_CERT = os.environ.get("TLS_CERT", "")
TLS_KEY = os.environ.get("TLS_KEY", "")

# ---------- OAuth2 resource server 模式(可选) ----------
def _flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")

RESOURCE_SERVER = _flag("OPENID_RESOURCE_SERVER", "false")

# ---- OAuth2 授权服务器(AS) ----
# 只配 issuer;introspection/authorization/token 等端点一律从 AS 的 .well-known
# 元数据(OIDC discovery / RFC 8414)动态发现,不按厂商路径硬拼(避免 Keycloak
# /auth vs /authorize 之类的差异)。
AS_ISSUER = os.environ.get("OAUTH2_AS_ISSUER", "https://keycloak.eit217.cn/realms/eit217").rstrip("/")
AS_USERNAME_FIELD = os.environ.get("OAUTH2_AS_USERNAME_FIELD", "preferred_username")
# RS 用「机密(confidential)client」调 AS introspection 校验 token:
# OAUTH2_CLIENT_ID + OAUTH2_CLIENT_SECRET 走 client_secret_basic 认证。
# RS 模式下二者必填(见 missing_config),且该 client 需在 Keycloak 里有 introspection 权限。
OAUTH2_CLIENT_ID = os.environ.get("OAUTH2_CLIENT_ID", "ags-mcp-server")
OAUTH2_CLIENT_SECRET = os.environ.get("OAUTH2_CLIENT_SECRET", "")
# RS 对外规范 URL(如 https://ags-mcp-server.eit217.cn:8443),用于 RFC 9728 受保护资源
# 元数据。反代/端口映射下 request.host 不可靠,建议显式配置。
RESOURCE_URL = os.environ.get("RESOURCE_URL", "").rstrip("/")

class ASUnavailable(Exception):
    """授权服务器 / introspection 端点不可达或返回异常(上游问题 → 502)。"""


class TokenInvalid(Exception):
    """access token 无效 / 过期 / 未激活(客户端问题 → 401)。"""


# AS 元数据发现缓存:成功 fetch 一次后复用。
_as_metadata: dict = {}
_as_metadata_lock = threading.Lock()


def as_metadata() -> dict:
    """获取并缓存 AS 元数据(优先 OIDC discovery,回退 RFC 8414)。失败抛 ASUnavailable。"""
    with _as_metadata_lock:
        if _as_metadata:
            return dict(_as_metadata)
    last_err = None
    for path in ("/.well-known/openid-configuration",
                 "/.well-known/oauth-authorization-server"):
        try:
            with urllib.request.urlopen(AS_ISSUER + path, timeout=10) as resp:
                meta = json.loads(resp.read().decode())
            with _as_metadata_lock:
                _as_metadata.clear()
                _as_metadata.update(meta)
            return meta
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            last_err = e
    raise ASUnavailable(f"无法获取 AS 元数据({AS_ISSUER}): {last_err}")


def _prm_url() -> str:
    """本 RS 提供的受保护资源元数据 URL(RFC 9728);未配 RESOURCE_URL 则为空。"""
    return f"{RESOURCE_URL}/.well-known/oauth-protected-resource" if RESOURCE_URL else ""


# RoleSessionName 只允许 [\w+=,.@-],最长 64。
_SESSION_SANITIZE = re.compile(r"[^\w+=,.@-]")

# 缓存:key=(role_session_name, duration) -> {creds, expired_time}。
_cache: dict[tuple[str, int], dict] = {}
_cache_lock = threading.Lock()


def sanitize_session_name(username: str) -> str:
    """username 直接作为 RoleSessionName,仅按腾讯云约束清洗非法字符并截断到 64。"""
    return _SESSION_SANITIZE.sub("-", username)[:64]


def assume_role(session_name: str, duration: int) -> dict:
    """调用 STS AssumeRole,返回临时凭证三件套(+ 过期时间)。"""
    cred = credential.Credential(SECRET_ID, SECRET_KEY)

    http_profile = HttpProfile()
    http_profile.endpoint = "sts.tencentcloudapi.com"
    client_profile = ClientProfile()
    client_profile.httpProfile = http_profile

    client = sts_client.StsClient(cred, REGION, client_profile)

    req = models.AssumeRoleRequest()
    req.from_json_string(json.dumps({
        "RoleArn": ROLE_ARN,
        "RoleSessionName": session_name,
        "DurationSeconds": duration,
    }))

    resp = client.AssumeRole(req)
    c = resp.Credentials
    return {
        "TENCENTCLOUD_SECRET_ID": c.TmpSecretId,
        "TENCENTCLOUD_SECRET_KEY": c.TmpSecretKey,
        "TENCENTCLOUD_TOKEN": c.Token,
        "Expiration": resp.Expiration,      # 过期时间(UTC 字符串)
        "ExpiredTime": resp.ExpiredTime,    # 过期时间戳(秒)
    }


def get_credentials(session_name: str, duration: int) -> tuple[dict, bool]:
    """带缓存地获取临时凭证。返回 (creds, cached)。"""
    key = (session_name, duration)
    now = time.time()

    with _cache_lock:
        entry = _cache.get(key)
        if entry and now < entry["ExpiredTime"] - REFRESH_MARGIN_SECONDS:
            return entry, True

    # 未命中或临期:重新 AssumeRole(锁外发网络请求,避免阻塞其他 key)。
    creds = assume_role(session_name, duration)

    with _cache_lock:
        _cache[key] = creds
    return creds, False


def introspect_token(access_token: str) -> dict:
    """用「机密 client」调 AS introspection(RFC 7662)校验 access token。

    以 client_secret_basic(Authorization: Basic base64(client_id:client_secret))认证,
    Keycloak 机密 client 的默认方式;introspection_endpoint 从 AS .well-known 发现。
    返回 introspection 响应 dict。

    异常区分:
    - ASUnavailable:AS/introspection 不可达、无端点、HTTP 错误(含 client 认证失败)、
      解析失败——属上游/配置问题,调用方应回 502。
    - TokenInvalid:introspection 返回 active!=true——属客户端问题,调用方应回 401。
    """
    meta = as_metadata()  # 失败抛 ASUnavailable
    url = meta.get("introspection_endpoint")
    if not url:
        raise ASUnavailable("AS 元数据未提供 introspection_endpoint")

    basic = base64.b64encode(
        f"{OAUTH2_CLIENT_ID}:{OAUTH2_CLIENT_SECRET}".encode()
    ).decode()
    data = urllib.parse.urlencode({"token": access_token}).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {basic}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            info = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        # 非 2xx(如 client_secret 错 → 401)是我们与 AS 之间的问题,不等同用户 token 失效。
        raise ASUnavailable(f"introspection endpoint returned HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise ASUnavailable(f"introspection request failed: {e}") from None

    if not info.get("active"):
        raise TokenInvalid("token inactive or invalid")
    return info


def username_from_claims(info: dict) -> str:
    """从 introspection 响应里取 username(默认 preferred_username,可配),回退 sub/username。"""
    value = info.get(AS_USERNAME_FIELD)
    if value is None:
        value = info.get("sub") or info.get("username")
    return str(value).strip() if value else ""


# ---------- 请求解析(纯函数,REST 与 MCP 工具共用,不再依赖请求上下文) ----------
def extract_bearer(headers) -> str:
    """从 Authorization: Bearer <token> 中取 token;缺失返回空串。"""
    auth = headers.get("authorization", "") if headers else ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def read_username(body: dict | None, query) -> str:
    """非 RS 模式:username 取 body.username 或 ?username=。"""
    val = body.get("username") if body else None
    if val is None or val == "":
        val = query.get("username") if query else None
    return str(val).strip() if val not in (None, "") else ""


def read_duration(body: dict | None, query) -> int:
    """token 有效期:body.duration 或 ?duration=,缺省或非法时用默认值。"""
    raw = body.get("duration") if body else None
    if raw is None:
        raw = query.get("duration") if query else None
    if raw is None or str(raw).strip() == "":
        return DEFAULT_DURATION_SECONDS
    try:
        return int(raw)
    except (TypeError, ValueError):
        return DEFAULT_DURATION_SECONDS


def missing_config() -> list[str] | None:
    """返回缺失的必填配置名;无缺失返回 None。"""
    checks = [
        ("TENCENTCLOUD_SECRET_ID", SECRET_ID),
        ("TENCENTCLOUD_SECRET_KEY", SECRET_KEY),
        ("ROLE_ARN", ROLE_ARN),
    ]
    if RESOURCE_SERVER:
        # 机密 client introspection 需要 client_id + client_secret。
        checks += [
            ("OAUTH2_CLIENT_ID", OAUTH2_CLIENT_ID),
            ("OAUTH2_CLIENT_SECRET", OAUTH2_CLIENT_SECRET),
        ]
    miss = [name for name, value in checks if not value]
    return miss or None


def unauthorized() -> tuple[int, dict, dict]:
    """无/无效 access token 时构造 (401, body, extra_headers)。

    遵循 RFC 6750 + RFC 9728:WWW-Authenticate 里给出 resource_metadata(本 RS 的
    /.well-known/oauth-protected-resource),客户端据此发现 AS,再从 AS 的 .well-known
    读到真实 authorization_endpoint 去走授权码流程——本服务不硬编码任何 AS 端点。
    """
    metadata = _prm_url()
    challenge_parts = ['Bearer realm="token-service"']
    if metadata:
        challenge_parts.append(f'resource_metadata="{metadata}"')

    body = {
        "error": "invalid_token",
        "error_description": "missing or invalid access token",
    }
    if metadata:
        body["resource_metadata"] = metadata

    return 401, body, {"WWW-Authenticate": ", ".join(challenge_parts)}


def resolve_username_rs(headers) -> tuple[str | None, str | None]:
    """RS 模式:机密 client introspection 校验 Bearer token,取 username。

    返回 (username, error)。username 非空且 error 为 None 表示鉴权通过(→200);
    error 非 None 表示 token 无效(→401)。AS 不可达则抛 ASUnavailable 向上传播(→502)。
    """
    token = extract_bearer(headers)
    if not token:
        return None, "missing access token (Authorization: Bearer <access_token>)"

    try:
        info = introspect_token(token)   # ASUnavailable 不在此捕获,向上抛 → 502
    except TokenInvalid as e:
        return None, f"{e}"

    username = username_from_claims(info)
    if not username:
        return None, "token valid but no username in introspection response"
    return username, None


def credentials_logic(headers, body: dict | None, query) -> tuple[int, dict, dict]:
    """REST /credentials 的纯逻辑:鉴权 → 取凭证 → 返回 (status, body, extra_headers)。"""
    if RESOURCE_SERVER:
        try:
            username, err = resolve_username_rs(headers)
        except ASUnavailable as e:
            return 502, {"error": "authorization server unavailable", "detail": str(e)}, {}
        if err is not None:
            return unauthorized()
    else:
        username = read_username(body, query)

    session_name = sanitize_session_name(username)
    if not session_name:
        return 400, {"error": "username produced an empty RoleSessionName"}, {}

    duration = read_duration(body, query)

    try:
        creds, cached = get_credentials(session_name, duration)
    except TencentCloudSDKException as e:
        return 502, {"error": "assume_role failed", "detail": str(e)}, {}

    return 200, {**creds, "cached": cached, "session": session_name}, {}


# ===================== MCP 服务器 + 工具 =====================
mcp_server = MCPServer(
    name="token-service",
    version="1.0",
    instructions=(
        "签发腾讯云临时凭证(STS AssumeRole)的 MCP 服务。"
        "工具:get_temporary_credentials 返回 TENCENTCLOUD_SECRET_ID/KEY/TOKEN(+过期时间、是否命中缓存)。"
        "RS 模式(OPENID_RESOURCE_SERVER=true)下用 Authorization: Bearer <access_token> "
        "鉴权(机密 client 调 AS introspection),username 取自 introspection 响应,工具无须传 username;"
        "非 RS 模式下 username 由调用方传入。"
    ),
)


@mcp_server.tool()
async def get_temporary_credentials(
    ctx: Context,
    username: str = "",
    duration: int = DEFAULT_DURATION_SECONDS,
) -> dict:
    """签发(带缓存)腾讯云临时凭证。

    RS 模式下无须传 username——鉴权走请求的 Authorization: Bearer 头,
    username 取自 introspection 响应(机密 client 调 AS introspection);duration 缺省用服务默认值。
    非 RS 模式下 username 必填,duration 可选。

    返回:TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY / TENCENTCLOUD_TOKEN、
    Expiration(UTC 字符串)、ExpiredTime(秒级时间戳)、cached、session。
    """
    miss = missing_config()
    if miss:
        raise ToolError(f"server misconfigured, missing env: {miss}")

    headers = ctx.headers or {}
    if RESOURCE_SERVER:
        # introspection 是阻塞网络调用,下放到线程池避免阻塞事件循环。
        try:
            resolved, err = await anyio.to_thread.run_sync(resolve_username_rs, headers)
        except ASUnavailable as e:
            raise ToolError(f"authorization server unavailable: {e}") from None
        if err is not None:
            raise ToolError(err)
        username = resolved  # type: ignore[assignment]

    if not username or not username.strip():
        raise ToolError("username is required (non-RS mode; pass it as a tool argument)")
    username = username.strip()

    session_name = sanitize_session_name(username)
    if not session_name:
        raise ToolError("username produced an empty RoleSessionName")

    # AssumeRole 是阻塞 SDK 调用,同样下放线程池。
    try:
        creds, cached = await anyio.to_thread.run_sync(get_credentials, session_name, duration)
    except TencentCloudSDKException as e:
        raise ToolError(f"assume_role failed: {e}") from None

    return {**creds, "cached": cached, "session": session_name}


# ===================== REST 路由(挂在同一 ASGI app) =====================
@mcp_server.custom_route("/healthz", methods=["GET"])
async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@mcp_server.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def protected_resource_metadata(request: Request) -> JSONResponse:
    """RFC 9728 受保护资源元数据:告诉客户端本 RS 由哪个 AS 保护。

    客户端拿到 authorization_servers 后,再去 AS 的 .well-known 读取真实
    authorization_endpoint,自行发起授权码流程。
    """
    resource = RESOURCE_URL or request.base_url.rstrip("/")
    return JSONResponse({
        "resource": resource,
        "authorization_servers": [AS_ISSUER],
    })


@mcp_server.custom_route("/credentials", methods=["GET", "POST"])
async def credentials(request: Request) -> JSONResponse:
    miss = missing_config()
    if miss:
        return JSONResponse({"error": "server misconfigured", "missing_env": miss},
                            status_code=500)

    body: dict | None = None
    if request.method == "POST":
        try:
            body = await request.json()
        except (ValueError, json.JSONDecodeError):
            body = {}
        if not isinstance(body, dict):
            body = {}
    query = request.query_params

    # 鉴权 + AssumeRole 均为阻塞网络调用,整体下放线程池,保持事件循环畅通。
    status, payload, extra_headers = await anyio.to_thread.run_sync(
        credentials_logic, request.headers, body, query
    )
    return JSONResponse(payload, status_code=status, headers=extra_headers)


# 顶层 ASGI app:/mcp(streamable-http MCP) + 上面 custom_route 的 REST 路由,同端口。
# host=LISTEN_HOST:仅当恰好是 127.0.0.1/localhost/::1 时 SDK 自动启用 DNS rebinding
# 防护;绑定 0.0.0.0(生产)时不启用,外部域名可正常访问。
app = mcp_server.streamable_http_app(streamable_http_path="/mcp", host=LISTEN_HOST)


if __name__ == "__main__":
    import uvicorn

    debug = _flag("DEBUG", "false")
    ssl_kwargs = {}
    if TLS_CERT and TLS_KEY:
        ssl_kwargs = {"ssl_certfile": TLS_CERT, "ssl_keyfile": TLS_KEY}
    # 调试模式:开 reload + 详细日志;生产走 gunicorn(见 entrypoint.sh)。
    uvicorn.run("token_service:app", host=LISTEN_HOST, port=LISTEN_PORT,
                reload=debug, log_level="debug" if debug else "info", **ssl_kwargs)