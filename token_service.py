#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""多用户临时凭证服务。

携带 apikey 调用接口,返回一组腾讯云临时凭证:
  TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY / TENCENTCLOUD_TOKEN

约定:
- apikey 暂不做任何校验(仅读取,便于以后接鉴权)。
- username 由调用方传入,直接用作 RoleSessionName(调用方保证已做过权限验证)。
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

运行:
  pip install flask tencentcloud-sdk-python python-dotenv
  python token_service.py

调用:
  curl -X POST http://127.0.0.1:8080/credentials \
       -H 'X-API-Key: any' \
       -H 'Content-Type: application/json' \
       -d '{"username": "alice", "duration": 3600}'
"""

import json
import os
import re
import threading
import time

from dotenv import load_dotenv
from flask import Flask, jsonify, request

from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.sts.v20180813 import models, sts_client

load_dotenv()

# ---------- 配置:全部可通过环境变量 / .env 覆盖 ----------
SECRET_ID = os.environ.get("TENCENTCLOUD_SECRET_ID", "")
SECRET_KEY = os.environ.get("TENCENTCLOUD_SECRET_KEY", "")
ROLE_ARN = os.environ.get("ROLE_ARN", "qcs::cam::uin/3321337994:roleName/ags-sandbox-role")
REGION = os.environ.get("REGION", "ap-shanghai")
DEFAULT_DURATION_SECONDS = int(os.environ.get("DEFAULT_DURATION_SECONDS", "7200"))
REFRESH_MARGIN_SECONDS = int(os.environ.get("REFRESH_MARGIN_SECONDS", "300"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))

app = Flask(__name__)

# RoleSessionName 只允许 [\w+=,.@-],最长 64。
_SESSION_SANITIZE = re.compile(r"[^\w+=,.@-]")

# 缓存:key=(role_session_name, duration) -> {creds, expired_time}。threaded=True 下需加锁。
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


def read_apikey() -> str:
    """从 header 或 query 读取 apikey(暂不校验)。"""
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        header = header[7:].strip()
    return request.headers.get("X-API-Key") or header or request.args.get("apikey", "")


def read_username() -> str:
    body = request.get_json(silent=True) or {}
    return str(body.get("username", request.args.get("username", ""))).strip()


def read_duration() -> int:
    """token 有效期:body.duration 或 ?duration=,缺省或非法时用默认值。"""
    body = request.get_json(silent=True) or {}
    raw = body.get("duration", request.args.get("duration"))
    if raw is None or str(raw).strip() == "":
        return DEFAULT_DURATION_SECONDS
    try:
        return int(raw)
    except (TypeError, ValueError):
        return DEFAULT_DURATION_SECONDS


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.route("/credentials", methods=["GET", "POST"])
def credentials():
    missing = [name for name, value in (
        ("TENCENTCLOUD_SECRET_ID", SECRET_ID),
        ("TENCENTCLOUD_SECRET_KEY", SECRET_KEY),
        ("ROLE_ARN", ROLE_ARN),
    ) if not value]
    if missing:
        return jsonify({"error": "server misconfigured", "missing_env": missing}), 500

    _ = read_apikey()                 # 暂不校验
    username = read_username()
    if not username:
        return jsonify({"error": "username is required"}), 400

    session_name = sanitize_session_name(username)
    if not session_name:
        return jsonify({"error": "username produced an empty RoleSessionName"}), 400

    duration = read_duration()

    try:
        creds, cached = get_credentials(session_name, duration)
    except TencentCloudSDKException as e:
        return jsonify({"error": "assume_role failed", "detail": str(e)}), 502

    return jsonify({**creds, "cached": cached, "session": session_name})


if __name__ == "__main__":
    # threaded=True 支持多用户并发;生产请用 gunicorn 等 WSGI 服务器。
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, threaded=True)
