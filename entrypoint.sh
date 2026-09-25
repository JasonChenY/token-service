#!/bin/sh
set -e

# 调试模式(DEBUG=true):直接跑 uvicorn(token_service.py 内置 --reload + debug 日志),不经过 gunicorn。
if echo "$DEBUG" | grep -qiE '^(1|true|yes|on)$'; then
    echo "entrypoint: DEBUG 模式,uvicorn (reload + debug 日志)"
    exec python token_service.py
fi

# 生产模式:gunicorn + uvicorn ASGI worker(MCP streamable-http 需 ASGI)。
# TLS 开关:同时配置 TLS_CERT 与 TLS_KEY 即启用 HTTPS,否则 HTTP。
TLS_ARGS=""
if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
    if [ ! -f "$TLS_CERT" ]; then
        echo "entrypoint: TLS_CERT 指向的证书不存在: $TLS_CERT" >&2
        exit 1
    fi
    if [ ! -f "$TLS_KEY" ]; then
        echo "entrypoint: TLS_KEY 指向的私钥不存在: $TLS_KEY" >&2
        exit 1
    fi
    TLS_ARGS="--keyfile $TLS_KEY --certfile $TLS_CERT"
    echo "entrypoint: HTTPS 模式 (cert=$TLS_CERT key=$TLS_KEY)"
else
    echo "entrypoint: HTTP 模式 (未同时配置 TLS_CERT/TLS_KEY)"
fi

# 进程内缓存需在同一进程共享:单 worker。阻塞的 STS/introspection 调用由 anyio
# 下放到 uvicorn worker 自带的线程池,不阻塞事件循环。
exec gunicorn -k uvicorn.workers.UvicornWorker --workers 1 --timeout 60 \
    --bind 0.0.0.0:${LISTEN_PORT:-8080} \
    $TLS_ARGS \
    token_service:app
