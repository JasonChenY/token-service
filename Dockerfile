FROM python:3.12-slim

WORKDIR /app

# 使用腾讯云镜像源加速 apt(Debian bookworm 为 deb822 格式的 debian.sources,
# 老格式回退到 sources.list)。
RUN sed -i 's@//deb.debian.org@//mirrors.tencent.com@g; s@//security.debian.org@//mirrors.tencent.com@g' \
        /etc/apt/sources.list.d/debian.sources 2>/dev/null \
    || sed -i 's@//deb.debian.org@//mirrors.tencent.com@g; s@//security.debian.org@//mirrors.tencent.com@g' \
        /etc/apt/sources.list

# 使用腾讯云 PyPI 镜像源加速 pip(对后续所有 pip 生效)。
ENV PIP_INDEX_URL=https://mirrors.tencent.com/pypi/simple/

# 常用运维/调试工具:ps(procps)、curl、ping、netstat/ifconfig、dig/nslookup、
# telnet、vim、less 等,便于进容器排障。
RUN apt-get update && apt-get install -y --no-install-recommends \
        procps \
        curl \
        wget \
        iputils-ping \
        net-tools \
        dnsutils \
        telnet \
        vim \
        less \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 先装依赖,利用镜像层缓存(仅在 requirements 变化时重装)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY token_service.py entrypoint.sh ./
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

# 启动入口:按 TLS_CERT/TLS_KEY 决定 HTTP 或 HTTPS(见 entrypoint.sh)。
ENTRYPOINT ["/app/entrypoint.sh"]

# 健康检查:按是否配置 TLS 切换 http/https。自签/内网证书用 -k 跳过校验。
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD (if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then \
        curl -fsSk https://127.0.0.1:${LISTEN_PORT:-8080}/healthz; \
      else \
        curl -fsS http://127.0.0.1:${LISTEN_PORT:-8080}/healthz; \
      fi) || exit 1
