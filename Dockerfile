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

COPY token_service.py .

EXPOSE 8080

# 进程内缓存需在同一进程共享,故用「单 worker + 多线程」:
#   多 worker 会各自持有独立缓存,命中率下降(要多副本共享请改用 Redis)。
# 密钥等通过运行时 -e / --env-file 注入,不写进镜像。
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--timeout", "60", \
     "--bind", "0.0.0.0:8080", "token_service:app"]

# 健康检查:已装 curl,直接探活 /healthz。
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
