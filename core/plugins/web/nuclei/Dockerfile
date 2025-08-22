# core/plugins/web/nuclei/Dockerfile
FROM python:3.12-slim

ARG NUCLEI_VERSION=3.4.7

# Minimal tools to fetch nuclei binary
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei (arch-aware)
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64) narch=amd64 ;; \
      aarch64) narch=arm64 ;; \
      armv7l) narch=armv7 ;; \
      *) echo "unsupported arch: $arch" && exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${narch}.zip"; \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin; \
    chmod +x /usr/local/bin/nuclei; \
    nuclei -version; \
    rm -f /tmp/nuclei.zip

# Non-root user (uid/gid 1000 like your manifest) + writable dirs
RUN groupadd -g 1000 app && useradd -m -u 1000 -g app -s /bin/sh app \
    && mkdir -p /cache /artifacts \
    && chown -R app:app /cache /artifacts

WORKDIR /app
# Build context MUST be repo root (so this path exists)
COPY core/plugins/web/nuclei/ /app/
RUN chown -R app:app /app

# Rootless-friendly defaults (override via env if needed)
ENV PATH="/usr/local/bin:/usr/bin:/bin" \
    HOME="/cache" \
    XDG_CONFIG_HOME="/cache/.config" \
    NUCLEI_TEMPLATES="/cache/nuclei-templates"

USER app:app

ENTRYPOINT ["python","/app/main.py"]
