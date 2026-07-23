# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

ARG SYFT_VERSION=1.48.0
ARG GRYPE_VERSION=0.116.0
ARG TARGETARCH=amd64

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    GRYPE_DB_CACHE_DIR=/data/grype-db \
    PATH="/usr/local/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Syft and Grype fixed versions
RUN set -eux; \
    arch="${TARGETARCH}"; \
    if [ "$arch" = "amd64" ]; then syft_arch=linux_amd64; grype_arch=linux_amd64; \
    elif [ "$arch" = "arm64" ]; then syft_arch=linux_arm64; grype_arch=linux_arm64; \
    else syft_arch=linux_amd64; grype_arch=linux_amd64; fi; \
    curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_${syft_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin syft; \
    curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_${grype_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin grype; \
    chmod +x /usr/local/bin/syft /usr/local/bin/grype; \
    syft version; \
    grype version

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY app ./app
COPY policies ./policies
COPY scripts ./scripts

RUN pip install --upgrade pip \
    && pip install . \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin scanner \
    && mkdir -p /data/reports /data/grype-db /tmp/scanner-auth \
    && chown -R scanner:scanner /data /tmp/scanner-auth /app

USER scanner

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
