FROM rust:1.97-bookworm AS builder

WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p auths-opentofu-demo

FROM debian:bookworm-slim AS opentofu
ARG TOFU_VERSION=1.12.5
ARG TOFU_ZIP_SHA256=dade9650e6b74fc7a8b986bd8717497d32f9e09cf82e479afef4977fa3085536
ARG OPENTOFU_SANDBOX=local
COPY demos/opentofu-plan/sandbox/${OPENTOFU_SANDBOX}/main.tf /opt/auths/opentofu/main.tf
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl unzip \
    && curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
      "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_amd64.zip" \
      --output /tmp/tofu.zip \
    && printf '%s  %s\n' "${TOFU_ZIP_SHA256}" /tmp/tofu.zip | sha256sum --check --strict \
    && unzip /tmp/tofu.zip -d /usr/local/bin \
    && /usr/local/bin/tofu version \
    && cd /opt/auths/opentofu \
    && /usr/local/bin/tofu providers lock -platform=linux_amd64 \
    && rm -rf /opt/auths/opentofu/.terraform \
    && rm -rf /tmp/tofu.zip /var/lib/apt/lists/*

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/auths-opentofu-demo /usr/local/bin/auths-opentofu-demo
COPY --from=opentofu /usr/local/bin/tofu /usr/local/bin/tofu
COPY --from=opentofu --chown=10001:10001 /opt/auths/opentofu /workspace/opentofu

RUN useradd --system --uid 10001 --create-home auths \
    && mkdir -p /data/auths-opentofu /workspace/opentofu \
    && chown -R auths:auths /data/auths-opentofu /workspace/opentofu

USER auths
ENV AUTHS_OPENTOFU_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/auths-opentofu-demo"]
