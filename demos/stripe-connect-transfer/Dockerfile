FROM rust:1.97-bookworm AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p auths-stripe-connect-transfer-demo

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/auths-stripe-connect-transfer-demo /usr/local/bin/auths-stripe-connect-transfer-demo
RUN useradd --system --uid 10001 --create-home auths \
    && mkdir -p /data/auths-stripe-connect-transfer \
    && chown -R auths:auths /data/auths-stripe-connect-transfer
USER auths
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/auths-stripe-connect-transfer-demo"]
