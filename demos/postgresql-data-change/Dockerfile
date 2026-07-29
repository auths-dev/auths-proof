FROM rust:1.97.1-bookworm AS builder

WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p auths-postgresql-demo

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/auths-postgresql-demo /usr/local/bin/auths-postgresql-demo

RUN useradd --system --uid 10001 --create-home auths \
    && mkdir -p /data/auths-postgresql \
    && chown -R auths:auths /data/auths-postgresql

USER auths
ENV AUTHS_POSTGRESQL_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/auths-postgresql-demo"]
