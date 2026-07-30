FROM rust:1.97-bookworm AS builder

WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p auths-records-demo

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/auths-records-demo /usr/local/bin/auths-records-demo

RUN useradd --system --uid 10001 --create-home auths \
    && mkdir -p /data/auths-records \
    && chown -R auths:auths /data/auths-records

USER auths
ENV PORT=8080
ENV AUTHS_RECORDS_STATE_PATH=/data/auths-records/ledger.json
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/auths-records-demo", "serve"]
