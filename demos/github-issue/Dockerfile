# syntax=docker/dockerfile:1.7
FROM rust:1.97.1-bookworm AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p auths-github-demo

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates git gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 auths \
    && useradd --uid 10001 --gid auths --create-home auths \
    && mkdir -p /data/github \
    && chown -R auths:auths /data
COPY --from=builder /workspace/target/release/auths-github-demo /usr/local/bin/auths-github-demo
COPY demos/github-issue/entrypoint.sh /usr/local/bin/auths-github-entrypoint
RUN chmod 0755 /usr/local/bin/auths-github-entrypoint
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/auths-github-entrypoint"]
