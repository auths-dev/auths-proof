# syntax=docker/dockerfile:1.7
FROM rust:1.97.1-bookworm AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p auths-radicle-demo

FROM debian:bookworm-slim AS radicle
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl openssh-client xz-utils \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://radicle.xyz/install -o /tmp/radicle-install.sh \
    && sh /tmp/radicle-install.sh --version=1.9.1 --prefix=/radicle --no-modify-path \
    && rm /tmp/radicle-install.sh

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates git gosu openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 auths \
    && useradd --uid 10001 --gid auths --create-home auths \
    && mkdir -p /data/radicle \
    && chown -R auths:auths /data
COPY --from=builder /workspace/target/release/auths-radicle-demo /usr/local/bin/auths-radicle-demo
COPY --from=radicle /radicle/bin/rad /usr/local/bin/rad
COPY --from=radicle /radicle/bin/radicle-node /usr/local/bin/radicle-node
COPY --from=radicle /radicle/bin/git-remote-rad /usr/local/bin/git-remote-rad
COPY demos/radicle-issue/entrypoint.sh /usr/local/bin/auths-radicle-entrypoint
RUN chmod 0755 /usr/local/bin/auths-radicle-entrypoint
EXPOSE 8080 8776
ENTRYPOINT ["/usr/local/bin/auths-radicle-entrypoint"]
