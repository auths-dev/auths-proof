FROM rust:1.91.0-bookworm@sha256:e187887ec511b3d93e45c0231d2f0fd59f1347526c58aa86343aa83c74f3e1a9 AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p auths-node

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:adcd20c7b4c988b73cbfbddb26d2eee574571e6d7c9ffea29b3821e0690efb77
COPY --from=builder /workspace/target/release/auths-node /usr/local/bin/auths-node
COPY --from=builder /workspace/target/release/auths-sandbox-request /usr/local/bin/auths-sandbox-request
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/auths-node"]
