FROM rust:1.91-bookworm AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p auths-identity-iroh-demo

FROM debian:bookworm-slim
RUN useradd --create-home --uid 10001 auths
COPY --from=builder /workspace/target/release/auths-identity-iroh-demo /usr/local/bin/auths-identity-iroh-demo
USER auths
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/auths-identity-iroh-demo"]
