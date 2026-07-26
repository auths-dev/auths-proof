# syntax=docker/dockerfile:1.7
FROM rust:1.97.1-bookworm AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --locked --release -p auths-live-service

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /workspace/target/release/auths-live-service /usr/local/bin/auths-live-service
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/auths-live-service"]
