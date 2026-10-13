FROM node:22.23.1-bookworm-slim AS node-runtime
FROM ubuntu:24.04
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/* && python3 -m venv /opt/consumer \
    && ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm
WORKDIR /opt/demo
COPY . /opt/demo/
RUN /opt/consumer/bin/pip install --no-index artifacts/auths-*.whl \
    && npm install --omit=dev --ignore-scripts --no-audit --no-fund --no-save artifacts/auths-dev-sdk-*.tgz \
    && chmod 755 bin/auths-gateway bin/auths-gateway-simulation
ENTRYPOINT ["/opt/consumer/bin/python", "/opt/demo/operate.py"]
CMD ["--mode", "simulation"]
