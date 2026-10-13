FROM node:22.23.1-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/* && python3 -m venv /opt/consumer
WORKDIR /opt/demo
COPY . /opt/demo/
RUN /opt/consumer/bin/pip install --no-index artifacts/auths-*.whl \
    && npm install --omit=dev --ignore-scripts --no-audit --no-fund --no-save artifacts/auths-dev-sdk-*.tgz \
    && chmod 755 bin/auths-gateway bin/auths-gateway-simulation
ENTRYPOINT ["/opt/consumer/bin/python", "/opt/demo/operate.py"]
CMD ["--mode", "simulation"]
