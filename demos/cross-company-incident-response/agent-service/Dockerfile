FROM rust:1.91-slim AS binding
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip python3-venv && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir maturin==1.9.4
WORKDIR /src
COPY . .
RUN /venv/bin/maturin build --manifest-path bindings/python/Cargo.toml --release --out /wheels

FROM python:3.12-slim
WORKDIR /app
COPY --from=binding /wheels /wheels
COPY demos/cross-company-incident-response/agent-service/requirements.txt /requirements.txt
RUN pip install --no-cache-dir /wheels/*.whl -r /requirements.txt && rm -rf /wheels
COPY demos/cross-company-incident-response/agent-service/auths_incident_agent ./auths_incident_agent
COPY core/fixtures/v1/valid/webauthn-root-raw-key-actor.proof.cbor /repo/core/fixtures/v1/valid/
COPY core/fixtures/v1/valid/webauthn-root-raw-key-actor.action.cbor /repo/core/fixtures/v1/valid/
COPY core/fixtures/v1/valid/webauthn-root-raw-key-actor.context.cbor /repo/core/fixtures/v1/valid/
ENV PORT=8080 AUTHS_REPO_ROOT=/repo AGENT_STATE_PATH=/tmp/auths-incident-demo/agent.sqlite3 PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "-m", "auths_incident_agent.server"]
