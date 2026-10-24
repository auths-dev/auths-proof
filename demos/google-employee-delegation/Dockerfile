ARG PYTHON_IMAGE=python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
FROM ${PYTHON_IMAGE} AS wheels

ARG AP070_ROLE
ARG AUTHS_WHEEL_SHA256
WORKDIR /build
COPY artifacts/auths-*.whl /wheelhouse/
COPY broker/ /build/broker/
COPY agent/ /build/agent/
RUN set -eu; \
    test "$AP070_ROLE" = broker || test "$AP070_ROLE" = agent; \
    test -n "$AUTHS_WHEEL_SHA256"; \
    set -- /wheelhouse/auths-*.whl; \
    test "$#" -eq 1; \
    printf '%s  %s\n' "$AUTHS_WHEEL_SHA256" "$1" | sha256sum -c -; \
    python -m pip wheel --no-deps --wheel-dir /wheelhouse "/build/$AP070_ROLE"; \
    if test "$AP070_ROLE" = broker; then \
      python -m pip download --only-binary=:all: --dest /wheelhouse \
        'jsonschema>=4.23,<5' 'google-auth>=2.35,<3' \
        'requests>=2.32,<3' 'cryptography>=44,<47'; \
    else \
      python -m pip download --only-binary=:all: --dest /wheelhouse \
        'cryptography>=44,<47' 'openai>=2,<3'; \
    fi

FROM ${PYTHON_IMAGE}
ARG AP070_ROLE
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=wheels /wheelhouse/ /wheelhouse/
RUN set -eu; \
    if test "$AP070_ROLE" = broker; then \
      python -m pip install --no-index --find-links=/wheelhouse \
        auths-google-employee-delegation-broker==0.1.0; \
      python -c 'from auths import _native; from auths.self_hosted import verify_command; import employee_read_demo.app'; \
    elif test "$AP070_ROLE" = agent; then \
      python -m pip install --no-index --find-links=/wheelhouse \
        auths-google-employee-read-agent==0.1.0; \
      python -c 'from auths import _native; import employee_read_agent.run'; \
    else \
      exit 1; \
    fi; \
    python -m pip check; \
    rm -rf /wheelhouse
WORKDIR /
