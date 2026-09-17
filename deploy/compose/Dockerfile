# Diagnostic only. Override with an approved digest-pinned base for your fleet.
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}
WORKDIR /app
COPY tools/ tools/
COPY tests/fixtures/ tests/fixtures/
RUN python -m tools.fetch_gateway --output /usr/local/bin/agentgateway
USER 65532:65532
ENTRYPOINT ["python", "-m", "tools.gateway_probe", "--gateway-bin", "/usr/local/bin/agentgateway", "--report", "/tmp/gateway-stock.json"]
