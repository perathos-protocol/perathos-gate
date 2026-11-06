FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8787 \
    GATE_KEY_FILE=/data/gate_signing.key \
    DATABASE_URL=sqlite:////data/gate.db \
    GATE_TRUST_PROXY=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY perathos_gate ./perathos_gate
RUN pip install --upgrade pip && pip install ".[postgres]"

RUN useradd --create-home --uid 10001 gate && mkdir -p /data && chown gate:gate /data
USER gate
VOLUME ["/data"]
EXPOSE 8787

# Prefer GATE_SIGNING_KEY (a 64-hex secret) on PaaS; otherwise mount /data and run `perathos-gate init` once.
CMD ["sh", "-c", "perathos-gate serve --host 0.0.0.0 --port ${PORT}"]
