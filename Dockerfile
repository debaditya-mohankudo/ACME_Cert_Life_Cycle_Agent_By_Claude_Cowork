# ── Stage 1: base ─────────────────────────────────────────────────────────────
# Installs all Python dependencies (shared by all stages).
FROM python:3.12-slim AS base

COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /bin/uv

WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH"

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --group dev --no-install-project


# ── Stage 2: test-runner ──────────────────────────────────────────────────────
# Runs unit tests during the image build.  The build fails here if any test
# fails — the production stage is unreachable until all tests pass.
FROM base AS test-runner

COPY . .

# Provide a dummy key so the settings singleton initialises without error;
# unit tests mock all LLM calls and never actually reach the API.
ENV ANTHROPIC_API_KEY=dummy-build-key

RUN pytest tests/test_unit_acme.py -v


# ── Stage 3: production ───────────────────────────────────────────────────────
# Long-running daemon that renews certs on a daily schedule.
# Only reachable when the test-runner stage above has succeeded.
FROM base AS production

# Copy only application source from the tested stage (tests excluded).
COPY --from=test-runner /app/agent   ./agent
COPY --from=test-runner /app/acme    ./acme
COPY --from=test-runner /app/llm     ./llm
COPY --from=test-runner /app/storage ./storage
COPY --from=test-runner /app/config.py /app/main.py ./

# Redirect persistent data to /data/ — mount a named volume here so certs and
# the ACME account key survive container restarts.
ENV CERT_STORE_PATH=/data/certs
ENV ACCOUNT_KEY_PATH=/data/account.key

# Non-root user.  Port 80 binding is granted at runtime via NET_BIND_SERVICE
# (see docker-compose.yml cap_add) — no root required inside the container.
RUN useradd -r -u 1001 -M -s /sbin/nologin acme \
    && mkdir -p /data/certs \
    && chown -R 1001 /data

USER 1001

# Port 80 is used by the HTTP-01 standalone challenge server (temporary, during
# each renewal window). Map the host's port 80 to this port via docker-compose.
EXPOSE 80

ENTRYPOINT ["python", "main.py"]
CMD ["--schedule"]


# ── Stage 4: test ─────────────────────────────────────────────────────────────
# Explicit test runner for CI / docker-compose.pebble.yml.
# Runs the full suite including Pebble integration tests.
# All test deps (pytest, pytest-asyncio, responses) are in requirements.txt.
FROM base AS test

COPY . .

ENTRYPOINT []
CMD ["pytest", "-v", "-n", "auto", "-m", "not integration"]
