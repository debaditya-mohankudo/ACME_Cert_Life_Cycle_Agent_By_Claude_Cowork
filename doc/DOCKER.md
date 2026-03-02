# Running with Docker

## See also

- Wiki home: [WIKI_HOME.md](WIKI_HOME.md)
- Operations hub: [WIKI_OPERATIONS.md](WIKI_OPERATIONS.md)
- Docker non-root hardening: [DOCKER_NONROOT.md](DOCKER_NONROOT.md)
- Docker test flow: [DOCKER_TEST_FLOW.md](DOCKER_TEST_FLOW.md)
- Security considerations: [SECURITY.md](SECURITY.md)

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose v2

## Production — daily scheduler daemon

```bash
# 1. Copy the example config and fill in your values
cp .env.example .env
# Edit .env: set ANTHROPIC_API_KEY, MANAGED_DOMAINS, CA_PROVIDER, etc.

# 2. Build and start the agent in the background
docker compose up -d --build

# 3. Tail logs
docker compose logs -f acme-agent
```

The container runs `python main.py --schedule` by default, renewing certificates
daily at `SCHEDULE_TIME` (default `06:00` UTC).

**One-shot run** (renew once and exit):

```bash
docker compose run --rm acme-agent --once
```

**Override to one-shot in the compose file** — add `command: ["--once"]` under the
`acme-agent` service in `docker-compose.yml`.

## Port 80 and network security

The container exposes **a single port: 80**, and only for the brief window while an
ACME HTTP-01 challenge is being validated (typically a few seconds per domain).
No other port is opened or listened on at any time.

All other network traffic is **outbound-only**:

| Direction | Destination | Purpose |
|---|---|---|
| Outbound | CA ACME API (Let's Encrypt, DigiCert, …) | Certificate issuance |
| Outbound | LLM provider API (Anthropic, OpenAI, …) | Planner / reporter inference |
| Inbound | Port 80 (transient) | ACME HTTP-01 challenge response |

This means server owners can verify at a glance that the agent cannot act as a
backdoor, proxy, or listener: there is no inbound attack surface beyond the
standard ACME validation port, and that port is only open for the duration of a
renewal — not permanently.

If even that is undesirable (e.g. port 80 is already owned by nginx), switch to
webroot mode and the container needs **no inbound ports at all**:

```env
HTTP_CHALLENGE_MODE=webroot
WEBROOT_PATH=/var/www/html
```

In webroot mode the agent writes the challenge token file into a directory served
by your existing web server and never binds any port itself.

## Persistent storage

The named Docker volume `acme_data` is mounted at `/data/` inside the container.
It stores both the issued certificates (`CERT_STORE_PATH=/data/certs`) and the
ACME account key (`ACCOUNT_KEY_PATH=/data/account.key`). Data survives container
restarts and image rebuilds.

## Tests in Docker

**Default test command (matches CI exactly):**

```bash
docker build --target test -t acme-test .
docker run --rm acme-test
```

The `test` image runs:

```bash
uv run pytest -v -n auto -m "not integration"
```

This matches the canonical CI command documented in [CI_TEST_COVERAGE.md](CI_TEST_COVERAGE.md).

**Integration tests against Pebble (explicit run):**

```bash
docker compose -f docker-compose.pebble.yml up -d --build
docker compose -f docker-compose.pebble.yml run --rm acme-test uv run pytest -v -m "integration"
```

**Compose default run (still excludes integration):**

```bash
docker compose -f docker-compose.pebble.yml up --build --exit-code-from acme-test
```

This builds the `test` image, starts a local [Pebble](https://github.com/letsencrypt/pebble)
ACME server alongside it, and runs the CI-aligned non-integration test selection.
Use the explicit integration command above when you want Pebble-only integration coverage.

See also: [Docker test flow](./DOCKER_TEST_FLOW.md) for a detailed walkthrough.
