# How Pebble Integration Tests Run with the Docker Image

This document explains end-to-end what happens when you run:

```bash
docker compose -f docker-compose.pebble.yml up --build --exit-code-from acme-test
```

---

## The two containers

Docker Compose creates a private bridge network and starts both services on it:

```
┌─────────────────────────────────────────────────────────┐
│              Docker Compose bridge network               │
│                                                         │
│  ┌──────────────────────┐   ┌──────────────────────┐   │
│  │  pebble              │   │  acme-test           │   │
│  │  (Pebble ACME stub)  │   │  (pytest runner)     │   │
│  │  :14000  ACME dir    │   │  built from          │   │
│  │  :15000  mgmt API    │   │  Dockerfile          │   │
│  └──────────────────────┘   │  target: test        │   │
│                              └──────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

`acme-test` declares `depends_on: pebble`, so Compose starts Pebble first and only
then starts the test runner container.

---

## Step 1 — `acme-test` image is built from the `test` stage

`Dockerfile` stage 4 (`test`):

```dockerfile
FROM base AS test
COPY . .          # full source tree including tests/
ENTRYPOINT []
CMD ["pytest", "tests/", "-v"]
```

This is an **independent path** from the `production` stage. It does not go through
the `test-runner` stage (which runs unit tests during a production build), so the
image builds quickly without re-running unit tests.

---

## Step 2 — Environment variables configure the agent to talk to Pebble

`docker-compose.pebble.yml` injects these into the `acme-test` container:

| Variable | Value | Purpose |
|---|---|---|
| `PEBBLE_HOST` | `pebble` | Docker service name — used by conftest to probe and connect |
| `ACME_DIRECTORY_URL` | `https://pebble:14000/dir` | Points the ACME client at Pebble instead of a real CA |
| `ACME_INSECURE` | `true` | Skips TLS verification (Pebble uses a self-signed CA) |
| `CA_PROVIDER` | `custom` | Tells `make_client()` to use `ACME_DIRECTORY_URL` directly |
| `HTTP_CHALLENGE_MODE` | `webroot` | No port-80 binding needed — Pebble skips real HTTP validation |
| `ANTHROPIC_API_KEY` | `dummy-key-for-testing` | Satisfies the settings singleton; LLM calls are mocked |

These are consumed by `config.Settings` (Pydantic, env-based) at import time. By the
time pytest starts, the whole agent stack already believes it is talking to `pebble:14000`.

---

## Step 3 — `conftest.py` decides which tests to run

`tests/conftest.py` at module load time:

```python
_PEBBLE_HOST = os.getenv("PEBBLE_HOST", "localhost")   # → "pebble" inside Docker

def _pebble_running(host=_PEBBLE_HOST, port=14000):
    try:
        socket.create_connection((host, port), timeout=1)
        return True
    except OSError:
        return False

requires_pebble = pytest.mark.skipif(not _pebble_running(), ...)
```

Inside the container, `_PEBBLE_HOST = "pebble"` (from the env var injected by
Compose). The socket probe connects to `pebble:14000` on the Docker bridge — Pebble
is already up (`depends_on`), so `_pebble_running()` returns `True` and
`requires_pebble` becomes a no-op mark: **all integration tests run**.

Without Docker (local development with no Pebble), `_PEBBLE_HOST = "localhost"`,
the probe fails, and those tests are **automatically skipped** rather than failing.

---

## Step 4 — `pebble_settings` fixture redirects the settings singleton

Every integration test declares `pebble_settings` as a fixture argument.
Before each test the fixture:

1. Saves original values of the module-level `config.settings` singleton.
2. Overwrites them in-process:
   ```python
   settings.ACME_DIRECTORY_URL = f"https://{_PEBBLE_HOST}:14000/dir"
   settings.ACME_INSECURE      = True
   settings.CERT_STORE_PATH    = str(tmp_path / "certs")   # fresh per-test dir
   settings.ACCOUNT_KEY_PATH   = str(tmp_path / "account.key")
   settings.HTTP_CHALLENGE_MODE = "webroot"
   settings.WEBROOT_PATH       = str(tmp_path / "webroot")
   ```
3. Yields the patched settings to the test body.
4. Restores original values on teardown.

Each test therefore gets a **clean, isolated filesystem** (pytest's `tmp_path`) and a
guaranteed pointer to Pebble — no leftover state from a previous test.

---

## Step 5 — `mock_llm_nodes` patches out real LLM calls

```python
with patch("llm.factory.init_chat_model",
           return_value=_mock_llm_response(PLANNER_RESPONSE)):
    yield
```

`init_chat_model` is the single call-site all nodes go through (`llm/factory.py`).
Replacing it with a mock means:

- No real Anthropic / OpenAI API call is ever made.
- The planner always returns `{"routine": ["acme-test.localhost"], ...}`.
- The reporter returns a canned summary string.
- Every other node — account, order, challenge, CSR, finalizer, storage — runs its
  **real implementation** against Pebble.

---

## Step 6 — The full ACME flow runs against Pebble

`test_full_renewal_flow` calls `graph.invoke(state)`. The LangGraph node chain
executes in sequence:

```
scanner → planner (mocked LLM)
        → account   POST https://pebble:14000/sign-me-up
        → order     POST https://pebble:14000/order-plz
        → challenge  write token to /tmp/pebble-webroot/.well-known/acme-challenge/<token>
                     POST pebble to trigger validation
                     ↳ Pebble: PEBBLE_VA_ALWAYS_VALID=1 → auto-approves, no real HTTP needed
        → csr        generate RSA key + CSR in-memory
        → finalizer  POST CSR, poll until cert issued, download chain
        → storage    write cert.pem / chain.pem / fullchain.pem / privkey.pem / metadata.json
        → reporter (mocked LLM)
```

Every ACME operation is real RFC 8555 traffic between the two Docker containers.

---

## Step 7 — Assertions verify the complete outcome

After `graph.invoke()` returns, each test asserts:

| Assertion | What it proves |
|---|---|
| `domain in result["completed_renewals"]` | Full flow reached `storage` node without error |
| `result["failed_renewals"] == []` | No domain ended in the error path |
| All 5 PEM/JSON files exist in `tmp_path` | `storage` node wrote every file |
| `privkey.pem` mode is `0o600` | Private key is owner-read-only (security requirement) |
| `cert.pem` parses as valid PEM | Certificate is well-formed |
| `metadata.json` contains `issued_at` / `expires_at` | Metadata written correctly |

`test_certificate_lifecycle` additionally runs the agent **twice** with
`renewal_threshold_days=9999` to force a renewal, verifies the serial number changed
(proving a genuinely new cert was issued), then calls `client.revoke_certificate()`
directly against Pebble's `/revokeCert` endpoint.

---

## The full trust chain at a glance

```
docker-compose.pebble.yml
  └─ starts pebble + acme-test on shared Docker network
       └─ PEBBLE_HOST=pebble → conftest._PEBBLE_HOST="pebble"
            ├─ _pebble_running("pebble") → True → @requires_pebble is a no-op
            ├─ pebble_settings fixture → ACME_DIRECTORY_URL="https://pebble:14000/dir"
            │                            isolated tmp_path per test
            └─ mock_llm_nodes fixture  → no real Anthropic/OpenAI calls
                 └─ graph.invoke() — full ACME RFC 8555 flow over Docker network
                      └─ Pebble: PEBBLE_VA_ALWAYS_VALID=1 → auto-approves challenges
                           └─ cert issued, files written, assertions pass → exit 0
```

The only thing mocked is the LLM. Every ACME protocol operation — account
registration, order creation, challenge validation, CSR submission, certificate
issuance, download, and revocation — is real network traffic between the two
containers.
