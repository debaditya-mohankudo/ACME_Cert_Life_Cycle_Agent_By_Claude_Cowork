---
name: acme-test-pebble
description: Local CA for integration testing is Pebble — how to spin it up
metadata:
  type: reference
  domain: acme
  priority: 20
  tags: testing, pebble, integration, docker, ca
---

Local test CA is **Pebble** (Let's Encrypt's lightweight ACME test server). Spun up via Docker.

```bash
docker compose -f docker-compose.pebble.yml up -d
pytest tests/test_integration_pebble.py tests/test_lifecycle_pebble.py -v
```

Integration tests are marked `@pytest.mark.integration` — excluded from the default `pytest -n auto -m "not integration"` run.

Use `pebble_settings` fixture to mutate the settings singleton in tests (auto-restores via teardown).
Use `mock_llm_nodes` fixture to patch `llm.factory.init_chat_model` — avoids needing a real API key in unit tests.
