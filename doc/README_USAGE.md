# Usage

## Run one renewal cycle immediately

```bash
python main.py --once
```

## Run on a daily schedule

```bash
python main.py --schedule
```

Runs immediately on start, then repeats daily at `SCHEDULE_TIME` (default `06:00` UTC).

## Override domains for a single run

```bash
python main.py --once --domains api.example.com shop.example.com
```

## Enable checkpointing (resume interrupted runs)

```bash
python main.py --once --checkpoint
```

Uses LangGraph's `MemorySaver` to checkpoint state after each node. If a run is interrupted mid-flow (e.g., a network failure during finalization), the graph can resume from the last completed node.

## Revoke certificates

Revoke one or more certificates via ACME POST /revokeCert:

```bash
python main.py --revoke-cert example.com
python main.py --revoke-cert example.com api.example.com --reason 4
```

### Revocation reason codes (RFC 5280)

| Code | Meaning |
|------|---------|
| `0` | Unspecified (default) |
| `1` | Key compromise |
| `4` | Superseded |
| `5` | Cessation of operation |

Example — revoke due to key compromise:

```bash
python main.py --revoke-cert example.com --reason 1
```

The revocation graph:
1. Sets up an ACME account (reuses existing key or creates new)
2. Loops through each target domain
3. Reads the certificate file from disk (`CERT_STORE_PATH/<domain>/cert.pem`)
4. POSTs a revoke request with the specified reason code
5. Generates a summary report of successes and failures

If a certificate file is not found, revocation fails for that domain and continues with the next one (best-effort).
