# How It Works

The agent is a LangGraph `StateGraph` that walks through the ACME protocol step-by-step, with three LLM decision points:

```
START
  │
  ▼
[certificate_scanner]     — reads ./certs/<domain>/cert.pem, parses expiry
  │
  ▼
[renewal_planner] (LLM)   — classifies domains: urgent / routine / skip
  │
  ├── no renewals needed ──────────────────────────────────► [summary_reporter] ──► END
  │
  ▼
[acme_account_setup]      — registers or retrieves ACME account (EAB injected by CA subclass)
  │
  ▼
[pick_next_domain] ◄──────────────────────────────────────────────────────────┐
  │                                                                            │
  ▼                                                                            │
[order_initializer]       — POST /newOrder, fetch HTTP-01 challenge tokens    │
  │                                                                            │
  ▼                                                                            │
[challenge_setup]         — serve token (standalone server or webroot)        │
  │                                                                            │
  ▼                                                                            │
[challenge_verifier]      — trigger CA verification, poll until valid         │
  │                                                                            │
  ├── failed ──► [error_handler] (LLM) ─── retry ──► [retry_scheduler] ──────┤
  │                                    ├── skip  ────────────────────────────►│
  │                                    └── abort ──────────────────────────► [summary_reporter]
  ▼                                                                            │
[csr_generator]           — generate RSA-2048 private key + CSR               │
  │                                                                            │
  ▼                                                                            │
[order_finalizer]         — POST CSR to /finalize, poll for certificate URL   │
  │                                                                            │
  ▼                                                                            │
[cert_downloader]         — POST-as-GET certificate chain (PEM)               │
  │                                                                            │
  ▼                                                                            │
[storage_manager]         — write cert.pem, chain.pem, fullchain.pem,        │
  │                          privkey.pem, metadata.json to ./certs/<domain>/  │
  │                                                                            │
  ├── more domains ────────────────────────────────────────────────────────────┘
  │
  └── all done ──► [summary_reporter] (LLM) ──► END
```
