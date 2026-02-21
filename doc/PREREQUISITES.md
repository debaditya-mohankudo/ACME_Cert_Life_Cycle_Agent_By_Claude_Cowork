# Prerequisites

- **Python 3.11+**
- **Port 80 available** (for standalone HTTP-01 challenge mode). On Linux, use `authbind` or `sudo` to bind port 80 as a non-root user. See [HTTP challenge modes](./HTTP_CHALLENGE_MODES.md) for options.
- **CA credentials** — for DigiCert: a DigiCert account with ACME enabled (Console → Automation → ACME), obtain your `ACME_EAB_KEY_ID` and `ACME_EAB_HMAC_KEY`. For Let's Encrypt: no credentials needed.
- An **LLM API key** — supports **Anthropic Claude** (default), **OpenAI**, or **Ollama** (local). See [LLM nodes and provider support](./LLM_NODES.md).
