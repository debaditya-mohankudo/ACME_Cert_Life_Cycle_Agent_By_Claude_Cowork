# Dependencies

| Package | Purpose |
|---|---|
| `langgraph` | Stateful agent graph execution |
| `langchain` | LLM abstraction layer |
| `langchain-anthropic` | Claude LLM integration (default) |
| `langchain-openai` | OpenAI LLM integration |
| `langchain-ollama` | Ollama LLM integration (local models) |
| `josepy` | JWK / JWS signing (Certbot's battle-tested library) |
| `cryptography` | Key generation, CSR creation, certificate parsing |
| `requests` | ACME HTTP client |
| `pydantic-settings` | Environment-based configuration with validation |
| `schedule` | Lightweight daily scheduler |
| `structlog` | Structured logging |
| `pytest` + `responses` | Unit testing with mocked HTTP |
