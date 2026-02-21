# LLM Nodes and Provider Support

All three LLM decision points use a **provider-agnostic factory** (`llm.factory.make_llm()`), allowing you to switch between vendors by changing a single config variable.

| Node | Default model | Responsibility |
|---|---|---|
| `renewal_planner` | Haiku | Classify domains as urgent / routine / skip; output is validated JSON |
| `error_handler` | Sonnet | Diagnose ACME failures; decide retry / skip / abort and schedule backoff via `retry_scheduler` |
| `retry_scheduler` | — | Apply backoff delay before retrying (separates timing from error analysis) |
| `summary_reporter` | Haiku | Generate a human-readable run summary for ops teams |

The planner validates its own output: any domain name the LLM returns that is not in `MANAGED_DOMAINS` is stripped before use, preventing hallucinated domains from triggering unintended renewals.

## LLM provider configuration

The agent supports **Anthropic Claude** (default), **OpenAI**, and **Ollama**. Switch providers by setting `LLM_PROVIDER` in `.env`:

### Anthropic (default)

```dotenv
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
LLM_MODEL_PLANNER=claude-haiku-4-5-20251001
LLM_MODEL_REPORTER=claude-haiku-4-5-20251001
LLM_MODEL_ERROR_HANDLER=claude-sonnet-4-6
```

### OpenAI

```dotenv
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
LLM_MODEL_PLANNER=gpt-4o-mini
LLM_MODEL_REPORTER=gpt-4o-mini
LLM_MODEL_ERROR_HANDLER=gpt-4o
```

### Ollama (local)

```dotenv
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
LLM_MODEL_PLANNER=llama3.2
LLM_MODEL_REPORTER=llama3.2
LLM_MODEL_ERROR_HANDLER=llama3.2
```
