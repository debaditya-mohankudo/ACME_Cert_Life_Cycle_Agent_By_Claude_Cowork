"""
LLM factory for the ACME Certificate Lifecycle Agent.

Centralises chat model construction so all nodes share one code path.
Provider is selected by LLM_PROVIDER in settings (anthropic | openai | ollama).
"""
from __future__ import annotations

from langchain.chat_models import init_chat_model
from langchain_core.language_models.chat_models import BaseChatModel

from config import settings


def make_llm(model: str, max_tokens: int) -> BaseChatModel:
    """Return a chat model for the configured LLM_PROVIDER."""
    provider = settings.LLM_PROVIDER
    kwargs: dict = {}

    if provider == "anthropic":
        if not settings.ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY must be set when LLM_PROVIDER='anthropic'. "
                "Add it to .env or set the environment variable."
            )
        kwargs["api_key"] = settings.ANTHROPIC_API_KEY
        kwargs["max_tokens"] = max_tokens

    elif provider == "openai":
        if not settings.OPENAI_API_KEY:
            raise ValueError(
                "OPENAI_API_KEY must be set when LLM_PROVIDER='openai'. "
                "Add it to .env or set the environment variable."
            )
        kwargs["api_key"] = settings.OPENAI_API_KEY
        kwargs["max_tokens"] = max_tokens

    elif provider == "ollama":
        # Ollama is local — no API key. Uses num_predict instead of max_tokens.
        kwargs["base_url"] = settings.OLLAMA_BASE_URL
        kwargs["num_predict"] = max_tokens

    else:
        raise ValueError(
            f"Unsupported LLM_PROVIDER: {provider!r}. "
            "Must be one of: 'anthropic', 'openai', 'ollama'."
        )

    return init_chat_model(model, model_provider=provider, **kwargs)
