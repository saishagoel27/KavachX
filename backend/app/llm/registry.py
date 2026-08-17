"""Provider selection.

One entry point, ``build_provider``, so a run records exactly which provider produced its
proposals. If the configured provider cannot be constructed (no key, no local server) and
``LLM_FALLBACK_TO_MOCK`` is on, the run continues on the deterministic proposer and says so —
the run trace and the certificate both name the provider that was actually used, because
"which model proposed this" is part of the evidence.
"""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.core.errors import ModelUnavailable
from app.core.logging import get_logger
from app.llm.base import LLMProvider, TokenBudget
from app.llm.mock_provider import MockLLMProvider

logger = get_logger(__name__)


def build_provider(
    *,
    provider_name: str | None = None,
    budget: TokenBudget | None = None,
    allow_fallback: bool | None = None,
) -> LLMProvider:
    name = (provider_name or settings.llm_provider).lower()
    fallback = settings.llm_fallback_to_mock if allow_fallback is None else allow_fallback
    budget = budget or TokenBudget(limit=settings.llm_run_token_budget)

    if name == "mock":
        return MockLLMProvider(budget=budget)

    try:
        if name == "groq":
            from app.llm.groq_provider import GroqProvider

            return GroqProvider(budget=budget)
        if name == "llama":
            from app.llm.llama_provider import LocalLlamaProvider

            return LocalLlamaProvider(budget=budget)
        raise ModelUnavailable(f"Unknown LLM provider {name!r}.")
    except Exception as exc:
        if not fallback:
            raise
        logger.warning(
            "llm.provider_fallback",
            requested=name,
            fallback="mock",
            reason=str(exc)[:300],
        )
        return MockLLMProvider(budget=budget)


async def provider_health(provider_name: str | None = None) -> dict[str, Any]:
    name = (provider_name or settings.llm_provider).lower()
    if name == "mock":
        return {
            "provider": "mock",
            "reachable": True,
            "models_configured": ["mock-proposer/deterministic"],
            "note": "Deterministic scripted proposer. Offline. Used by the test suite.",
        }
    provider = build_provider(provider_name=name, allow_fallback=False)
    try:
        health = getattr(provider, "health", None)
        if health is None:
            return {"provider": name, "reachable": True}
        return await health()
    finally:
        await provider.aclose()
