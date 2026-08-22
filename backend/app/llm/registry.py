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
from app.core.errors import BudgetExceeded, ModelUnavailable
from app.core.logging import get_logger
from app.llm.base import LLMProvider, TokenBudget
from app.llm.mock_provider import MockLLMProvider

logger = get_logger(__name__)


class FallbackProvider(LLMProvider):
    """Wraps a real provider and drops to the deterministic mock **at generation time**.

    Construction-time fallback (no key, no server) is handled in :func:`build_provider`. This
    class covers the other half: a provider that constructs fine but then fails a call — a Groq
    ``429`` rate limit, a ``404`` for a decommissioned model, a run of schema-invalid responses.
    Without this, one flaky model call fails the whole run; with it, the run completes on the
    deterministic proposer and says so (``fell_back_to_mock`` flips true, because "which model
    proposed this" is part of the evidence).

    A ``BudgetExceeded`` is never caught — the token ceiling is a hard stop, and the mock would
    not help. The call log is shared across primary and mock, so evidence stays in one place.
    """

    def __init__(self, *, primary: LLMProvider, budget: TokenBudget) -> None:
        super().__init__(budget=budget)
        self.primary = primary
        self.name = primary.name
        # One shared call log, so per-call evidence (provider/model per response) is complete
        # whichever provider actually answered.
        self.call_log = primary.call_log
        self._mock: MockLLMProvider | None = None
        self._fell_back = False

    async def _raw_generate(self, *_: Any, **__: Any) -> Any:  # pragma: no cover - never called
        raise NotImplementedError("FallbackProvider overrides generate() directly.")

    async def generate(self, request: Any) -> Any:
        try:
            return await self.primary.generate(request)
        except BudgetExceeded:
            raise
        except Exception as exc:
            logger.warning(
                "llm.runtime_fallback",
                task=getattr(request, "task", "?"),
                primary=self.primary.name,
                reason=str(exc)[:300],
            )
            if self._mock is None:
                self._mock = MockLLMProvider(budget=self.budget)
                self._mock.call_log = self.call_log
            self._fell_back = True
            self.name = "mock"  # honest: at least one proposal came from the deterministic proposer
            return await self._mock.generate(request)

    async def aclose(self) -> None:
        await self.primary.aclose()
        if self._mock is not None:
            await self._mock.aclose()


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

            real: LLMProvider = GroqProvider(budget=budget)
        elif name == "llama":
            from app.llm.llama_provider import LocalLlamaProvider

            real = LocalLlamaProvider(budget=budget)
        else:
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

    # Constructed fine. When fallback is enabled, wrap it so a runtime failure (429/404/schema)
    # degrades to the deterministic proposer instead of failing the whole run.
    if fallback:
        return FallbackProvider(primary=real, budget=budget)
    return real


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
