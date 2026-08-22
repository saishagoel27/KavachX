"""Groq provider — the default hosted inference path.

Groq speaks an OpenAI-compatible chat API and supports ``response_format={"type":
"json_object"}``, which pairs well with the strict-schema contract: the transport enforces
"valid JSON", and :class:`~app.llm.base.LLMProvider` then enforces "valid *for this schema*".

Token accounting comes from the API's own ``usage`` block, so the resource meter in the
console shows real numbers rather than an estimate.
"""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.core.errors import ModelUnavailable
from app.core.logging import get_logger
from app.llm.base import LLMProvider, LLMRequest, TokenBudget

logger = get_logger(__name__)


class GroqProvider(LLMProvider):
    name = "groq"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        models: dict[str, str] | None = None,
        timeout_seconds: int | None = None,
        max_retries: int | None = None,
        max_output_tokens: int | None = None,
        temperature: float | None = None,
        budget: TokenBudget | None = None,
    ) -> None:
        super().__init__(
            timeout_seconds=timeout_seconds or settings.llm_timeout_seconds,
            max_retries=max_retries if max_retries is not None else settings.llm_max_retries,
            max_output_tokens=max_output_tokens or settings.llm_max_output_tokens,
            temperature=temperature if temperature is not None else settings.llm_temperature,
            budget=budget,
        )
        self.api_key = api_key or settings.groq_api_key
        self.base_url = (base_url or settings.groq_base_url).rstrip("/")
        self.models = models or settings.llm_models
        self._client: Any = None

        if not self.api_key:
            raise ModelUnavailable(
                "GROQ_API_KEY is not set.",
                code="GROQ_API_KEY_MISSING",
            )

    # -- client ------------------------------------------------------------
    def _get_client(self) -> Any:
        if self._client is None:
            try:
                from groq import AsyncGroq
            except ImportError as exc:  # pragma: no cover
                raise ModelUnavailable(
                    "The groq package is not installed. Run `uv sync` in backend/."
                ) from exc
            self._client = AsyncGroq(
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=float(self.timeout_seconds),
                # Retries are handled by LLMProvider.generate so that a schema repair hint
                # can be attached to the next attempt.
                max_retries=0,
            )
        return self._client

    def model_for(self, hint: str) -> str:
        return self.models.get(hint, self.models.get("workhorse", "openai/gpt-oss-120b"))

    # -- generation --------------------------------------------------------
    async def _raw_generate(
        self, request: LLMRequest[Any], *, attempt: int, repair_hint: str | None
    ) -> tuple[str, int, int, str]:
        from groq import APIStatusError, GroqError

        client = self._get_client()
        model = self.model_for(request.model_hint)
        system, user = self.build_prompt(request, repair_hint)

        try:
            completion = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=request.temperature
                if request.temperature is not None
                else self.temperature,
                max_tokens=request.max_output_tokens or self.max_output_tokens,
                response_format={"type": "json_object"},
                stream=False,
            )
        except APIStatusError as exc:
            raise ModelUnavailable(
                f"Groq returned HTTP {exc.status_code} for model {model}.",
                details={"status": exc.status_code, "model": model},
            ) from exc
        except GroqError as exc:
            raise ModelUnavailable(f"Groq request failed: {exc}") from exc

        choices = getattr(completion, "choices", None) or []
        if not choices:
            raise ModelUnavailable("Groq returned no choices.")
        text = choices[0].message.content or ""

        usage = getattr(completion, "usage", None)
        tokens_in = int(getattr(usage, "prompt_tokens", 0) or 0)
        tokens_out = int(getattr(usage, "completion_tokens", 0) or 0)
        if not tokens_in:
            tokens_in = self.estimate_tokens(system) + self.estimate_tokens(user)
        if not tokens_out:
            tokens_out = self.estimate_tokens(text)

        return text, tokens_in, tokens_out, model

    async def health(self) -> dict[str, Any]:
        """Cheap reachability probe used by ``/api/system/llm``."""
        try:
            client = self._get_client()
            listing = await client.models.list()
            available = sorted(getattr(m, "id", "") for m in getattr(listing, "data", []))
            configured = list(self.models.values())
            return {
                "provider": self.name,
                "reachable": True,
                "models_configured": configured,
                "models_missing": [m for m in configured if available and m not in available],
                "models_available": available[:60],
            }
        except Exception as exc:
            return {"provider": self.name, "reachable": False, "error": str(exc)[:300]}

    async def aclose(self) -> None:
        if self._client is not None:
            close = getattr(self._client, "close", None)
            if close is not None:
                try:
                    await close()
                except Exception:  # pragma: no cover
                    pass
            self._client = None
