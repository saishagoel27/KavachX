"""Local llama.cpp provider — the air-gapped path.

Talks the OpenAI-compatible ``/chat/completions`` surface exposed by ``llama-server``, so the
same code also drives vLLM, Ollama's compatibility endpoint or any other local server. This
is the provider that keeps the architecture capable of fully offline operation: no hosted
API, no egress, no third-party dependency on the reasoning path.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.config import settings
from app.core.errors import ModelUnavailable
from app.core.logging import get_logger
from app.llm.base import LLMProvider, LLMRequest, TokenBudget

logger = get_logger(__name__)


class LocalLlamaProvider(LLMProvider):
    name = "llama"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
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
        self.base_url = (base_url or settings.llama_base_url).rstrip("/")
        self.api_key = api_key or settings.llama_api_key
        self.models = models or settings.llm_models
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=httpx.Timeout(float(self.timeout_seconds)),
            )
        return self._client

    def model_for(self, hint: str) -> str:
        return self.models.get(hint, self.models.get("workhorse", "local-model"))

    async def _raw_generate(
        self, request: LLMRequest[Any], *, attempt: int, repair_hint: str | None
    ) -> tuple[str, int, int, str]:
        client = self._get_client()
        model = self.model_for(request.model_hint)
        system, user = self.build_prompt(request, repair_hint)

        body: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": request.temperature
            if request.temperature is not None
            else self.temperature,
            "max_tokens": request.max_output_tokens or self.max_output_tokens,
            "stream": False,
            # llama-server honours this; servers that don't simply ignore it and the strict
            # schema check still catches malformed output.
            "response_format": {"type": "json_object"},
        }

        try:
            response = await client.post("/chat/completions", json=body)
        except httpx.HTTPError as exc:
            raise ModelUnavailable(
                f"Local model server at {self.base_url} is unreachable: {exc}"
            ) from exc

        if response.status_code >= 400:
            raise ModelUnavailable(
                f"Local model server returned HTTP {response.status_code}.",
                details={"status": response.status_code, "body": response.text[:300]},
            )

        data = response.json()
        choices = data.get("choices") or []
        if not choices:
            raise ModelUnavailable("Local model server returned no choices.")
        text = (choices[0].get("message") or {}).get("content") or ""

        usage = data.get("usage") or {}
        tokens_in = int(usage.get("prompt_tokens") or 0) or (
            self.estimate_tokens(system) + self.estimate_tokens(user)
        )
        tokens_out = int(usage.get("completion_tokens") or 0) or self.estimate_tokens(text)
        return text, tokens_in, tokens_out, str(data.get("model") or model)

    async def health(self) -> dict[str, Any]:
        try:
            client = self._get_client()
            response = await client.get("/models")
            available = [m.get("id", "") for m in (response.json().get("data") or [])]
            return {
                "provider": self.name,
                "reachable": response.status_code < 400,
                "base_url": self.base_url,
                "models_configured": list(self.models.values()),
                "models_available": available[:60],
            }
        except Exception as exc:
            return {
                "provider": self.name,
                "reachable": False,
                "base_url": self.base_url,
                "error": str(exc)[:300],
            }

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
