"""One provider for every OpenAI-compatible server: llama.cpp, Ollama, vLLM, LM Studio, TGI.

These all expose the same ``/chat/completions`` surface, so a provider per vendor would be four
copies of one HTTP call differing only in a base URL and a default model name. Instead there is
one implementation plus a :data:`PRESETS` table, which is also what keeps the model
*configurable rather than hardcoded*: switching from Qwen3-Coder on llama.cpp to a different model
on vLLM is a change to two environment variables, not a code change.

The self-hosted path matters beyond convenience. It is the only configuration in which a security
tool can analyse a private repository with **no egress on the reasoning path at all** — which is
why it is a first-class provider here and not an afterthought.

Two behaviours worth naming because they are easy to get wrong:

* **``response_format`` is offered, never relied on.** llama.cpp and vLLM honour
  ``{"type": "json_object"}``; Ollama's compatibility layer historically ignored it. The strict
  Pydantic validation in :class:`~app.llm.base.LLMProvider` is the actual guarantee, and the
  retry-with-repair-hint loop is what makes a server that ignores the hint still usable.
* **Token accounting falls back to estimation, and says so.** A server that omits ``usage`` would
  otherwise silently charge nothing against the run's token budget, which would defeat the hard
  ceiling. When usage is absent the estimate is used and the response is flagged, so the budget
  stays enforced and the certificate does not present an estimate as a measurement.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from app.config import settings
from app.core.errors import ModelUnavailable
from app.core.logging import get_logger
from app.llm.base import LLMProvider, LLMRequest, TokenBudget

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ProviderPreset:
    """Defaults for one flavour of OpenAI-compatible server."""

    id: str
    label: str
    default_base_url: str
    #: Whether the server is known to honour ``response_format: json_object``.
    supports_response_format: bool = True
    #: Servers that require *some* Authorization header even when unauthenticated.
    requires_auth_header: bool = False
    notes: str = ""


PRESETS: dict[str, ProviderPreset] = {
    "llama": ProviderPreset(
        "llama",
        "llama.cpp (llama-server)",
        "http://localhost:8080/v1",
        supports_response_format=True,
        notes="Fully offline. The reference air-gapped configuration.",
    ),
    "ollama": ProviderPreset(
        "ollama",
        "Ollama",
        "http://localhost:11434/v1",
        # Ollama's OpenAI compatibility layer has historically ignored response_format; the
        # schema validator and repair retry cover it either way.
        supports_response_format=False,
        notes="Fully offline. Model names are Ollama tags, e.g. qwen3-coder:30b.",
    ),
    "vllm": ProviderPreset(
        "vllm",
        "vLLM",
        "http://localhost:8000/v1",
        supports_response_format=True,
        notes="Fully offline. Highest throughput of the local options.",
    ),
    "openai_compatible": ProviderPreset(
        "openai_compatible",
        "Any OpenAI-compatible endpoint",
        "http://localhost:8080/v1",
        supports_response_format=True,
        requires_auth_header=True,
        notes=(
            "Generic escape hatch. Points at any server speaking /chat/completions, including a "
            "hosted one — in which case the reasoning path is no longer offline."
        ),
    ),
}


class OpenAICompatibleProvider(LLMProvider):
    """Talks ``/chat/completions`` to any compatible server."""

    def __init__(
        self,
        *,
        preset: str = "llama",
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
        self.preset = PRESETS.get(preset, PRESETS["llama"])
        self.name = self.preset.id
        self.base_url = (base_url or _configured_base_url(self.preset.id)).rstrip("/")
        self.api_key = api_key if api_key is not None else _configured_api_key(self.preset.id)
        self.models = models or settings.llm_models
        #: Set when a response carried no usage block, so the run can report that its token
        #: figures are estimates rather than measurements.
        self.estimated_usage_calls = 0
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            elif self.preset.requires_auth_header:
                # Some gateways reject a request with no Authorization header at all, even when
                # they do not check it. A placeholder is not a credential and is never logged.
                headers["Authorization"] = "Bearer unused"
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
        }
        if self.preset.supports_response_format:
            body["response_format"] = {"type": "json_object"}

        try:
            response = await client.post("/chat/completions", json=body)
        except httpx.HTTPError as exc:
            raise ModelUnavailable(
                f"{self.preset.label} at {self.base_url} is unreachable: {exc}"
            ) from exc

        if response.status_code >= 400:
            raise ModelUnavailable(
                f"{self.preset.label} returned HTTP {response.status_code}.",
                details={"status": response.status_code, "body": response.text[:300]},
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise ModelUnavailable(
                f"{self.preset.label} returned a non-JSON body.",
                details={"body": response.text[:300]},
            ) from exc

        choices = data.get("choices") or []
        if not choices:
            raise ModelUnavailable(f"{self.preset.label} returned no choices.")
        message = choices[0].get("message") or {}
        text = message.get("content") or ""
        if not text and message.get("reasoning_content"):
            # Some reasoning models put everything in reasoning_content when the answer is short.
            text = str(message["reasoning_content"])

        usage = data.get("usage") or {}
        reported_in = int(usage.get("prompt_tokens") or 0)
        reported_out = int(usage.get("completion_tokens") or 0)
        if not reported_in and not reported_out:
            self.estimated_usage_calls += 1
            logger.debug(
                "llm.usage_estimated", provider=self.name, task=request.task, model=model
            )
        tokens_in = reported_in or (self.estimate_tokens(system) + self.estimate_tokens(user))
        tokens_out = reported_out or self.estimate_tokens(text)
        return text, tokens_in, tokens_out, str(data.get("model") or model)

    # ------------------------------------------------------------------
    async def health(self) -> dict[str, Any]:
        try:
            client = self._get_client()
            response = await client.get("/models")
            payload = response.json() if response.status_code < 400 else {}
            available = [str(m.get("id", "")) for m in (payload.get("data") or [])]
            configured = list(self.models.values())
            missing = [m for m in configured if available and m not in available]
            return {
                "provider": self.name,
                "label": self.preset.label,
                "reachable": response.status_code < 400,
                "base_url": self.base_url,
                "offline_capable": self.preset.id in ("llama", "ollama", "vllm"),
                "models_configured": configured,
                "models_available": available[:60],
                # Naming the mismatch is the difference between a run that fails at the first
                # model call with a 404 and one the operator could have fixed in advance.
                "models_missing": missing,
                "notes": self.preset.notes,
            }
        except Exception as exc:
            return {
                "provider": self.name,
                "label": self.preset.label,
                "reachable": False,
                "base_url": self.base_url,
                "error": str(exc)[:300],
            }

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


# ---------------------------------------------------------------------------
def _configured_base_url(preset_id: str) -> str:
    """Base URL for a preset, from its own setting then the preset default."""
    explicit = {
        "llama": settings.llama_base_url,
        "ollama": settings.ollama_base_url,
        "vllm": settings.vllm_base_url,
        "openai_compatible": settings.openai_compatible_base_url,
    }.get(preset_id, "")
    return explicit or PRESETS.get(preset_id, PRESETS["llama"]).default_base_url


def _configured_api_key(preset_id: str) -> str:
    return {
        "llama": settings.llama_api_key,
        "ollama": settings.ollama_api_key,
        "vllm": settings.vllm_api_key,
        "openai_compatible": settings.openai_compatible_api_key,
    }.get(preset_id, "")


class LocalLlamaProvider(OpenAICompatibleProvider):
    """Back-compatible name for the llama.cpp preset.

    Kept so existing imports and ``LLM_PROVIDER=llama`` keep working unchanged after the provider
    surface was generalised.
    """

    name = "llama"

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("preset", "llama")
        super().__init__(**kwargs)
