"""Back-compatible import site for the llama.cpp provider.

The implementation moved to :mod:`app.llm.openai_compatible`, where one provider serves
llama.cpp, Ollama, vLLM and any other OpenAI-compatible server. This module is kept so existing
imports of ``LocalLlamaProvider`` and any deployment pinned to ``LLM_PROVIDER=llama`` keep working
without change.
"""

from __future__ import annotations

from app.llm.openai_compatible import LocalLlamaProvider, OpenAICompatibleProvider

__all__ = ["LocalLlamaProvider", "OpenAICompatibleProvider"]
