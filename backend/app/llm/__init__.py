"""LLM layer.

Contract: the model **proposes**, a deterministic component **validates**, the state machine
**decides**. Nothing in this package is allowed to mark anything verified.
"""

from app.llm.base import (
    LLMProvider,
    LLMRequest,
    LLMResponse,
    LLMTask,
    TokenBudget,
)
from app.llm.mock_provider import MockLLMProvider
from app.llm.registry import build_provider, provider_health

__all__ = [
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "LLMTask",
    "MockLLMProvider",
    "TokenBudget",
    "build_provider",
    "provider_health",
]
