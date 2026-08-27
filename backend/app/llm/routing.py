"""Task → model role routing.

The spec asks for an architecture that supports a small model plus a strong model, where the small
one does classification, summarisation and extraction and the strong one does the reasoning that
actually matters: vulnerability hypotheses, test synthesis, root cause, patch synthesis and
refutation strategy.

That split is expressed here as a table, in one place, rather than as a ``model_hint`` string
scattered across a dozen call sites. Three roles:

* ``router`` — the small, cheap model. Extraction and triage, where being wrong is recoverable
  because a deterministic component checks the answer immediately afterwards.
* ``workhorse`` — the general model. Structured proposals over a bounded context.
* ``security`` — the strong model. Tasks where a weak proposal wastes a whole patch iteration or a
  sandbox execution, so paying more per call is cheaper than the retry.

All three may point at the same model, and by default on a single-model deployment they do. The
value of the table is that the *intent* is recorded per task, so a deployment that has two models
gets the right one on each call without editing any call site.
"""

from __future__ import annotations

from typing import Any

from app.llm.base import LLMTask


class ModelRole:
    ROUTER = "router"
    WORKHORSE = "workhorse"
    SECURITY = "security"


#: Task → role. A task absent from this table falls back to ``workhorse``, which is the safe
#: default: a task nobody classified gets the general model rather than the cheapest one.
TASK_ROLES: dict[str, str] = {
    # -- extraction / classification: recoverable, checked immediately ---------
    LLMTask.PROBE_INTERFACES: ModelRole.ROUTER,
    LLMTask.STATIC_TRIAGE: ModelRole.ROUTER,
    LLMTask.ARCHITECTURE_ANNOTATE: ModelRole.ROUTER,
    # -- structured proposal over bounded context -----------------------------
    LLMTask.SAMHITA_PROPOSE: ModelRole.WORKHORSE,
    LLMTask.FLOW_TRIAGE: ModelRole.WORKHORSE,
    LLMTask.MUTATION_STRATEGIES: ModelRole.WORKHORSE,
    LLMTask.SIBLING_CANDIDATES: ModelRole.WORKHORSE,
    LLMTask.FUZZ_STRATEGY: ModelRole.WORKHORSE,
    # -- the expensive-to-get-wrong reasoning ---------------------------------
    LLMTask.SECURITY_HYPOTHESIS: ModelRole.SECURITY,
    LLMTask.TEST_SPEC: ModelRole.SECURITY,
    LLMTask.ROOT_CAUSE: ModelRole.SECURITY,
    LLMTask.PATCH_SYNTHESIS: ModelRole.SECURITY,
}


def role_for(task: str) -> str:
    return TASK_ROLES.get(task, ModelRole.WORKHORSE)


def routing_table() -> dict[str, Any]:
    """The active routing, for ``/api/system/llm`` and the certificate."""
    from app.config import settings

    models = settings.llm_models
    return {
        "roles": {
            role: models.get(role, models.get("workhorse", ""))
            for role in (ModelRole.ROUTER, ModelRole.WORKHORSE, ModelRole.SECURITY)
        },
        "tasks": dict(sorted(TASK_ROLES.items())),
        "single_model": len({
            models.get(ModelRole.ROUTER),
            models.get(ModelRole.WORKHORSE),
            models.get(ModelRole.SECURITY),
        }) == 1,
        "note": (
            "Roles may all point at one model. The table records which tasks would benefit from "
            "a stronger model on a multi-model deployment; it never changes what a deterministic "
            "component decides."
        ),
    }
