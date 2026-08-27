"""Security test synthesis: findings become executable, oracle-judged tests.

The pipeline this package implements, and the authority boundary inside it:

    candidate → TestSpec → validation → harness generator → sandbox → oracle → verdict
                  ▲            ▲              ▲                ▲         ▲
              the model    Pydantic       KavachX          existing   KavachX
              proposes     enforces       generates        adapter    decides

* :mod:`app.testing.specs` — ``TestSpec``: a structured testing *intention*. The model fills
  fields; it never supplies code, a command, an interpreter or a path.
* :mod:`app.testing.oracles` — deterministic verdicts (FIRED / HELD / UNSUPPORTED) from observable
  signals only.
* :mod:`app.testing.engines` — real engines (Hypothesis, Atheris, libFuzzer, AFL++, ASan/UBSan,
  fast-check), probed rather than assumed. An absent engine means NOT RUN, never "clean".
* :mod:`app.testing.harness` — generators. Every harness is a KavachX template; spec values are
  inserted as data literals.
* :mod:`app.testing.executor` — runs harnesses through the existing sandbox adapter, unchanged,
  with independent reproductions.
* :mod:`app.testing.coverage` — coverage as a bound on assurance *and* as a steering signal.
* :mod:`app.testing.fuzzing` — the coverage-guided loop. LLM-guided, not LLM-implemented.
* :mod:`app.testing.regression` — the reproduced exploit, preserved as a durable test.
* :mod:`app.testing.synthesis` — the engine that ties it together, with a deterministic fallback
  so the pipeline works with no model at all.
"""

from app.testing.coverage import CoverageObservation
from app.testing.executor import TestExecution, TestExecutor
from app.testing.oracles import OracleResult, Verdict
from app.testing.specs import OracleSpec, TestPlan, TestPlanStatus, TestSpec, TestSpecProposal
from app.testing.synthesis import TestSynthesisEngine, deterministic_specs

__all__ = [
    "CoverageObservation",
    "OracleResult",
    "OracleSpec",
    "TestExecution",
    "TestExecutor",
    "TestPlan",
    "TestPlanStatus",
    "TestSpec",
    "TestSpecProposal",
    "TestSynthesisEngine",
    "Verdict",
    "deterministic_specs",
]
