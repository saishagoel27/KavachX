"""Auto-loaded at interpreter startup inside the KavachX sandbox.

CPython imports ``sitecustomize`` from ``sys.path`` during ``site`` initialisation. The sandbox
puts the harness directory first on ``PYTHONPATH``, so this module — and therefore the network
denial in :mod:`kx_guard` — is active *before any target code runs*, including code executed by
child processes the target itself spawns.
"""

from __future__ import annotations

try:
    import kx_guard

    kx_guard.install()
except Exception:  # pragma: no cover - never let instrumentation break the target
    pass

# A deployed shield gates the request *before* the target executes. Importing it here is what
# makes that true for a plain CLI invocation: the interpreter has not yet run the entry script.
try:  # pragma: no cover - only active while a shield is deployed
    import os

    if os.environ.get("KAVACHX_SHIELD_RULES"):
        import kx_shield

        kx_shield.gate_argv()
except SystemExit:
    raise
except Exception:
    pass
