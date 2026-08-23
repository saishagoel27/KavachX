"""Sandbox image selection by detected project language.

The sandbox image is the *toolchain* the target is built and run against. A Python-only image has no
``npm``/``node``/``mvn``/``go``, so it can neither provision nor execute a Node, Java, or Go project —
which is exactly the ``npm: not found`` failure a hardcoded image produces. The image is therefore
chosen from the language the run-plan detector found, not fixed at Python.

Only the *toolchain* varies. The isolation is identical whichever image is picked: the adapter
supplies ``--runtime=runsc``, the capability drops, the resource caps, and — in the untrusted execute
phase — ``--network none`` and a read-only mount. See app/sandbox/gvisor.py.
"""

from __future__ import annotations

from app.config import settings


def image_for_language(language: str) -> str:
    """Map a detected language to its sandbox image.

    Languages without a dedicated toolchain image (python, c, unknown, …) fall back to the default
    image, which is Python plus a clang/llvm toolchain for native targets. Solidity maps to the Node
    image because Hardhat — the common toolchain — runs on Node.
    """
    lang = (language or "").strip().lower()
    return {
        "node": settings.sandbox_image_node,
        "javascript": settings.sandbox_image_node,
        "typescript": settings.sandbox_image_node,
        "solidity": settings.sandbox_image_node,
        "java": settings.sandbox_image_java,
        "kotlin": settings.sandbox_image_java,
        "go": settings.sandbox_image_go,
        "rust": settings.sandbox_image_rust,
    }.get(lang, settings.sandbox_image)


def image_for_framework(framework_id: str) -> str | None:
    """Sandbox image for a chosen framework, or ``None`` to defer to language detection.

    Used when the operator selects a framework in the run form: the framework fixes the toolchain
    (Next.js → Node, Spring → Java, …) regardless of what a shallow manifest scan would guess.
    """
    from app.analysis.frameworks import language_for_framework

    language = language_for_framework(framework_id)
    return image_for_language(language) if language else None
