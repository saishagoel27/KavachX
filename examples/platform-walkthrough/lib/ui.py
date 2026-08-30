"""Terminal presentation for the walkthrough.

Deliberately plain: ANSI colour where the terminal supports it, ASCII where it does not, and no
dependency outside the standard library. Nothing here invents a value — every helper takes what
the caller already read from the API and lays it out.

Two things are negotiated with the terminal once, at startup, by :func:`configure`:

* **colour** — only when the caller asked for it, stdout is a TTY, and (on Windows) virtual
  terminal processing could actually be switched on;
* **encoding** — the em dashes and middle dots below are worth having, but a console still on a
  legacy code page would render them as replacement characters. When UTF-8 cannot be arranged,
  every string printed through this module is transliterated to ASCII instead.
"""

from __future__ import annotations

import os
import sys
import textwrap
from collections.abc import Iterable
from typing import Any

WIDTH = 92

_ENABLED = False
_ASCII = False

#: Applied to every string this module prints, when the output stream cannot carry UTF-8.
_ASCII_MAP = str.maketrans(
    {
        "—": "--",
        "–": "-",
        "·": "*",
        "…": "...",
        "→": "->",
        "←": "<-",
        "⇒": "=>",
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "×": "x",
    }
)


class C:
    """ANSI codes, blanked out when colour is off."""

    RESET = BOLD = DIM = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = GREY = ""


_CODES = {
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RED": "\033[31m",
    "GREEN": "\033[32m",
    "YELLOW": "\033[33m",
    "BLUE": "\033[34m",
    "MAGENTA": "\033[35m",
    "CYAN": "\033[36m",
    "GREY": "\033[90m",
}


def configure(*, colour: bool) -> None:
    """Negotiate colour and encoding with the terminal. Call once, before anything is printed."""
    global _ENABLED, _ASCII
    _ASCII = not _prepare_encoding()
    _ENABLED = colour and sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    if _ENABLED and os.name == "nt" and not _enable_windows_vt():
        _ENABLED = False
    for name, code in _CODES.items():
        setattr(C, name, code if _ENABLED else "")


def _enable_windows_vt() -> bool:
    """Switch on virtual-terminal processing, so escape codes are rendered and not printed."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        return bool(kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7))
    except Exception:
        return False


def _prepare_encoding() -> bool:
    """True when the output stream can carry the typographic characters used in this module."""
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except Exception:
        pass
    encoding = getattr(sys.stdout, "encoding", "") or "ascii"
    try:
        "—·…→".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def t(text: Any) -> str:
    """Render one value for this terminal."""
    rendered = "" if text is None else str(text)
    return rendered.translate(_ASCII_MAP) if _ASCII else rendered


def raw(text: str) -> None:
    """Print a line that was assembled by the caller, colour codes and all."""
    print(t(text))


# ---------------------------------------------------------------------------
# structure
# ---------------------------------------------------------------------------
def act(number: str, title: str, question: str = "") -> None:
    """A numbered act header. ``question`` states what this act has to prove."""
    print()
    print(f"{C.CYAN}{'=' * WIDTH}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  ACT {t(number)}  |  {t(title).upper()}{C.RESET}")
    if question:
        print(f"{C.GREY}  {t(question)}{C.RESET}")
    print(f"{C.CYAN}{'=' * WIDTH}{C.RESET}")


def section(title: str) -> None:
    print()
    print(f"{C.BOLD}  {t(title)}{C.RESET}")
    print(f"{C.GREY}  {'-' * (WIDTH - 4)}{C.RESET}")


def kv(key: str, value: Any, *, colour: str = "", width: int = 26) -> None:
    print(f"   {C.GREY}{t(key):<{width}}{C.RESET} {colour}{t(value)}{C.RESET}")


def bullet(text: str, *, colour: str = "", indent: int = 3) -> None:
    pad = " " * indent
    wrapped = textwrap.wrap(t(text), width=WIDTH - indent - 3) or [""]
    print(f"{pad}{colour}- {wrapped[0]}{C.RESET}")
    for extra in wrapped[1:]:
        print(f"{pad}  {colour}{extra}{C.RESET}")


def line(text: str = "", *, colour: str = "", indent: int = 3) -> None:
    print(f"{' ' * indent}{colour}{t(text)}{C.RESET}")


def note(text: str) -> None:
    for chunk in textwrap.wrap(t(text), width=WIDTH - 6) or [""]:
        print(f"   {C.GREY}{chunk}{C.RESET}")


def ok(text: str) -> None:
    print(f"   {C.GREEN}[OK]{C.RESET} {t(text)}")


def warn(text: str) -> None:
    print(f"   {C.YELLOW}[!!]{C.RESET} {t(text)}")


def fail(text: str) -> None:
    print(f"   {C.RED}[XX]{C.RESET} {t(text)}")


def blank() -> None:
    print()


def code(text: str, *, limit: int = 0, indent: int = 5) -> int:
    """Print a block verbatim. Returns the number of lines withheld by ``limit``."""
    lines = t(text).splitlines()
    shown = lines if limit <= 0 else lines[:limit]
    for entry in shown:
        colour = ""
        if entry.startswith("+") and not entry.startswith("+++"):
            colour = C.GREEN
        elif entry.startswith("-") and not entry.startswith("---"):
            colour = C.RED
        elif entry.startswith("@@"):
            colour = C.CYAN
        print(f"{' ' * indent}{colour}{entry}{C.RESET}")
    return max(0, len(lines) - len(shown))


def table(headers: Iterable[str], rows: Iterable[Iterable[Any]], *, indent: int = 3) -> None:
    header_list = [t(h) for h in headers]
    row_list = [[t(cell) for cell in row] for row in rows]
    widths = [len(h) for h in header_list]
    for row in row_list:
        for index, cell in enumerate(row):
            if index < len(widths):
                widths[index] = max(widths[index], len(cell))
    pad = " " * indent
    print(pad + C.GREY + "  ".join(h.ljust(widths[i]) for i, h in enumerate(header_list)) + C.RESET)
    print(pad + C.GREY + "  ".join("-" * w for w in widths) + C.RESET)
    for row in row_list:
        print(pad + "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))


def verdict(passed: bool, text: str) -> None:
    badge = f"{C.GREEN}{C.BOLD} PASS {C.RESET}" if passed else f"{C.RED}{C.BOLD} FAIL {C.RESET}"
    print()
    print(f"  {badge}  {t(text)}")


def pause(enabled: bool, prompt: str = "press Enter for the next act") -> None:
    if not enabled:
        return
    try:
        input(f"\n   {C.GREY}({t(prompt)}){C.RESET} ")
    except (EOFError, KeyboardInterrupt) as exc:
        print()
        raise SystemExit(130) from exc


def banner(title: str, subtitle: str = "") -> None:
    print()
    print(f"{C.MAGENTA}{'#' * WIDTH}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}  {t(title)}{C.RESET}")
    if subtitle:
        print(f"{C.MAGENTA}  {t(subtitle)}{C.RESET}")
    print(f"{C.MAGENTA}{'#' * WIDTH}{C.RESET}")
