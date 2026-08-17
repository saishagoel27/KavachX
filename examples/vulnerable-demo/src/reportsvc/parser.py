"""Header parsing for incoming report requests."""

from __future__ import annotations

# The wire format reserves a fixed table of header slots. Real deployments never send more
# than a handful, so the table was sized generously and left at that.
MAX_HEADER_SLOTS = 8
MAX_KEY_LENGTH = 32


class HeaderError(ValueError):
    """Raised for a malformed header block."""


def _blank_slots() -> list[tuple[str, str] | None]:
    return [None] * MAX_HEADER_SLOTS


def parse_header(raw: str) -> dict[str, str]:
    """Parse a ``KEY:VALUE`` header block into a mapping.

    Header lines are written into a fixed slot table in arrival order.
    """
    if not isinstance(raw, str):
        raise HeaderError("header block must be a string")

    slots = _blank_slots()
    index = 0

    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            raise HeaderError(f"malformed header line: {line[:40]!r}")
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not key:
            raise HeaderError("empty header key")
        if len(key) > MAX_KEY_LENGTH:
            raise HeaderError("header key too long")

        # SEEDED VULNERABILITY (CWE-1284): the slot index is never checked against
        # MAX_HEADER_SLOTS before the write, so a caller controls an out-of-range index.
        slots[index] = (key, value)
        index += 1

    out: dict[str, str] = {}
    for slot in slots:
        if slot is not None:
            out[slot[0]] = slot[1]
    return out


def header_count(raw: str) -> int:
    """Number of non-empty header lines in the block."""
    return len([ln for ln in raw.split("\n") if ln.strip()])
