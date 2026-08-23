"""Parse a pasted ``.env`` blob into a key/value map.

Used by the run-configuration flow so an operator can paste a whole ``.env`` (the way Vercel and
Render let you) instead of adding variables one at a time. Deliberately small and permissive about
the common shapes, strict about never executing anything.
"""

from __future__ import annotations

import re

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def parse_dotenv(text: str, *, limit: int = 500) -> dict[str, str]:
    """Turn ``KEY=VALUE`` lines into a dict.

    * ``export KEY=value`` is accepted (the ``export`` is dropped).
    * Values may be single- or double-quoted; the quotes are stripped and, for double quotes,
      ``\\n``/``\\t`` escapes are expanded.
    * An unquoted trailing ``# comment`` is removed; a ``#`` inside quotes is kept.
    * Blank lines and full-line comments are ignored. Later keys win over earlier duplicates.
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()

        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            quote = value[0]
            value = value[1:-1]
            if quote == '"':
                value = value.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')
        else:
            # Strip an unquoted inline comment (`FOO=bar  # note`).
            hash_at = value.find(" #")
            if hash_at != -1:
                value = value[:hash_at].rstrip()

        out[key] = value
        if len(out) >= limit:
            break
    return out
