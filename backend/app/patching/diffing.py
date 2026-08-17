"""Unified diff generation and application.

KavachX generates the diff itself from ``(old_content, new_content)`` rather than accepting a
model-authored diff. That removes a whole failure class: a malformed or subtly-wrong hunk
cannot corrupt a workspace, and the diff shown in the UI is by construction exactly the change
that was applied.

The applier is included because ``patch``/``git apply`` are not reliably present on Windows and
we need to apply a diff to a workspace copy without shelling out.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any

HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(slots=True)
class DiffStats:
    files: list[str] = field(default_factory=list)
    lines_added: int = 0
    lines_removed: int = 0
    hunks: int = 0

    @property
    def total_changed(self) -> int:
        return self.lines_added + self.lines_removed

    def as_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            "hunks": self.hunks,
            "total_changed": self.total_changed,
        }


def make_unified_diff(*, path: str, old: str, new: str, context: int = 3) -> str:
    """Standard unified diff with ``a/``-``b/`` prefixes, so it applies with git too."""
    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        n=context,
    )
    return "".join(diff)


def combine_diffs(diffs: list[str]) -> str:
    return "".join(d if d.endswith("\n") else d + "\n" for d in diffs if d)


def diff_stats(diff: str) -> DiffStats:
    stats = DiffStats()
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path and path != "/dev/null" and path not in stats.files:
                stats.files.append(path)
        elif line.startswith("@@"):
            stats.hunks += 1
        elif line.startswith("+") and not line.startswith("+++"):
            stats.lines_added += 1
        elif line.startswith("-") and not line.startswith("---"):
            stats.lines_removed += 1
    return stats


def diff_touched_files(diff: str) -> list[str]:
    return diff_stats(diff).files


class DiffApplyError(ValueError):
    """The diff does not apply cleanly to the given content."""


def apply_unified_diff(original: str, diff: str) -> str:
    """Apply a single-file unified diff.

    Strict by design: context lines must match exactly. A fuzzy applier would silently place a
    security fix in the wrong location, which is worse than failing.
    """
    original_lines = original.splitlines(keepends=True)
    result: list[str] = []
    cursor = 0  # 0-based index into original_lines
    lines = diff.splitlines()
    index = 0

    while index < len(lines):
        line = lines[index]
        if line.startswith(("--- ", "+++ ", "diff ", "index ", "new file", "deleted file")):
            index += 1
            continue

        match = HUNK_HEADER.match(line)
        if not match:
            index += 1
            continue

        old_start = int(match.group(1))
        target = max(0, old_start - 1)
        if target < cursor:
            raise DiffApplyError(
                f"hunk at line {old_start} overlaps an earlier hunk; diff is not ordered"
            )
        result.extend(original_lines[cursor:target])
        cursor = target
        index += 1

        while index < len(lines):
            body = lines[index]
            if HUNK_HEADER.match(body) or body.startswith(("--- ", "+++ ", "diff ")):
                break
            if body.startswith("\\"):  # "\ No newline at end of file"
                index += 1
                continue

            marker, content = (body[:1], body[1:]) if body else (" ", "")
            if marker == " ":
                if cursor >= len(original_lines):
                    raise DiffApplyError("context line past end of file")
                existing = original_lines[cursor].rstrip("\r\n")
                if existing != content.rstrip("\r\n"):
                    raise DiffApplyError(
                        f"context mismatch at line {cursor + 1}: "
                        f"expected {content!r}, found {existing!r}"
                    )
                result.append(original_lines[cursor])
                cursor += 1
            elif marker == "-":
                if cursor >= len(original_lines):
                    raise DiffApplyError("removal line past end of file")
                existing = original_lines[cursor].rstrip("\r\n")
                if existing != content.rstrip("\r\n"):
                    raise DiffApplyError(
                        f"removal mismatch at line {cursor + 1}: "
                        f"expected {content!r}, found {existing!r}"
                    )
                cursor += 1
            elif marker == "+":
                result.append(content + "\n")
            else:
                raise DiffApplyError(f"unrecognised diff line: {body[:60]!r}")
            index += 1

    result.extend(original_lines[cursor:])
    return "".join(result)


def split_multifile_diff(diff: str) -> dict[str, str]:
    """Split a combined diff into ``{path: single-file diff}``."""
    out: dict[str, str] = {}
    current_path = ""
    buffer: list[str] = []

    def flush() -> None:
        if current_path and buffer:
            out[current_path] = "\n".join(buffer) + "\n"

    for line in diff.splitlines():
        if line.startswith("--- "):
            flush()
            buffer = [line]
            current_path = ""
            continue
        if line.startswith("+++ "):
            path = line[4:].strip()
            current_path = path[2:] if path.startswith("b/") else path
        buffer.append(line)
    flush()
    return out


def summarise_change(old: str, new: str) -> dict[str, Any]:
    """Human-readable shape of a change, used in patch metadata and CHANGES.md."""
    old_lines = old.splitlines()
    new_lines = new.splitlines()
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
    regions: list[dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        regions.append(
            {
                "kind": tag,
                "old_range": [i1 + 1, i2],
                "new_range": [j1 + 1, j2],
                "removed": old_lines[i1:i2][:20],
                "added": new_lines[j1:j2][:20],
            }
        )
    return {
        "regions": regions,
        "similarity": round(matcher.ratio(), 4),
        "old_line_count": len(old_lines),
        "new_line_count": len(new_lines),
    }
