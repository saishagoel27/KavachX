"""Deterministic source-transformation recipes for the mock proposer.

These are what the ``mock`` provider uses instead of a model when producing a patch. They are
*scripted proposals*: real transformations of the real file contents handed to the proposer,
so the resulting unified diff, the sandbox application, and every gauntlet verdict are
genuine. What they are not is intelligent — a recipe only fires when its anchor is present,
and returns ``None`` otherwise so the patch task fails honestly rather than emitting
plausible-looking garbage.

The first-iteration recipes are deliberately *naive* in the way a rushed human fix is naive
(blacklist the one character you saw in the bug report). The Refutation Gauntlet then has to
actually find the bypass by executing mutations. That refutation is not staged; if the
mutation engine failed to find a bypass, the patch would pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True)
class RecipeResult:
    new_content: str
    reason: str
    expected_effect: str
    risk: str
    invariants_preserved: list[str]


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _insert_before(text: str, anchor: str, block: str) -> str | None:
    """Insert ``block`` immediately before the first line matching ``anchor`` exactly."""
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.rstrip("\r\n") == anchor:
            pad = _indent_of(anchor)
            rendered = "".join(
                f"{pad}{ln}\n" if ln else "\n" for ln in block.strip("\n").split("\n")
            )
            return "".join(lines[:index]) + rendered + "".join(lines[index:])
    return None


def _replace_line(text: str, anchor: str, block: str) -> str | None:
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.rstrip("\r\n") == anchor:
            pad = _indent_of(anchor)
            rendered = "".join(
                f"{pad}{ln}\n" if ln else "\n" for ln in block.strip("\n").split("\n")
            )
            return "".join(lines[:index]) + rendered + "".join(lines[index + 1 :])
    return None


def _find_line(text: str, predicate: str) -> str | None:
    for line in text.splitlines():
        if predicate in line:
            return line.rstrip("\r\n")
    return None


# ---------------------------------------------------------------------------
# CWE-78 — OS command injection
# ---------------------------------------------------------------------------
def shell_injection_naive_filter(content: str, blocked_tokens: list[str]) -> RecipeResult | None:
    """Iteration 1: reject the separator observed in the proof of vulnerability.

    This is the classic incomplete fix. It closes the exact reported payload and nothing else.
    """
    anchor = _find_line(content, "if fmt not in SUPPORTED_FORMATS:")
    if anchor is None:
        return None

    tokens = [t for t in blocked_tokens if t] or [";"]
    primary = tokens[0]
    literal = repr(primary)

    guard = f"""
if {literal} in report_name:
    raise ExportError("illegal character in report name")
"""
    patched = _insert_before(content, anchor, guard)
    if patched is None:
        return None

    return RecipeResult(
        new_content=patched,
        reason=(
            f"The proof of vulnerability injected a shell command using the {primary!r} "
            f"separator. Reject {primary!r} in report_name before the archiver command is "
            "built, so the reported payload can no longer reach the shell."
        ),
        expected_effect=(
            f"export_report raises ExportError for any report_name containing {primary!r}. "
            "Benign report names are unaffected."
        ),
        risk="medium",
        invariants_preserved=["export of benign names still succeeds"],
    )


def shell_injection_remove_shell(content: str) -> RecipeResult | None:
    """Iteration 2+: eliminate the shell entirely and constrain the name to an allowlist.

    Addresses the root cause rather than the observed payload: with no shell, there is no
    metacharacter to escape, and the allowlist bounds the value independently.
    """
    if "shell=True" not in content:
        return None

    patched = content

    # 1. import re (idempotent, keeps stdlib imports alphabetical)
    if not re.search(r"^import re$", patched, flags=re.MULTILINE):
        patched = patched.replace(
            "import os\nimport subprocess", "import os\nimport re\nimport subprocess", 1
        )
        if "import re" not in patched:
            return None

    # 2. Allowlist constant next to the other module constants.
    const_anchor = _find_line(patched, 'SUPPORTED_FORMATS = ("txt", "csv", "json")')
    if const_anchor is None:
        return None
    patched_with_const = _insert_before(
        patched,
        const_anchor,
        "# Report names are constrained to an explicit allowlist. Anything outside it is\n"
        "# rejected before the archiver is invoked.\n"
        'SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")\n',
    )
    if patched_with_const is None:
        return None
    patched = patched_with_const

    # 3. Build an argument vector instead of a shell string.
    old_cmd = re.search(
        r"def _archiver_command\(report_name: str, fmt: str\) -> str:.*?"
        r"(?=\n\ndef |\n\nclass |\Z)",
        patched,
        flags=re.DOTALL,
    )
    if old_cmd is None:
        return None
    new_cmd = (
        "def _archiver_command(report_name: str, fmt: str) -> list[str]:\n"
        '    """Build the archiver argument vector for a report.\n'
        "\n"
        "    Returns a list, not a string: there is no shell in the execution path, so no\n"
        "    part of report_name can be interpreted as a command separator.\n"
        '    """\n'
        '    target = EXPORT_ROOT / f"{report_name}.{fmt}"\n'
        "    return [\n"
        "        sys.executable,\n"
        '        "-m",\n'
        '        "reportsvc.archiver",\n'
        '        "--name",\n'
        "        report_name,\n"
        '        "--out",\n'
        "        str(target),\n"
        "    ]"
    )
    patched = patched[: old_cmd.start()] + new_cmd + patched[old_cmd.end() :]

    # 4. Validate the name, then run without a shell.
    fmt_anchor = _find_line(patched, "if fmt not in SUPPORTED_FORMATS:")
    if fmt_anchor is None:
        return None
    validated = _insert_before(
        patched,
        fmt_anchor,
        "if not SAFE_NAME.match(report_name):\n"
        '    raise ExportError("report name must match ^[A-Za-z0-9._-]{1,64}$")\n',
    )
    if validated is None:
        return None
    patched = validated

    old_call = re.search(
        r"[ \t]*completed = subprocess\.run\(.*?\n(?:.*?\n)*?[ \t]*\)\n",
        patched,
    )
    if old_call is None:
        return None
    new_call = (
        "    completed = subprocess.run(\n"
        "        command,\n"
        "        shell=False,\n"
        "        capture_output=True,\n"
        "        text=True,\n"
        "        timeout=15,\n"
        "    )\n"
    )
    patched = patched[: old_call.start()] + new_call + patched[old_call.end() :]

    # 5. The response still reports the command; join the vector for display only.
    patched = patched.replace(
        '        "command": command,',
        '        "command": " ".join(command),',
        1,
    )
    # 6. Drop the now-obsolete noqa and seeded-vulnerability comments.
    patched = re.sub(
        r"[ \t]*# SEEDED VULNERABILITY \(CWE-78\)[^\n]*\n(?:[ \t]*#[^\n]*\n)*",
        "",
        patched,
    )

    if "shell=True" in patched:
        return None

    return RecipeResult(
        new_content=patched,
        reason=(
            "Root cause: report_name is interpolated into a string that is executed by a "
            "shell. Character filtering only ever removes the separators someone thought "
            "of. Remove the shell from the execution path and bound the value with an "
            "explicit allowlist, so no separator has any meaning."
        ),
        expected_effect=(
            "The archiver is invoked with an argument vector and shell=False. report_name "
            "must match ^[A-Za-z0-9._-]{1,64}$. No shell metacharacter can influence the "
            "command regardless of separator."
        ),
        risk="low",
        invariants_preserved=[
            "benign report names still export successfully",
            "archiver output shape unchanged",
            "no shell invocation from exporter",
        ],
    )


# ---------------------------------------------------------------------------
# CWE-1284 — unchecked length boundary
# ---------------------------------------------------------------------------
def bound_slot_index(content: str) -> RecipeResult | None:
    anchor = _find_line(content, "slots[index] = (key, value)")
    if anchor is None:
        return None
    guard = (
        "if index >= MAX_HEADER_SLOTS:\n"
        "    raise HeaderError(\n"
        '        f"too many header lines: limit is {MAX_HEADER_SLOTS}"\n'
        "    )\n"
    )
    patched = _insert_before(content, anchor, guard)
    if patched is None:
        return None
    patched = re.sub(
        r"[ \t]*# SEEDED VULNERABILITY \(CWE-1284\)[^\n]*\n(?:[ \t]*#[^\n]*\n)*",
        "",
        patched,
    )
    return RecipeResult(
        new_content=patched,
        reason=(
            "Root cause: the slot index is incremented per header line and used as a write "
            "index without ever being compared against MAX_HEADER_SLOTS. Check the bound "
            "before the write and reject the block with the module's own error type."
        ),
        expected_effect=(
            "A header block with more than MAX_HEADER_SLOTS lines raises HeaderError, which "
            "the entrypoint already converts into a structured ok:false response, instead of "
            "escaping as IndexError."
        ),
        risk="low",
        invariants_preserved=[
            "blocks at or under the slot limit parse identically",
            "malformed lines still raise HeaderError",
        ],
    )


# ---------------------------------------------------------------------------
# CWE-22 — path traversal
# ---------------------------------------------------------------------------
def confine_asset_path(content: str) -> RecipeResult | None:
    anchor = _find_line(content, "candidate = ASSET_ROOT / relative_path")
    if anchor is None:
        return None
    replacement = (
        "root = ASSET_ROOT.resolve()\n"
        "candidate = (root / relative_path).resolve()\n"
        "if candidate != root and root not in candidate.parents:\n"
        '    raise AssetError(f"asset path escapes the asset root: {relative_path}")\n'
    )
    patched = _replace_line(content, anchor, replacement)
    if patched is None:
        return None
    patched = re.sub(
        r"[ \t]*# SEEDED VULNERABILITY \(CWE-22\)[^\n]*\n(?:[ \t]*#[^\n]*\n)*",
        "",
        patched,
    )
    return RecipeResult(
        new_content=patched,
        reason=(
            "Root cause: the caller-supplied path is joined to ASSET_ROOT and used directly, "
            "so ../ sequences resolve outside the asset directory. Resolve both paths and "
            "require the target to be contained by the root."
        ),
        expected_effect=(
            "read_asset raises AssetError for any path that resolves outside ASSET_ROOT. "
            "Assets inside the root are read exactly as before."
        ),
        risk="low",
        invariants_preserved=[
            "assets inside the root read identically",
            "missing assets still raise AssetError",
        ],
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
def select_recipe(
    *,
    cwe: str,
    content: str,
    iteration: int,
    constraints: list[str],
    blocked_tokens: list[str],
) -> RecipeResult | None:
    """Pick a transformation for ``cwe``.

    ``constraints`` are the accumulated refutations from earlier iterations. A constraint
    mentioning a bypass forces the structural fix rather than another filter.
    """
    normalised = (cwe or "").upper().replace("_", "-")
    joined = " ".join(constraints).lower()
    escalate = iteration > 1 or "bypass" in joined or "shell" in joined

    if "78" in normalised:
        if escalate:
            return shell_injection_remove_shell(content)
        return shell_injection_naive_filter(content, blocked_tokens)
    if "1284" in normalised or "787" in normalised or "125" in normalised:
        return bound_slot_index(content)
    if "22" in normalised:
        return confine_asset_path(content)
    return None
