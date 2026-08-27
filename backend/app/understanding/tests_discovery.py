"""Test discovery — part of indexing, not an afterthought.

The spec's requirement is that the indexer knows what tests exist and what they cover, so the
system can answer "what already covers this function?" and, more importantly, "which
security-sensitive paths are covered by nothing?". That second question is what turns a coverage
gap into a prioritised target for test synthesis.

Detection is convention-based and multi-framework: pytest, unittest, Jest, Vitest, Mocha, Go's
``testing``, JUnit, cargo test, RSpec, PHPUnit. Nothing here assumes Python.

Mapping tests to the code they exercise is done **statically and conservatively**. A test is
linked to a symbol when it names it — an import of the module plus a reference to the symbol name.
That under-approximates (a test reaching a function through three layers of indirection is not
linked) and the edge is labelled so nobody mistakes it for measured coverage. Real coverage comes
from executing the suite under instrumentation, which :mod:`app.testing.coverage` does; this is the
static map that tells the synthesiser where to look first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.indexing.model import CodeEdge, CodeGraph, CodeNode, EdgeKind, NodeKind, Provider

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class TestFramework:
    id: str
    label: str
    language: str
    #: Path globs that identify a test file.
    path_patterns: tuple[str, ...]
    #: Content markers that confirm the framework, so a file merely *named* ``test_x.py`` in a
    #: repository using unittest is not attributed to pytest.
    markers: tuple[str, ...]
    #: Regex capturing individual test case names.
    case_pattern: str
    #: The command that runs the suite, offered to the harness generator.
    command: tuple[str, ...] = ()


FRAMEWORKS: tuple[TestFramework, ...] = (
    TestFramework(
        "pytest",
        "pytest",
        "python",
        ("test_*.py", "*_test.py", "tests/*.py", "tests/**/*.py"),
        ("import pytest", "from pytest", "@pytest.", "def test_"),
        r"^\s*(?:async\s+)?def\s+(test_\w+)",
        ("python", "-m", "pytest", "-q"),
    ),
    TestFramework(
        "unittest",
        "unittest",
        "python",
        ("test_*.py", "*_test.py", "tests/*.py", "tests/**/*.py"),
        ("import unittest", "from unittest", "unittest.TestCase"),
        r"^\s*def\s+(test\w*)",
        ("python", "-m", "unittest", "discover"),
    ),
    TestFramework(
        "hypothesis",
        "Hypothesis (property-based)",
        "python",
        ("test_*.py", "*_test.py", "tests/**/*.py"),
        ("from hypothesis", "import hypothesis", "@given("),
        r"^\s*(?:async\s+)?def\s+(test_\w+)",
        ("python", "-m", "pytest", "-q"),
    ),
    TestFramework(
        "vitest",
        "Vitest",
        "javascript",
        ("*.test.ts", "*.test.js", "*.spec.ts", "*.spec.js", "**/__tests__/**"),
        ("from 'vitest'", 'from "vitest"', "vitest"),
        r"""(?:it|test)\s*\(\s*['"`]([^'"`]{1,120})""",
        ("npx", "vitest", "run"),
    ),
    TestFramework(
        "jest",
        "Jest",
        "javascript",
        ("*.test.ts", "*.test.js", "*.spec.ts", "*.spec.js", "**/__tests__/**"),
        ("@jest/globals", "jest.fn", "describe(", "jest.config"),
        r"""(?:it|test)\s*\(\s*['"`]([^'"`]{1,120})""",
        ("npx", "jest"),
    ),
    TestFramework(
        "mocha",
        "Mocha",
        "javascript",
        ("test/*.js", "test/*.ts", "*.spec.js"),
        ("require('mocha')", "from 'mocha'", "describe("),
        r"""(?:it|test)\s*\(\s*['"`]([^'"`]{1,120})""",
        ("npx", "mocha"),
    ),
    TestFramework(
        "go-test",
        "Go testing",
        "go",
        ("*_test.go",),
        ("testing.T", "testing.F", '"testing"'),
        r"^\s*func\s+(Test\w+|Fuzz\w+)\s*\(",
        ("go", "test", "./..."),
    ),
    TestFramework(
        "junit",
        "JUnit",
        "java",
        ("*Test.java", "*Tests.java", "src/test/**/*.java"),
        ("org.junit", "@Test"),
        r"^\s*(?:public\s+)?void\s+(\w+)\s*\(",
        ("mvn", "test"),
    ),
    TestFramework(
        "cargo-test",
        "cargo test",
        "rust",
        ("tests/*.rs", "**/tests/*.rs"),
        ("#[test]", "#[cfg(test)]"),
        r"^\s*fn\s+(\w+)\s*\(",
        ("cargo", "test"),
    ),
    TestFramework(
        "rspec",
        "RSpec",
        "ruby",
        ("spec/**/*_spec.rb",),
        ("RSpec.describe", "require 'rspec'"),
        r"""(?:it|specify)\s+['"]([^'"]{1,120})""",
        ("bundle", "exec", "rspec"),
    ),
    TestFramework(
        "phpunit",
        "PHPUnit",
        "php",
        ("tests/*Test.php", "**/*Test.php"),
        ("PHPUnit\\Framework\\TestCase", "extends TestCase"),
        r"^\s*public\s+function\s+(test\w+)\s*\(",
        ("./vendor/bin/phpunit",),
    ),
)

#: Directory names that mark a test tree even when filenames do not.
_TEST_DIRS = frozenset({"test", "tests", "spec", "specs", "__tests__", "testing", "e2e"})

#: Cap on bytes read per candidate file. A test file large enough to exceed this is not something
#: a name-reference scan will usefully understand anyway.
_MAX_READ_BYTES = 400_000


@dataclass
class DiscoveredTest:
    path: str
    framework: str
    language: str
    cases: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    #: Symbols this test plausibly exercises, by static name reference.
    covers: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "framework": self.framework,
            "language": self.language,
            "cases": self.cases[:100],
            "case_count": len(self.cases),
            "command": self.command,
            "covers": self.covers[:80],
        }


# ---------------------------------------------------------------------------
def _looks_like_test(rel: str) -> bool:
    parts = rel.split("/")
    if any(part.lower() in _TEST_DIRS for part in parts[:-1]):
        return True
    name = parts[-1].lower()
    return (
        name.startswith("test_")
        or name.startswith("test.")
        or "_test." in name
        or ".test." in name
        or ".spec." in name
        or name.endswith("_spec.rb")
        or name.endswith("test.java")
        or name.endswith("tests.java")
        or name.endswith("test.php")
    )


def _match_framework(rel: str, text: str) -> TestFramework | None:
    """Pick the framework whose content markers actually appear.

    Content over filename: a repository using unittest names its files ``test_x.py`` too, and
    attributing them to pytest would put the wrong runner command in front of the harness
    generator.
    """
    best: TestFramework | None = None
    best_score = 0
    for framework in FRAMEWORKS:
        score = sum(1 for marker in framework.markers if marker in text)
        if score > best_score:
            best, best_score = framework, score
    if best is not None:
        return best
    # No marker matched. Fall back on path shape so the file is still recorded as a test.
    suffix = Path(rel).suffix.lower()
    for framework in FRAMEWORKS:
        if suffix == ".py" and framework.id == "pytest":
            return framework
        if suffix in (".js", ".ts", ".tsx", ".jsx") and framework.id == "jest":
            return framework
        if suffix == ".go" and framework.id == "go-test":
            return framework
        if suffix == ".java" and framework.id == "junit":
            return framework
        if suffix == ".rs" and framework.id == "cargo-test":
            return framework
        if suffix == ".rb" and framework.id == "rspec":
            return framework
        if suffix == ".php" and framework.id == "phpunit":
            return framework
    return None


def discover(root: Path, graph: CodeGraph | None = None) -> list[DiscoveredTest]:
    """Find test files, their cases, and the symbols they plausibly exercise."""
    from app.sandbox.workspace import list_source_files

    # Names of every callable in the graph, so a test's references can be matched against real
    # symbols rather than arbitrary identifiers.
    by_name: dict[str, list[str]] = {}
    if graph is not None:
        for node in graph.callables():
            if node.name:
                by_name.setdefault(node.name, []).append(node.uid)

    found: list[DiscoveredTest] = []
    for path in list_source_files(root):
        rel = path.relative_to(root).as_posix()
        if not _looks_like_test(rel):
            continue
        try:
            if path.stat().st_size > _MAX_READ_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        framework = _match_framework(rel, text)
        if framework is None:
            continue

        cases = sorted(
            set(re.findall(framework.case_pattern, text, re.MULTILINE))
        )
        covers: list[str] = []
        if by_name:
            # A symbol is "covered" only if its name is referenced as an identifier. Requiring a
            # word boundary stops `parse` from matching `parser` and inflating the map.
            for name, uids in by_name.items():
                if len(name) < 3:
                    continue
                if re.search(rf"\b{re.escape(name)}\b", text):
                    covers.extend(uids)

        found.append(
            DiscoveredTest(
                path=rel,
                framework=framework.id,
                language=framework.language,
                cases=cases,
                command=list(framework.command),
                covers=sorted(set(covers)),
            )
        )

    logger.info(
        "understanding.tests_discovered",
        files=len(found),
        cases=sum(len(t.cases) for t in found),
        frameworks=sorted({t.framework for t in found}),
    )
    return found


def attach(graph: CodeGraph, root: Path) -> int:
    """Discover tests and write them into the graph as TEST nodes with TESTED_BY edges.

    Returns the number of test files found. Called from the indexing service so that tests are
    part of the index — which is what makes ``tests_discovered`` a real index counter and lets the
    coverage-gap question be answered from the graph alone.
    """
    tests = discover(root, graph)
    for test in tests:
        test_uid = f"test:{test.path}"
        graph.add_node(
            CodeNode(
                uid=test_uid,
                kind=NodeKind.TEST.value,
                name=test.path.rsplit("/", 1)[-1],
                qualname=test.path,
                file=test.path,
                language=test.language,
                provenance={Provider.KAVACHX.value},
                attrs={
                    "framework": test.framework,
                    "cases": test.cases[:100],
                    "case_count": len(test.cases),
                    "command": test.command,
                },
            )
        )
        # The test file itself is also a source file in the graph; link the two so a query can go
        # from a file to the tests that live in it.
        if graph.has(test.path):
            graph.add_edge(
                CodeEdge(
                    src=test.path,
                    dst=test_uid,
                    kind=EdgeKind.CONTAINS.value,
                    provenance={Provider.KAVACHX.value},
                    confidence=1.0,
                )
            )
        for uid in test.covers:
            graph.add_edge(
                CodeEdge(
                    src=uid,
                    dst=test_uid,
                    kind=EdgeKind.TESTED_BY.value,
                    provenance={Provider.KAVACHX.value},
                    # Static name reference, not measured execution. Deliberately well below 1.0
                    # and never marked resolved, so this can never read as coverage evidence.
                    confidence=0.4,
                    attrs={"basis": "static name reference"},
                )
            )
    return len(tests)


def tests_for(graph: CodeGraph, uid: str) -> list[str]:
    """Test files that plausibly exercise ``uid``."""
    return sorted({e.dst for e in graph.out_edges(uid, EdgeKind.TESTED_BY.value)})


def untested_callables(graph: CodeGraph) -> list[str]:
    """Callables with no test linked. The starting point for coverage-gap prioritisation."""
    return sorted(
        node.uid
        for node in graph.callables()
        if not graph.out_edges(node.uid, EdgeKind.TESTED_BY.value)
    )
