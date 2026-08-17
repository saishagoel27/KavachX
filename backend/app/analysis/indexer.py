"""Repository indexing with tree-sitter.

Produces a *symbol-level* index — files, functions, classes, imports, call sites — which the
World Model then turns into a graph. The point is that the LLM never receives the repository:
it receives handles into this index and asks targeted questions.

tree-sitter is the primary parser (Python, C, JavaScript/TypeScript grammars are bundled). If
a grammar is unavailable for a language, a conservative regex indexer takes over for that file
and the resulting :class:`FileIndex` records ``indexer="regex"`` so downstream consumers — and
the certificate — know the fidelity of what they are looking at.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.hashing import sha256_text
from app.core.logging import get_logger

logger = get_logger(__name__)

LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".c": "c",
    ".h": "c",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
}

CONFIG_SUFFIXES = frozenset({".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"})


@dataclass(slots=True)
class SymbolRef:
    """A function, method or class definition."""

    name: str
    qualname: str
    kind: str  # function | method | class
    file: str
    start_line: int
    end_line: int
    parameters: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    #: Names called from inside the body, resolved later against the symbol table.
    calls: list[str] = field(default_factory=list)
    docline: str = ""

    @property
    def handle(self) -> str:
        return f"{self.file}:{self.qualname}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "qualname": self.qualname,
            "kind": self.kind,
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "parameters": self.parameters,
            "decorators": self.decorators,
            "calls": sorted(set(self.calls)),
            "docline": self.docline,
            "handle": self.handle,
        }


@dataclass(slots=True)
class FileIndex:
    path: str
    language: str
    lines: int
    sha256: str
    indexer: str
    symbols: list[SymbolRef] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    #: ``(line, text)`` for every line that matched a sink pattern.
    sink_hits: list[tuple[int, str]] = field(default_factory=list)
    has_main_guard: bool = False
    #: Non-empty when the file was deliberately not analysed, naming the reason. The file is still
    #: hashed and counted — it is part of the pinned tree — but contributes no symbols and no sinks.
    skipped_reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "language": self.language,
            "lines": self.lines,
            "sha256": self.sha256,
            "indexer": self.indexer,
            "imports": sorted(set(self.imports)),
            "symbol_count": len(self.symbols),
            "has_main_guard": self.has_main_guard,
            "sink_hits": [{"line": ln, "text": text[:200]} for ln, text in self.sink_hits],
            "skipped_reason": self.skipped_reason,
        }


#: Dangerous-sink patterns. Deliberately syntactic and conservative: a hit is a *candidate*
#: that the discovery channels must then prove reachable and the validator must then prove
#: exploitable. Nothing here is a finding on its own.
SINK_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"subprocess\.(run|Popen|call|check_output|check_call)\s*\(", "process_exec"),
    (r"shell\s*=\s*True", "shell_exec"),
    (r"\bos\.(system|popen|execv?p?e?|spawn\w*)\s*\(", "process_exec"),
    (r"\beval\s*\(", "dynamic_eval"),
    (r"\bexec\s*\(", "dynamic_eval"),
    (r"\b__import__\s*\(", "dynamic_import"),
    (r"pickle\.(load|loads)\s*\(", "deserialisation"),
    (r"yaml\.load\s*\(", "deserialisation"),
    (r"\bopen\s*\(", "file_read_write"),
    (r"\.read_(bytes|text)\s*\(", "file_read_write"),
    (r"\.write_(bytes|text)\s*\(", "file_read_write"),
    (r"Path\s*\([^)]*\)\s*/", "path_join"),
    (r"\bmemcpy\s*\(", "memory_copy"),
    (r"\bstrcpy\s*\(", "memory_copy"),
    (r"\bstrcat\s*\(", "memory_copy"),
    (r"\bsprintf\s*\(", "memory_copy"),
    (r"\bgets\s*\(", "memory_copy"),
    (r"\balloca\s*\(", "memory_alloc"),
    (r"\bmalloc\s*\(", "memory_alloc"),
    (r"\[\s*\w+\s*\]\s*=", "indexed_write"),
    (r"\bcursor\.execute\s*\(", "sql"),
    (r"requests\.(get|post|put|delete)\s*\(", "network"),
    (r"urllib\.request", "network"),
    (r"socket\.socket\s*\(", "network"),
)

COMPILED_SINKS = tuple((re.compile(pattern), label) for pattern, label in SINK_PATTERNS)

#: Names that signal an externally reachable entrypoint.
#:
#: Kept deliberately tight and matched *exactly*, not by prefix. A loose list here is not a
#: harmless heuristic: treating an internal helper like ``parse_header`` as an entrypoint would
#: make it trivially "reachable" and inflate every reachability score that depends on it.
ENTRYPOINT_HINTS = (
    "main",
    "handle",
    "handler",
    "entrypoint",
    "dispatch",
    "serve",
    "app",
    "lambda_handler",
    "llvmfuzzertestoneinput",
)


# ---------------------------------------------------------------------------
@lru_cache(maxsize=8)
def _load_language(language: str) -> Any | None:
    try:
        from tree_sitter import Language

        if language == "python":
            import tree_sitter_python as ts_mod
        elif language == "c":
            import tree_sitter_c as ts_mod
        elif language == "javascript":
            import tree_sitter_javascript as ts_mod
        else:
            return None
        return Language(ts_mod.language())
    except Exception as exc:  # pragma: no cover - grammar availability varies
        logger.warning("indexer.grammar_unavailable", language=language, error=str(exc)[:200])
        return None


def _parser_for(language: str) -> Any | None:
    lang = _load_language(language)
    if lang is None:
        return None
    try:
        from tree_sitter import Parser

        return Parser(lang)
    except Exception:  # pragma: no cover
        return None


# ---------------------------------------------------------------------------
#: Filename shapes that are conventionally build output rather than authored source.
_BUNDLE_NAME_HINTS = (".min.js", ".min.css", ".bundle.js", "-bundle.js", ".pack.js", ".map")

#: Line geometry that identifies minified output regardless of filename. A vendored bundle checked
#: in as ``app/static/loader.js`` looks nothing like a bundle by name, but a single 40,000-character
#: line is not something a human wrote.
_MINIFIED_MAX_LINE = 2_000
_MINIFIED_MEAN_LINE = 400


def _generated_reason(path: Path, text: str) -> str:
    """Name the reason this file is build output, or return "" if it looks authored.

    Minified bundles are worth detecting because of what they do to everything downstream: each
    500-character line trips several sink patterns, so one vendored bundle can contribute dozens of
    "candidate sinks" that are neither reachable nor readable, crowd out the real findings in the
    queue, and burn prompt budget on machine-generated text. They are excluded from *analysis* only —
    still hashed, still part of the pinned tree.
    """
    name = path.name.lower()
    if any(hint in name for hint in _BUNDLE_NAME_HINTS):
        return f"{path.suffix.lstrip('.') or 'file'} build output (filename indicates a bundle)"

    lines = text.splitlines()
    if not lines:
        return ""
    longest = max(len(line) for line in lines)
    if longest > _MINIFIED_MAX_LINE:
        return f"minified: longest line is {longest} characters"
    # A short file with one long-ish line is fine; a whole file of them is not.
    if len(lines) > 20 and (len(text) / len(lines)) > _MINIFIED_MEAN_LINE:
        return f"minified: mean line length is {int(len(text) / len(lines))} characters"
    return ""


def index_file(path: Path, *, root: Path) -> FileIndex:
    rel = path.relative_to(root).as_posix()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return FileIndex(path=rel, language="unknown", lines=0, sha256="", indexer="none")

    language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "")
    file_index = FileIndex(
        path=rel,
        language=language or ("config" if path.suffix.lower() in CONFIG_SUFFIXES else "other"),
        lines=text.count("\n") + 1,
        sha256=sha256_text(text),
        indexer="none",
    )

    generated = _generated_reason(path, text)
    if generated:
        # Return before sink scanning and before parsing: no symbols, no sinks, no call edges.
        # ``indexer`` carries the reason so indexer_summary() reports the skip instead of hiding it.
        file_index.skipped_reason = generated
        file_index.indexer = "skipped"
        return file_index

    file_index.sink_hits = _scan_sinks(text)
    file_index.has_main_guard = '__name__ == "__main__"' in text or "__name__=='__main__'" in text

    if not language:
        return file_index

    parser = _parser_for(language)
    if parser is not None:
        try:
            _index_with_tree_sitter(parser, text, file_index, language)
            file_index.indexer = "tree-sitter"
            return file_index
        except Exception as exc:  # pragma: no cover
            logger.warning("indexer.tree_sitter_failed", path=rel, error=str(exc)[:200])

    _index_with_regex(text, file_index, language)
    file_index.indexer = "regex"
    return file_index


def _scan_sinks(text: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue
        for pattern, _label in COMPILED_SINKS:
            if pattern.search(line):
                hits.append((number, stripped))
                break
    return hits


# ---------------------------------------------------------------------------
def _node_text(source: bytes, node: Any) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _index_with_tree_sitter(parser: Any, text: str, file_index: FileIndex, language: str) -> None:
    source = text.encode("utf-8")
    tree = parser.parse(source)

    def walk(node: Any, scope: list[str]) -> None:
        node_type = node.type

        if language == "python":
            if node_type == "class_definition":
                name = _child_field_text(source, node, "name")
                file_index.symbols.append(
                    _make_symbol(source, node, name, scope, "class", file_index.path)
                )
                for child in node.children:
                    walk(child, [*scope, name])
                return
            if node_type == "function_definition":
                name = _child_field_text(source, node, "name")
                kind = "method" if scope else "function"
                symbol = _make_symbol(source, node, name, scope, kind, file_index.path)
                symbol.parameters = _python_parameters(source, node)
                symbol.calls = _collect_calls(source, node, language)
                symbol.docline = _first_docline(source, node)
                file_index.symbols.append(symbol)
                return
            if node_type in ("import_statement", "import_from_statement"):
                file_index.imports.append(_node_text(source, node).strip()[:200])

        elif language == "c":
            if node_type == "function_definition":
                declarator = node.child_by_field_name("declarator")
                name = _c_function_name(source, declarator) if declarator else ""
                symbol = _make_symbol(source, node, name, scope, "function", file_index.path)
                symbol.calls = _collect_calls(source, node, language)
                file_index.symbols.append(symbol)
                return
            if node_type == "preproc_include":
                file_index.imports.append(_node_text(source, node).strip()[:200])

        elif language == "javascript":
            if node_type in (
                "function_declaration",
                "method_definition",
                "generator_function_declaration",
            ):
                name = _child_field_text(source, node, "name")
                kind = "method" if node_type == "method_definition" else "function"
                symbol = _make_symbol(source, node, name, scope, kind, file_index.path)
                symbol.calls = _collect_calls(source, node, language)
                file_index.symbols.append(symbol)
                return
            if node_type == "class_declaration":
                name = _child_field_text(source, node, "name")
                file_index.symbols.append(
                    _make_symbol(source, node, name, scope, "class", file_index.path)
                )
                for child in node.children:
                    walk(child, [*scope, name])
                return
            if node_type == "import_statement":
                file_index.imports.append(_node_text(source, node).strip()[:200])

        for child in node.children:
            walk(child, scope)

    walk(tree.root_node, [])


def _make_symbol(
    source: bytes, node: Any, name: str, scope: list[str], kind: str, file_path: str
) -> SymbolRef:
    qualname = ".".join([*scope, name]) if name else ".".join(scope) or "<anonymous>"
    return SymbolRef(
        name=name or "<anonymous>",
        qualname=qualname,
        kind=kind,
        file=file_path,
        start_line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
    )


def _child_field_text(source: bytes, node: Any, field_name: str) -> str:
    child = node.child_by_field_name(field_name)
    return _node_text(source, child) if child is not None else ""


def _c_function_name(source: bytes, declarator: Any) -> str:
    current = declarator
    for _ in range(6):
        if current is None:
            return ""
        if current.type == "identifier":
            return _node_text(source, current)
        nested = current.child_by_field_name("declarator")
        if nested is None:
            for child in current.children:
                if child.type == "identifier":
                    return _node_text(source, child)
            return ""
        current = nested
    return ""


def _python_parameters(source: bytes, node: Any) -> list[str]:
    params = node.child_by_field_name("parameters")
    if params is None:
        return []
    out: list[str] = []
    for child in params.children:
        if child.type == "identifier":
            out.append(_node_text(source, child))
        elif child.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
            for grand in child.children:
                if grand.type == "identifier":
                    out.append(_node_text(source, grand))
                    break
    return [p for p in out if p not in ("self", "cls")]


def _collect_calls(source: bytes, node: Any, language: str) -> list[str]:
    calls: list[str] = []
    call_types = {"call", "call_expression"}

    def walk(current: Any) -> None:
        if current.type in call_types:
            function_node = current.child_by_field_name("function")
            if function_node is not None:
                calls.append(_node_text(source, function_node).strip()[:120])
        for child in current.children:
            walk(child)

    walk(node)
    return calls


def _first_docline(source: bytes, node: Any) -> str:
    body = node.child_by_field_name("body")
    if body is None:
        return ""
    for child in body.children:
        if child.type == "expression_statement":
            text = _node_text(source, child).strip().strip("\"'")
            return text.splitlines()[0][:200] if text else ""
        break
    return ""


# ---------------------------------------------------------------------------
_PY_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE)
_PY_CLASS = re.compile(r"^(\s*)class\s+(\w+)", re.MULTILINE)
_C_DEF = re.compile(r"^[\w\s\*]+?\b(\w+)\s*\([^;{]*\)\s*\{", re.MULTILINE)
_JS_DEF = re.compile(r"function\s+(\w+)\s*\(|(\w+)\s*[:=]\s*(?:async\s*)?\(", re.MULTILINE)


def _index_with_regex(text: str, file_index: FileIndex, language: str) -> None:
    """Conservative fallback. Records fewer symbols rather than wrong ones."""
    lines = text.splitlines()

    def line_of(offset: int) -> int:
        return text.count("\n", 0, offset) + 1

    if language == "python":
        for match in _PY_CLASS.finditer(text):
            file_index.symbols.append(
                SymbolRef(
                    name=match.group(2),
                    qualname=match.group(2),
                    kind="class",
                    file=file_index.path,
                    start_line=line_of(match.start()),
                    end_line=line_of(match.start()),
                )
            )
        for match in _PY_DEF.finditer(text):
            start = line_of(match.start())
            params = [
                p.split(":")[0].split("=")[0].strip()
                for p in match.group(3).split(",")
                if p.strip() and p.strip() not in ("self", "cls")
            ]
            file_index.symbols.append(
                SymbolRef(
                    name=match.group(2),
                    qualname=match.group(2),
                    kind="method" if match.group(1) else "function",
                    file=file_index.path,
                    start_line=start,
                    end_line=min(len(lines), start + 40),
                    parameters=params,
                )
            )
        file_index.imports = [
            ln.strip() for ln in lines if ln.strip().startswith(("import ", "from "))
        ][:100]
    elif language == "c":
        for match in _C_DEF.finditer(text):
            start = line_of(match.start())
            file_index.symbols.append(
                SymbolRef(
                    name=match.group(1),
                    qualname=match.group(1),
                    kind="function",
                    file=file_index.path,
                    start_line=start,
                    end_line=min(len(lines), start + 60),
                )
            )
        file_index.imports = [ln.strip() for ln in lines if ln.strip().startswith("#include")]
    else:
        for match in _JS_DEF.finditer(text):
            name = match.group(1) or match.group(2) or ""
            if not name:
                continue
            start = line_of(match.start())
            file_index.symbols.append(
                SymbolRef(
                    name=name,
                    qualname=name,
                    kind="function",
                    file=file_index.path,
                    start_line=start,
                    end_line=min(len(lines), start + 40),
                )
            )


# ---------------------------------------------------------------------------
def index_tree(root: Path, *, max_files: int = 4000) -> list[FileIndex]:
    from app.sandbox.workspace import list_source_files

    out: list[FileIndex] = []
    for path in list_source_files(root)[:max_files]:
        suffix = path.suffix.lower()
        if suffix not in LANGUAGE_BY_SUFFIX and suffix not in CONFIG_SUFFIXES:
            if suffix not in (".md", ".txt", ".sh", ".mk", "") and path.name != "Makefile":
                continue
        out.append(index_file(path, root=root))
    return out


def indexer_summary(indexes: list[FileIndex]) -> dict[str, Any]:
    by_indexer: dict[str, int] = {}
    by_language: dict[str, int] = {}
    skipped: list[dict[str, str]] = []
    for entry in indexes:
        by_indexer[entry.indexer] = by_indexer.get(entry.indexer, 0) + 1
        by_language[entry.language] = by_language.get(entry.language, 0) + 1
        if entry.skipped_reason:
            skipped.append({"path": entry.path, "reason": entry.skipped_reason})
    return {
        "files": len(indexes),
        "symbols": sum(len(e.symbols) for e in indexes),
        "by_indexer": by_indexer,
        "by_language": by_language,
        #: Named, not merely counted: "3 files were not analysed" invites the question "which?", and
        #: an unanalysed file is a hole in coverage that a reader is entitled to see.
        "skipped_files": skipped[:50],
        "skipped_count": len(skipped),
        "grammars_available": {
            language: _load_language(language) is not None
            for language in ("python", "c", "javascript")
        },
    }
