"""The security taxonomy: what counts as a source, a sink, a sanitizer or a control.

This is a **registry, not a hardcoded list**. The rules below are defaults that ship with KavachX;
:func:`load_taxonomy` merges an operator-supplied JSON file over them, so a deployment can add a
framework's request object, an in-house sanitiser or a proprietary sink class without touching
Python. That extensibility is a requirement, not a nicety: a taxonomy that only knows Flask and
``subprocess`` will silently report a clean result on a codebase built from anything else, and
"clean" is the most expensive thing this system can get wrong.

Four rule families, deliberately kept separate because they answer different questions:

* **Sources** — where data an attacker can influence enters the program.
* **Sinks** — operations where attacker-influenced data becomes dangerous.
* **Sanitizers / validators** — operations that constrain a value. Their presence *on a path* is
  what distinguishes a reachable sink from an exploitable one, and their presence is recorded as
  evidence rather than treated as proof: :mod:`app.security_model.flows` marks a flow
  ``sanitized`` but never marks it safe, because whether the sanitiser was actually *executed* on
  the exploit path is a runtime question the validator answers.
* **Controls** — authentication and authorisation decision points, which bound who can reach an
  entrypoint at all.

Nothing here concludes anything. Every match is a *candidate fact* about the code; reachability is
computed over the code graph, and exploitability is decided by execution in the sandbox.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


class _Str(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


class SecurityCategory(_Str):
    """The role a code location plays in the security model."""

    SOURCE = "SOURCE"
    SINK = "SINK"
    SANITIZER = "SANITIZER"
    VALIDATOR = "VALIDATOR"
    AUTHENTICATION_CHECK = "AUTHENTICATION_CHECK"
    AUTHORIZATION_CHECK = "AUTHORIZATION_CHECK"
    TRUST_BOUNDARY = "TRUST_BOUNDARY"
    EXTERNAL_INPUT = "EXTERNAL_INPUT"
    SENSITIVE_DATA = "SENSITIVE_DATA"
    DANGEROUS_OPERATION = "DANGEROUS_OPERATION"


class SourceKind(_Str):
    """Where attacker-influenced data can come from. Extensible via the taxonomy file."""

    HTTP_PARAM = "http_param"
    HTTP_BODY = "http_body"
    HTTP_HEADER = "http_header"
    HTTP_COOKIE = "http_cookie"
    HTTP_PATH = "http_path"
    UPLOADED_FILE = "uploaded_file"
    ENV_VAR = "env_var"
    CLI_ARG = "cli_arg"
    STDIN = "stdin"
    FILE_READ = "file_read"
    DB_RECORD = "db_record"
    MESSAGE_QUEUE = "message_queue"
    IPC = "ipc"
    USER_CONFIG = "user_config"
    NETWORK_RESPONSE = "network_response"
    DESERIALIZED = "deserialized_input"


class SinkKind(_Str):
    """Operations where attacker-influenced data becomes dangerous."""

    SQL = "sql"
    SHELL_EXEC = "shell_exec"
    PROCESS_EXEC = "process_exec"
    TEMPLATE_RENDER = "template_render"
    DESERIALISATION = "deserialisation"
    FILESYSTEM = "filesystem"
    PATH_CONSTRUCTION = "path_construction"
    NETWORK_REQUEST = "network_request"
    DYNAMIC_EVAL = "dynamic_eval"
    DYNAMIC_IMPORT = "dynamic_import"
    HTML_OUTPUT = "html_output"
    AUTH_DECISION = "auth_decision"
    AUTHZ_DECISION = "authz_decision"
    CRYPTO = "crypto"
    LOG_WRITE = "log_write"
    MEMORY_COPY = "memory_copy"
    MEMORY_ALLOC = "memory_alloc"
    INDEXED_WRITE = "indexed_write"
    XML_PARSE = "xml_parse"
    REDIRECT = "redirect"


class TrustBoundaryKind(_Str):
    """A place where data changes trust domain."""

    HTTP_TO_APP = "http_to_application"
    CLI_TO_APP = "cli_to_application"
    APP_TO_DATABASE = "application_to_database"
    APP_TO_SHELL = "application_to_shell"
    APP_TO_FILESYSTEM = "application_to_filesystem"
    APP_TO_NETWORK = "application_to_network"
    APP_TO_TEMPLATE = "application_to_template"
    APP_TO_DESERIALISER = "application_to_deserialiser"
    ENV_TO_APP = "environment_to_application"
    FILE_TO_APP = "file_to_application"
    QUEUE_TO_APP = "queue_to_application"


@dataclass(frozen=True, slots=True)
class Rule:
    """One taxonomy rule.

    ``pattern`` is matched against a single source line. That is intentionally cheap and
    syntactic: a rule fires a *candidate*, and precision comes from the taint analysis
    (:mod:`app.security_model.taint`) and from execution, not from a cleverer regex.
    """

    id: str
    category: str
    kind: str
    pattern: str
    languages: tuple[str, ...] = ("python",)
    cwe: str = ""
    severity: str = "MEDIUM"
    why: str = ""
    #: Names this rule contributes as callable identifiers, used by the taint analyser to
    #: recognise a sanitiser/sink by call target rather than by line text.
    callables: tuple[str, ...] = ()
    #: 0–1 prior on the rule itself. A `subprocess(..., shell=True)` match is far more reliable
    #: than a bare `open(` match, and the flow confidence multiplies this in.
    confidence: float = 0.6

    @property
    def compiled(self) -> re.Pattern[str]:
        return _compile(self.pattern)

    def applies_to(self, language: str) -> bool:
        return "*" in self.languages or language in self.languages

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "kind": self.kind,
            "pattern": self.pattern,
            "languages": list(self.languages),
            "cwe": self.cwe,
            "severity": self.severity,
            "why": self.why,
            "confidence": self.confidence,
        }


@lru_cache(maxsize=1024)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
SOURCE_RULES: tuple[Rule, ...] = (
    # -- HTTP (Python: Flask / Django / FastAPI) --------------------------
    Rule(
        "src.py.flask.args", SecurityCategory.SOURCE.value, SourceKind.HTTP_PARAM.value,
        r"\brequest\.(args|GET|query_params)\b", ("python",),
        why="HTTP query parameters are fully attacker-controlled.", confidence=0.95,
    ),
    Rule(
        "src.py.flask.form", SecurityCategory.SOURCE.value, SourceKind.HTTP_BODY.value,
        r"\brequest\.(form|POST|json|data|body)\b", ("python",),
        why="HTTP request bodies are fully attacker-controlled.", confidence=0.95,
    ),
    Rule(
        "src.py.flask.headers", SecurityCategory.SOURCE.value, SourceKind.HTTP_HEADER.value,
        r"\brequest\.headers\b", ("python",),
        why="HTTP headers are attacker-controlled and often trusted by mistake.", confidence=0.9,
    ),
    Rule(
        "src.py.flask.cookies", SecurityCategory.SOURCE.value, SourceKind.HTTP_COOKIE.value,
        r"\brequest\.cookies\b", ("python",),
        why="Cookies are client-supplied and can be forged unless signed.", confidence=0.9,
    ),
    Rule(
        "src.py.flask.files", SecurityCategory.SOURCE.value, SourceKind.UPLOADED_FILE.value,
        r"\brequest\.files\b", ("python",),
        why="Uploaded file names and contents are attacker-controlled.", confidence=0.95,
    ),
    # -- HTTP (JavaScript / Express) --------------------------------------
    Rule(
        "src.js.req.query", SecurityCategory.SOURCE.value, SourceKind.HTTP_PARAM.value,
        r"\breq(uest)?\.query\b", ("javascript",),
        why="HTTP query parameters are fully attacker-controlled.", confidence=0.95,
    ),
    Rule(
        "src.js.req.body", SecurityCategory.SOURCE.value, SourceKind.HTTP_BODY.value,
        r"\breq(uest)?\.body\b", ("javascript",),
        why="HTTP request bodies are fully attacker-controlled.", confidence=0.95,
    ),
    Rule(
        "src.js.req.params", SecurityCategory.SOURCE.value, SourceKind.HTTP_PATH.value,
        r"\breq(uest)?\.params\b", ("javascript",),
        why="Path parameters are attacker-controlled.", confidence=0.9,
    ),
    Rule(
        "src.js.req.headers", SecurityCategory.SOURCE.value, SourceKind.HTTP_HEADER.value,
        r"\breq(uest)?\.(headers|cookies)\b", ("javascript",),
        why="Headers and cookies are client-supplied.", confidence=0.9,
    ),
    # -- process / environment -------------------------------------------
    Rule(
        "src.py.argv", SecurityCategory.SOURCE.value, SourceKind.CLI_ARG.value,
        r"\bsys\.argv\b|\bargparse\b|\bparse_args\s*\(", ("python",),
        why="Command-line arguments are supplied by whoever invokes the program.",
        confidence=0.8,
    ),
    Rule(
        "src.py.stdin", SecurityCategory.SOURCE.value, SourceKind.STDIN.value,
        r"\bsys\.stdin\b|\binput\s*\(", ("python",),
        why="Standard input is externally supplied.", confidence=0.8,
    ),
    Rule(
        "src.py.environ", SecurityCategory.SOURCE.value, SourceKind.ENV_VAR.value,
        r"\bos\.environ\b|\bos\.getenv\s*\(", ("python",),
        why="Environment variables are set outside the program.", confidence=0.6,
    ),
    Rule(
        "src.js.env", SecurityCategory.SOURCE.value, SourceKind.ENV_VAR.value,
        r"\bprocess\.env\b|\bprocess\.argv\b", ("javascript",),
        why="Environment and argv are set outside the program.", confidence=0.6,
    ),
    Rule(
        "src.c.argv", SecurityCategory.SOURCE.value, SourceKind.CLI_ARG.value,
        r"\bargv\s*\[|\bgetenv\s*\(", ("c",),
        why="argv and the environment are externally supplied.", confidence=0.75,
    ),
    Rule(
        "src.c.read", SecurityCategory.SOURCE.value, SourceKind.STDIN.value,
        r"\b(fgets|gets|scanf|fscanf|read|recv|fread)\s*\(", ("c",),
        why="Reads from a stream or socket bring in external bytes.", confidence=0.8,
    ),
    # -- files / db / queues ---------------------------------------------
    Rule(
        "src.py.file_read", SecurityCategory.SOURCE.value, SourceKind.FILE_READ.value,
        r"\.read_text\s*\(|\.read_bytes\s*\(|\bopen\s*\([^)]*[\"']r", ("python",),
        why="File contents are external data unless the file is trusted.", confidence=0.45,
    ),
    Rule(
        "src.py.deserialise_in", SecurityCategory.SOURCE.value, SourceKind.DESERIALIZED.value,
        r"\bjson\.loads?\s*\(|\byaml\.safe_load\s*\(", ("python",),
        why="Deserialised structures carry externally-shaped data.", confidence=0.5,
    ),
    Rule(
        "src.py.db_fetch", SecurityCategory.SOURCE.value, SourceKind.DB_RECORD.value,
        r"\.fetch(one|all|many)\s*\(|\.scalars?\s*\(", ("python",),
        why="Stored records may hold data an attacker wrote earlier (second-order flows).",
        confidence=0.4,
    ),
    Rule(
        "src.py.network_response", SecurityCategory.SOURCE.value,
        SourceKind.NETWORK_RESPONSE.value,
        r"\brequests\.(get|post|put|delete)\s*\([^)]*\)\.(text|json|content)", ("python",),
        why="A remote response is data from another trust domain.", confidence=0.5,
    ),
)


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------
SINK_RULES: tuple[Rule, ...] = (
    Rule(
        "sink.py.shell_true", SecurityCategory.SINK.value, SinkKind.SHELL_EXEC.value,
        r"shell\s*=\s*True", ("python",), cwe="CWE-78", severity="CRITICAL",
        why="A shell interprets metacharacters, so any injected token becomes a command.",
        callables=("subprocess.run", "subprocess.Popen", "subprocess.call"), confidence=0.95,
    ),
    Rule(
        "sink.py.os_system", SecurityCategory.SINK.value, SinkKind.SHELL_EXEC.value,
        r"\bos\.(system|popen)\s*\(", ("python",), cwe="CWE-78", severity="CRITICAL",
        why="os.system and os.popen always run through a shell.",
        callables=("os.system", "os.popen"), confidence=0.95,
    ),
    Rule(
        "sink.py.subprocess", SecurityCategory.SINK.value, SinkKind.PROCESS_EXEC.value,
        r"\bsubprocess\.(run|Popen|call|check_output|check_call)\s*\(", ("python",),
        cwe="CWE-78", severity="HIGH",
        why="Process execution with a caller-influenced argv can change which program runs.",
        callables=("subprocess.run", "subprocess.Popen", "subprocess.call",
                   "subprocess.check_output", "subprocess.check_call"),
        confidence=0.75,
    ),
    Rule(
        "sink.py.eval", SecurityCategory.SINK.value, SinkKind.DYNAMIC_EVAL.value,
        r"\beval\s*\(|\bexec\s*\(", ("python",), cwe="CWE-95", severity="CRITICAL",
        why="eval/exec turn data into code.", callables=("eval", "exec"), confidence=0.9,
    ),
    Rule(
        "sink.py.import", SecurityCategory.SINK.value, SinkKind.DYNAMIC_IMPORT.value,
        r"\b__import__\s*\(|\bimportlib\.import_module\s*\(", ("python",), cwe="CWE-470",
        severity="HIGH", why="A caller-controlled module name loads arbitrary code.",
        callables=("__import__", "importlib.import_module"), confidence=0.8,
    ),
    Rule(
        "sink.py.pickle", SecurityCategory.SINK.value, SinkKind.DESERIALISATION.value,
        r"\bpickle\.(load|loads)\s*\(|\bdill\.(load|loads)\s*\(", ("python",), cwe="CWE-502",
        severity="CRITICAL", why="Unpickling untrusted bytes executes arbitrary constructors.",
        callables=("pickle.load", "pickle.loads"), confidence=0.95,
    ),
    Rule(
        "sink.py.yaml_load", SecurityCategory.SINK.value, SinkKind.DESERIALISATION.value,
        r"\byaml\.load\s*\((?![^)]*SafeLoader)", ("python",), cwe="CWE-502", severity="CRITICAL",
        why="yaml.load without SafeLoader instantiates arbitrary Python objects.",
        callables=("yaml.load",), confidence=0.9,
    ),
    Rule(
        "sink.py.sql", SecurityCategory.SINK.value, SinkKind.SQL.value,
        r"\b(cursor|conn(ection)?|session|db)\.execute\s*\(|\btext\s*\(\s*f?[\"']", ("python",),
        cwe="CWE-89", severity="CRITICAL",
        why="SQL assembled from a string cannot distinguish data from syntax.",
        callables=("cursor.execute", "session.execute", "db.execute"), confidence=0.8,
    ),
    Rule(
        "sink.js.sql", SecurityCategory.SINK.value, SinkKind.SQL.value,
        r"\.(query|raw)\s*\(\s*[`\"']|\.\$queryRawUnsafe\s*\(", ("javascript",), cwe="CWE-89",
        severity="CRITICAL", why="String-built SQL cannot separate data from syntax.",
        confidence=0.75,
    ),
    Rule(
        "sink.py.template", SecurityCategory.SINK.value, SinkKind.TEMPLATE_RENDER.value,
        r"\brender_template_string\s*\(|\bTemplate\s*\(|\bfrom_string\s*\(", ("python",),
        cwe="CWE-1336", severity="CRITICAL",
        why="Rendering an attacker-supplied template string executes template expressions.",
        callables=("render_template_string", "Template", "from_string"), confidence=0.85,
    ),
    Rule(
        "sink.py.path_join", SecurityCategory.SINK.value, SinkKind.PATH_CONSTRUCTION.value,
        r"Path\s*\([^)]*\)\s*/|\bos\.path\.join\s*\(", ("python",), cwe="CWE-22",
        severity="HIGH",
        why="A path built from caller input can escape its intended root via traversal.",
        callables=("os.path.join",), confidence=0.55,
    ),
    Rule(
        "sink.py.filesystem", SecurityCategory.SINK.value, SinkKind.FILESYSTEM.value,
        r"\bopen\s*\(|\.read_text\s*\(|\.write_text\s*\(|\bshutil\.(copy|move|rmtree)\s*\(",
        ("python",), cwe="CWE-22", severity="MEDIUM",
        why="Filesystem access with a caller-influenced path reads or writes outside its root.",
        callables=("open", "shutil.copy", "shutil.move", "shutil.rmtree"), confidence=0.4,
    ),
    Rule(
        "sink.py.network", SecurityCategory.SINK.value, SinkKind.NETWORK_REQUEST.value,
        r"\brequests\.(get|post|put|delete)\s*\(|\burllib\.request\.urlopen\s*\(", ("python",),
        cwe="CWE-918", severity="HIGH",
        why="A request to a caller-controlled URL reaches internal services (SSRF).",
        callables=("requests.get", "requests.post", "urllib.request.urlopen"), confidence=0.7,
    ),
    Rule(
        "sink.py.jwt_noverify", SecurityCategory.SINK.value, SinkKind.AUTH_DECISION.value,
        r"jwt\.decode\s*\([^)]*verify\s*=\s*False|options\s*=\s*\{[^}]*verify_signature[\"']?\s*:\s*False",
        ("python",), cwe="CWE-347", severity="CRITICAL",
        why="Decoding a token without verifying its signature accepts forged tokens.",
        confidence=0.95,
    ),
    Rule(
        "sink.py.crypto_weak", SecurityCategory.SINK.value, SinkKind.CRYPTO.value,
        r"\bhashlib\.(md5|sha1)\s*\(|\bDES\b|\bECB\b", ("python",), cwe="CWE-327",
        severity="MEDIUM", why="A weak primitive undermines the property it is used for.",
        confidence=0.6,
    ),
    Rule(
        "sink.js.eval", SecurityCategory.SINK.value, SinkKind.DYNAMIC_EVAL.value,
        r"\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*[\"'`]", ("javascript",),
        cwe="CWE-95", severity="CRITICAL", why="eval and Function turn data into code.",
        confidence=0.9,
    ),
    Rule(
        "sink.js.exec", SecurityCategory.SINK.value, SinkKind.SHELL_EXEC.value,
        r"\bchild_process\.(exec|execSync)\s*\(|\bexec\s*\(\s*`", ("javascript",), cwe="CWE-78",
        severity="CRITICAL", why="child_process.exec runs its argument through a shell.",
        confidence=0.9,
    ),
    Rule(
        "sink.js.html", SecurityCategory.SINK.value, SinkKind.HTML_OUTPUT.value,
        r"\.innerHTML\s*=|dangerouslySetInnerHTML|\.outerHTML\s*=", ("javascript",), cwe="CWE-79",
        severity="HIGH", why="Assigning untrusted HTML executes injected script.",
        confidence=0.85,
    ),
    Rule(
        "sink.c.memcpy", SecurityCategory.SINK.value, SinkKind.MEMORY_COPY.value,
        r"\b(memcpy|memmove|strcpy|strcat|sprintf|gets)\s*\(", ("c",), cwe="CWE-787",
        severity="CRITICAL",
        why="An unclamped copy length overflows the destination buffer.", confidence=0.8,
    ),
    Rule(
        "sink.c.alloc", SecurityCategory.SINK.value, SinkKind.MEMORY_ALLOC.value,
        r"\b(malloc|calloc|realloc|alloca)\s*\(", ("c",), cwe="CWE-789", severity="MEDIUM",
        why="An allocation sized from external input can be zero, huge or wrap.",
        confidence=0.5,
    ),
    Rule(
        "sink.py.xml", SecurityCategory.SINK.value, SinkKind.XML_PARSE.value,
        r"\betree\.(parse|fromstring)\s*\(|\bxmltodict\.parse\s*\(|\bminidom\.parse", ("python",),
        cwe="CWE-611", severity="HIGH",
        why="An XML parser that resolves external entities reads local files.", confidence=0.6,
    ),
    Rule(
        "sink.py.redirect", SecurityCategory.SINK.value, SinkKind.REDIRECT.value,
        r"\bredirect\s*\(", ("python",), cwe="CWE-601", severity="MEDIUM",
        why="A redirect to a caller-controlled URL enables phishing.", confidence=0.5,
    ),
    Rule(
        "sink.py.log", SecurityCategory.SINK.value, SinkKind.LOG_WRITE.value,
        r"\b(logger|logging)\.(debug|info|warning|error|critical|exception)\s*\(", ("python",),
        cwe="CWE-117", severity="LOW",
        why="Unescaped input in a log can forge entries or leak secrets.", confidence=0.3,
    ),
)


# ---------------------------------------------------------------------------
# Sanitizers and validators
# ---------------------------------------------------------------------------
SANITIZER_RULES: tuple[Rule, ...] = (
    Rule(
        "san.py.shlex_quote", SecurityCategory.SANITIZER.value, "shell_quote",
        r"\bshlex\.quote\s*\(", ("python",),
        why="shlex.quote makes a value a single shell word.",
        callables=("shlex.quote",), confidence=0.9,
    ),
    Rule(
        "san.py.shlex_split", SecurityCategory.SANITIZER.value, "argv_split",
        r"\bshlex\.split\s*\(", ("python",),
        why="Splitting into an argv list avoids shell interpretation entirely.",
        callables=("shlex.split",), confidence=0.8,
    ),
    Rule(
        "san.py.html_escape", SecurityCategory.SANITIZER.value, "html_escape",
        r"\bhtml\.escape\s*\(|\bescape\s*\(|\bbleach\.clean\s*\(|\bMarkupSafe\b", ("python",),
        why="HTML escaping neutralises markup.",
        callables=("html.escape", "bleach.clean", "escape"), confidence=0.8,
    ),
    Rule(
        "san.py.path_resolve", SecurityCategory.SANITIZER.value, "path_containment",
        r"\.resolve\s*\(\s*\)|\bos\.path\.realpath\s*\(|\bcommonpath\s*\(|\bis_relative_to\s*\(",
        ("python",),
        why="Resolving and comparing against a root is how containment is enforced.",
        callables=("os.path.realpath", "os.path.commonpath", "resolve", "is_relative_to"),
        confidence=0.75,
    ),
    Rule(
        # `.name` is deliberately NOT part of this pattern. As a bare attribute access it matches
        # every `foo.name` in a codebase, which floods the sanitizer set and — because a sanitizer
        # on a path lowers a flow's confidence — would quietly suppress real flows.
        "san.py.basename", SecurityCategory.SANITIZER.value, "path_basename",
        r"\bos\.path\.basename\s*\(|\bsecure_filename\s*\(|\bPurePath\([^)]*\)\.name\b",
        ("python",),
        why="Reducing a path to its basename removes traversal segments.",
        callables=("os.path.basename", "secure_filename"), confidence=0.7,
    ),
    Rule(
        "san.py.yaml_safe", SecurityCategory.SANITIZER.value, "safe_deserialise",
        r"\byaml\.safe_load\s*\(|SafeLoader", ("python",),
        why="safe_load refuses object construction.",
        callables=("yaml.safe_load",), confidence=0.9,
    ),
    Rule(
        "san.py.sql_params", SecurityCategory.SANITIZER.value, "sql_parameterisation",
        r"execute\s*\([^,)]+,\s*[\(\[]|\bbindparams\s*\(|:\w+\b.*execute", ("python",),
        why="Parameter binding keeps data out of SQL syntax.", confidence=0.65,
    ),
    Rule(
        "san.js.dompurify", SecurityCategory.SANITIZER.value, "html_escape",
        r"\bDOMPurify\.sanitize\s*\(|\bsanitizeHtml\s*\(", ("javascript",),
        why="An HTML sanitiser strips active content.", confidence=0.85,
    ),
    Rule(
        "san.c.bounded_copy", SecurityCategory.SANITIZER.value, "bounded_copy",
        r"\b(strncpy|strlcpy|snprintf|memcpy_s|strncat)\s*\(", ("c",),
        why="A bounded copy takes an explicit destination size.", confidence=0.7,
    ),
)

VALIDATOR_RULES: tuple[Rule, ...] = (
    Rule(
        "val.py.length_check", SecurityCategory.VALIDATOR.value, "length_bound",
        r"\blen\s*\([^)]*\)\s*[<>]=?|\bmax_length\b|\bmaxlen\b", ("python",),
        why="An explicit length bound constrains input size.", confidence=0.6,
    ),
    Rule(
        "val.py.allowlist", SecurityCategory.VALIDATOR.value, "allowlist",
        r"\bin\s*[\(\[\{][^\)\]\}]*[\)\]\}]\s*:|\bALLOWED\w*\b|\bWHITELIST\b|\bchoices\s*=",
        ("python",),
        why="Membership in a fixed set is the strongest input constraint.", confidence=0.7,
    ),
    Rule(
        "val.py.regex_match", SecurityCategory.VALIDATOR.value, "pattern_match",
        r"\bre\.(match|fullmatch)\s*\(", ("python",),
        why="A full-match pattern constrains input shape.", confidence=0.6,
    ),
    Rule(
        "val.py.schema", SecurityCategory.VALIDATOR.value, "schema_validation",
        r"\bBaseModel\b|\bpydantic\b|\bmarshmallow\b|\bvalidate\s*\(|\bmodel_validate\s*\(",
        ("python",),
        why="Schema validation rejects structurally invalid input before use.", confidence=0.7,
    ),
    Rule(
        "val.py.type_coerce", SecurityCategory.VALIDATOR.value, "type_coercion",
        r"\bint\s*\(|\bfloat\s*\(|\bbool\s*\(", ("python",),
        why="Coercing to a numeric type removes string injection payloads.", confidence=0.55,
    ),
)


# ---------------------------------------------------------------------------
# Authentication / authorisation controls
# ---------------------------------------------------------------------------
CONTROL_RULES: tuple[Rule, ...] = (
    Rule(
        "ctl.py.login_required", SecurityCategory.AUTHENTICATION_CHECK.value, "decorator",
        r"@login_required|@jwt_required|@requires_auth|@authenticate", ("python",),
        why="An authentication decorator gates the endpoint it decorates.", confidence=0.9,
    ),
    Rule(
        "ctl.py.auth_call", SecurityCategory.AUTHENTICATION_CHECK.value, "explicit_check",
        r"\b(authenticate|verify_token|check_password|verify_password|current_user)\s*\(",
        ("python",),
        why="An explicit authentication call establishes who the caller is.", confidence=0.7,
    ),
    Rule(
        "ctl.py.authz", SecurityCategory.AUTHORIZATION_CHECK.value, "explicit_check",
        r"\b(has_permission|is_authorized|can_access|check_acl|require_role|has_role)\s*\(",
        ("python",),
        why="An authorisation check decides whether this caller may do this.", confidence=0.8,
    ),
    Rule(
        "ctl.js.middleware", SecurityCategory.AUTHENTICATION_CHECK.value, "middleware",
        r"\b(requireAuth|isAuthenticated|passport\.authenticate|ensureLoggedIn)\b",
        ("javascript",),
        why="Authentication middleware gates the routes it is mounted on.", confidence=0.85,
    ),
)


#: Sink kind -> the trust boundary crossing it represents.
SINK_BOUNDARY: dict[str, str] = {
    SinkKind.SQL.value: TrustBoundaryKind.APP_TO_DATABASE.value,
    SinkKind.SHELL_EXEC.value: TrustBoundaryKind.APP_TO_SHELL.value,
    SinkKind.PROCESS_EXEC.value: TrustBoundaryKind.APP_TO_SHELL.value,
    SinkKind.FILESYSTEM.value: TrustBoundaryKind.APP_TO_FILESYSTEM.value,
    SinkKind.PATH_CONSTRUCTION.value: TrustBoundaryKind.APP_TO_FILESYSTEM.value,
    SinkKind.NETWORK_REQUEST.value: TrustBoundaryKind.APP_TO_NETWORK.value,
    SinkKind.TEMPLATE_RENDER.value: TrustBoundaryKind.APP_TO_TEMPLATE.value,
    SinkKind.DESERIALISATION.value: TrustBoundaryKind.APP_TO_DESERIALISER.value,
}

#: Source kind -> the trust boundary crossing it represents.
SOURCE_BOUNDARY: dict[str, str] = {
    SourceKind.HTTP_PARAM.value: TrustBoundaryKind.HTTP_TO_APP.value,
    SourceKind.HTTP_BODY.value: TrustBoundaryKind.HTTP_TO_APP.value,
    SourceKind.HTTP_HEADER.value: TrustBoundaryKind.HTTP_TO_APP.value,
    SourceKind.HTTP_COOKIE.value: TrustBoundaryKind.HTTP_TO_APP.value,
    SourceKind.HTTP_PATH.value: TrustBoundaryKind.HTTP_TO_APP.value,
    SourceKind.UPLOADED_FILE.value: TrustBoundaryKind.HTTP_TO_APP.value,
    SourceKind.CLI_ARG.value: TrustBoundaryKind.CLI_TO_APP.value,
    SourceKind.STDIN.value: TrustBoundaryKind.CLI_TO_APP.value,
    SourceKind.ENV_VAR.value: TrustBoundaryKind.ENV_TO_APP.value,
    SourceKind.FILE_READ.value: TrustBoundaryKind.FILE_TO_APP.value,
    SourceKind.DB_RECORD.value: TrustBoundaryKind.APP_TO_DATABASE.value,
    SourceKind.MESSAGE_QUEUE.value: TrustBoundaryKind.QUEUE_TO_APP.value,
    SourceKind.NETWORK_RESPONSE.value: TrustBoundaryKind.APP_TO_NETWORK.value,
}


@dataclass
class Taxonomy:
    """The active rule set. Built once per run and passed to the flow builder."""

    sources: list[Rule] = field(default_factory=list)
    sinks: list[Rule] = field(default_factory=list)
    sanitizers: list[Rule] = field(default_factory=list)
    validators: list[Rule] = field(default_factory=list)
    controls: list[Rule] = field(default_factory=list)
    #: Where extra rules came from, for the certificate.
    extensions: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def all_rules(self) -> list[Rule]:
        return [*self.sources, *self.sinks, *self.sanitizers, *self.validators, *self.controls]

    def for_language(self, language: str) -> Taxonomy:
        return Taxonomy(
            sources=[r for r in self.sources if r.applies_to(language)],
            sinks=[r for r in self.sinks if r.applies_to(language)],
            sanitizers=[r for r in self.sanitizers if r.applies_to(language)],
            validators=[r for r in self.validators if r.applies_to(language)],
            controls=[r for r in self.controls if r.applies_to(language)],
            extensions=self.extensions,
        )

    def sanitizer_callables(self) -> set[str]:
        out: set[str] = set()
        for rule in [*self.sanitizers, *self.validators]:
            out.update(rule.callables)
        return out

    def sink_callables(self) -> dict[str, Rule]:
        out: dict[str, Rule] = {}
        for rule in self.sinks:
            for name in rule.callables:
                out[name] = rule
        return out

    def summary(self) -> dict[str, Any]:
        return {
            "sources": len(self.sources),
            "sinks": len(self.sinks),
            "sanitizers": len(self.sanitizers),
            "validators": len(self.validators),
            "controls": len(self.controls),
            "extensions": self.extensions,
            "errors": self.errors,
            "languages": sorted(
                {language for rule in self.all_rules() for language in rule.languages}
            ),
        }


def default_taxonomy() -> Taxonomy:
    return Taxonomy(
        sources=list(SOURCE_RULES),
        sinks=list(SINK_RULES),
        sanitizers=list(SANITIZER_RULES),
        validators=list(VALIDATOR_RULES),
        controls=list(CONTROL_RULES),
    )


def load_taxonomy(path: str | Path | None = None) -> Taxonomy:
    """Defaults, with an operator-supplied JSON file merged over them.

    File shape::

        {"sources": [{"id": "...", "kind": "http_param", "pattern": "...",
                      "languages": ["python"], "cwe": "", "severity": "HIGH",
                      "why": "...", "confidence": 0.9, "callables": []}],
         "sinks": [...], "sanitizers": [...], "validators": [...], "controls": [...]}

    A rule with an existing ``id`` **replaces** the default of that id, which is how a deployment
    tightens or disables a noisy shipped rule (set its confidence to 0) without forking KavachX.
    An unparseable file is recorded in ``errors`` and the defaults still load — a typo in a
    taxonomy override must not silently disable security analysis.
    """
    taxonomy = default_taxonomy()
    if path is None:
        from app.config import settings

        path = settings.security_taxonomy_path or None
    if not path:
        return taxonomy

    file_path = Path(path)
    if not file_path.is_file():
        taxonomy.errors.append(
            f"Security taxonomy extension {file_path} was configured but does not exist; "
            "only the built-in rules are active."
        )
        logger.warning("security.taxonomy_missing", path=str(file_path))
        return taxonomy

    try:
        document = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        taxonomy.errors.append(
            f"Security taxonomy extension {file_path} could not be read ({exc}); only the "
            "built-in rules are active."
        )
        logger.warning("security.taxonomy_unreadable", path=str(file_path), error=str(exc)[:200])
        return taxonomy

    buckets: dict[str, tuple[list[Rule], str]] = {
        "sources": (taxonomy.sources, SecurityCategory.SOURCE.value),
        "sinks": (taxonomy.sinks, SecurityCategory.SINK.value),
        "sanitizers": (taxonomy.sanitizers, SecurityCategory.SANITIZER.value),
        "validators": (taxonomy.validators, SecurityCategory.VALIDATOR.value),
        "controls": (taxonomy.controls, SecurityCategory.AUTHENTICATION_CHECK.value),
    }
    added = 0
    replaced = 0
    for key, (bucket, default_category) in buckets.items():
        for raw in document.get(key) or []:
            if not isinstance(raw, dict):
                continue
            try:
                rule = Rule(
                    id=str(raw["id"]),
                    category=str(raw.get("category") or default_category),
                    kind=str(raw.get("kind") or "custom"),
                    pattern=str(raw["pattern"]),
                    languages=tuple(raw.get("languages") or ("*",)),
                    cwe=str(raw.get("cwe") or ""),
                    severity=str(raw.get("severity") or "MEDIUM"),
                    why=str(raw.get("why") or ""),
                    callables=tuple(raw.get("callables") or ()),
                    confidence=float(raw.get("confidence", 0.6)),
                )
                # Fail fast on a bad regex here rather than at match time on every line.
                re.compile(rule.pattern)
            except (KeyError, TypeError, ValueError, re.error) as exc:
                taxonomy.errors.append(
                    f"Ignored a malformed rule in {key} of {file_path.name}: {exc}"
                )
                continue
            existing = next((i for i, r in enumerate(bucket) if r.id == rule.id), None)
            if existing is None:
                bucket.append(rule)
                added += 1
            else:
                bucket[existing] = rule
                replaced += 1

    taxonomy.extensions.append(f"{file_path.name}: {added} added, {replaced} replaced")
    logger.info("security.taxonomy_loaded", path=str(file_path), added=added, replaced=replaced)
    return taxonomy
