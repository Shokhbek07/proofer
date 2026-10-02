"""Deterministic lead generation.

The model is slow and easily distracted, so it is not asked to wander a whole
repository. Each source or deployment file becomes one short review. Cheap
pattern matching ranks the files and supplies hints; it never decides that
something is a weakness, and a file with no pattern hit is still reviewed.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from .workspace import Workspace, WorkspaceError

CODE_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".java", ".go",
    ".rb", ".cs", ".kt", ".rs", ".c", ".cc", ".cpp", ".h", ".sh",
}
CONFIG_NAMES = re.compile(
    r"(^|/)(Dockerfile[^/]*|docker-compose[^/]*\.ya?ml|compose\.ya?ml|\.env[^/]*|"
    r"nginx[^/]*\.conf|[^/]*\.tf|settings\.py|config\.(py|js|json|ya?ml)|"
    r"application\.(properties|ya?ml))$"
)

# (weakness class, CWE, pattern). Kept deliberately loose: recall matters here,
# precision is the job of the investigation and the verification passes.
LEXICON: list[tuple[str, str, str]] = [
    ("sql injection", "CWE-89", r"(execute|query|raw|prepare)\s*\(.*(\+|%|\$\{|\.format\(|f[\"'])"),
    ("sql injection", "CWE-89", r"(SELECT|INSERT|UPDATE|DELETE)\b.*(\"\s*\+|'\s*\+|\$\{|%s\"\s*%|\.format\()"),
    ("command injection", "CWE-78", r"\b(os\.system|subprocess\.\w+|popen|exec|execSync|spawn|shell_exec|passthru|system|Runtime\.getRuntime)\s*\("),
    ("code injection", "CWE-94", r"\b(eval|exec|Function|compile)\s*\("),
    ("unsafe deserialisation", "CWE-502", r"\b(pickle\.loads?|yaml\.load|unserialize|ObjectInputStream|marshal\.loads?|node-serialize)\b"),
    ("path traversal", "CWE-22", r"\b(open|send_file|sendFile|readFile\w*|createReadStream|file_get_contents|include|require_once)\s*\(.*(\+|req\.|request\.|\$_|params|args)"),
    ("server-side request forgery", "CWE-918", r"\b(requests\.(get|post)|urlopen|fetch|axios\.\w+|http\.get|curl_exec)\s*\(.*(req\.|request\.|params|args|\$_|url)"),
    ("cross-site scripting", "CWE-79", r"(innerHTML|dangerouslySetInnerHTML|document\.write|\|\s*safe\b|render_template_string|Markup\(|res\.send\(.*\+|echo\s+\$_)"),
    ("template injection", "CWE-1336", r"\b(render_template_string|Template\(.*request|env\.from_string)"),
    ("weak cryptography", "CWE-327", r"\b(md5|sha1|DES|RC4|ECB)\b"),
    ("insecure randomness", "CWE-330", r"\b(Math\.random|random\.(random|randint|choice))\s*\("),
    ("hardcoded secret", "CWE-798", r"(?i)(secret|passw(or)?d|api[_-]?key|token|private[_-]?key)\w*\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']"),
    ("hardcoded secret", "CWE-798", r"(?i)^\s*\w*(secret|passw(or)?d|api_?key|token|private_?key)\w*\s*[:=]\s*[^\s\"'$]{6,}\s*$"),
    ("jwt verification", "CWE-347", r"(?i)(verify\s*[:=]\s*false|verify_signature.{0,6}false|algorithms?.{0,12}none|jwt\.decode\()"),
    ("tls verification disabled", "CWE-295", r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)"),
    ("debug or permissive config", "CWE-489", r"(?i)(debug\s*=\s*true|DEBUG\s*=\s*True|Access-Control-Allow-Origin.{0,6}\*|origins?\s*[:=]\s*[\"']\*|ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*)"),
    ("xml external entities", "CWE-611", r"\b(etree\.(parse|fromstring)|XMLParser\(|DocumentBuilderFactory|libxml_disable_entity_loader|parseString)\b"),
    ("open redirect", "CWE-601", r"\b(redirect|sendRedirect|res\.redirect)\s*\(.*(req\.|request\.|params|args|\$_)"),
    ("mass assignment", "CWE-915", r"(\*\*request\.(json|form|data)|Object\.assign\(.*req\.body|\.update\(\s*req\.body|setattr\(.*request)"),
    ("container hardening", "CWE-250", r"(?i)(^\s*USER\s+root|privileged\s*:\s*true|--privileged|/var/run/docker\.sock|network_mode\s*:\s*host|:latest\b)"),
    ("request handler", "", r"(@\w*\.?(route|get|post|put|delete|patch)\(|\b(app|router)\.(get|post|put|delete|patch|all)\(|@(Get|Post|Put|Delete|Request)Mapping|\$_(GET|POST|REQUEST|COOKIE)|http\.HandleFunc)"),
]
_COMPILED = [(cls, cwe, re.compile(rx)) for cls, cwe, rx in LEXICON]


@dataclass
class Lead:
    path: str
    hints: dict[str, list[int]] = field(default_factory=dict)
    cwes: set[str] = field(default_factory=set)

    @property
    def score(self) -> int:
        """Rank files with several distinct weakness classes first."""
        classes = [c for c in self.hints if c != "request handler"]
        return 10 * len(classes) + ("request handler" in self.hints) * 5

    def brief(self) -> str:
        lines = [f"Investigate `{self.path}`.", "Pattern matching flagged these places to check:"]
        for cls, nums in sorted(self.hints.items()):
            shown = ", ".join(str(n) for n in nums[:8])
            lines.append(f"- {cls}: line {shown}")
        lines.append(
            "These are only pointers and are often wrong. Read the code, follow the "
            "data into other files when needed, and report only what the code supports."
        )
        return "\n".join(lines)


def _relevant(rel: str) -> bool:
    dot = rel.rfind(".")
    ext = rel[dot:].lower() if dot != -1 else ""
    return ext in CODE_EXT or bool(CONFIG_NAMES.search(rel))


def find_leads(ws: Workspace, limit: int | None = None) -> list[Lead]:
    leads: list[Lead] = []
    for rel in ws.files():
        if not _relevant(rel):
            continue
        try:
            lines = ws.lines(rel)
        except WorkspaceError:
            continue
        hints: dict[str, list[int]] = defaultdict(list)
        cwes: set[str] = set()
        for n, text in enumerate(lines, start=1):
            if len(text) > 500:
                continue
            for cls, cwe, rx in _COMPILED:
                if rx.search(text):
                    hints[cls].append(n)
                    if cwe:
                        cwes.add(cwe)
        # Every source and deployment file is reviewed. Patterns only decide the
        # order, because the weaknesses they cannot point at are the ones that
        # matter most: a missing check, a missing USER line, a predictable id.
        leads.append(Lead(rel, dict(hints), cwes))
    leads.sort(key=lambda lead: (-lead.score, lead.path))
    return leads[:limit] if limit else leads
