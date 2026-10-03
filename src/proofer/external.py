"""Adapters for existing scanners, used as an outside baseline."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from .findings import Evidence, Finding
from .workspace import Workspace, WorkspaceError


class ScannerError(Exception):
    pass


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def same_place(finding: Finding, others: list[Finding], slack: int = 3) -> bool:
    """True when another tool reported within a few lines of any cited span."""
    return any(
        mine.path == theirs.path
        and mine.start_line - slack <= theirs.end_line
        and mine.end_line + slack >= theirs.start_line
        for mine in finding.evidence
        for other in others
        for theirs in other.evidence
    )


def scanner_env() -> dict[str, str]:
    """The environment minus empty certificate paths, which make Semgrep abort.

    A shell profile line such as `export SSL_CERT_FILE=$(python3 -m certifi)`
    leaves the variable empty when that Python lacks certifi.
    """
    return {k: v for k, v in os.environ.items()
            if v or k not in ("SSL_CERT_FILE", "SSL_CERT_DIR")}


def semgrep_findings(ws: Workspace, config: str = "p/default") -> list[Finding]:
    """Run Semgrep's community rules and convert the results to findings.

    The rules are fetched by Semgrep at run time and are not part of this
    repository: their licence allows internal use but not redistribution.
    """
    if not semgrep_available():
        raise ScannerError("semgrep is not installed (try: uv tool install semgrep)")
    proc = subprocess.run(
        ["semgrep", "scan", "--config", config, "--metrics", "off", "--json", "--quiet",
         str(ws.root)],
        capture_output=True, text=True, timeout=900, check=False, env=scanner_env(),
    )
    try:
        results = json.loads(proc.stdout)["results"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise ScannerError(f"semgrep failed: {proc.stderr.strip()[:300]}") from exc

    findings: list[Finding] = []
    for r in results:
        try:
            rel = ws.rel(ws.resolve(r["path"]))
            lines = ws.lines(rel)
        except (WorkspaceError, ValueError):
            continue
        start, end = r["start"]["line"], r["end"]["line"]
        meta = r["extra"].get("metadata", {})
        cwe = meta.get("cwe")
        findings.append(Finding(
            title=r["check_id"].rsplit(".", 1)[-1],
            cwe=cwe[0] if isinstance(cwe, list) and cwe else cwe,
            summary=r["extra"].get("message", "")[:400],
            origin="semgrep",
            evidence=[Evidence(path=rel, start_line=start, end_line=end,
                               quote="\n".join(lines[start - 1:end]), role="sink")],
        ))
    return findings
