"""Tools the model can call while investigating a repository.

All tools are read-only. `record_finding` is the only way to report, and it
runs the citation check immediately so the model can correct a bad quote
while it still has the file in context.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from .evidence import check_evidence
from .findings import Evidence, Finding, Severity
from .workspace import Workspace, WorkspaceError

MAX_READ_LINES = 220
MAX_LISTED = 200
MAX_OUTPUT_CHARS = 9000


def _fn(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


EVIDENCE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
        "start_line": {"type": "integer"},
        "end_line": {"type": "integer"},
        "quote": {
            "type": "string",
            "description": "Code copied exactly from those lines, without line numbers.",
        },
        "role": {
            "type": "string",
            "enum": ["source", "sink", "propagation", "missing_check", "config", "context"],
        },
    },
    "required": ["path", "start_line", "end_line", "quote", "role"],
}

TOOL_SPECS = [
    _fn(
        "list_files",
        "List files in the repository, optionally under a directory or matching a glob.",
        {
            "dir": {"type": "string", "description": "Directory relative to the repo root."},
            "glob": {"type": "string", "description": "For example *.py or src/*.js."},
        },
        [],
    ),
    _fn(
        "read_file",
        f"Read a file with line numbers. Returns at most {MAX_READ_LINES} lines per call.",
        {
            "path": {"type": "string"},
            "start_line": {"type": "integer"},
            "end_line": {"type": "integer"},
        },
        ["path"],
    ),
    _fn(
        "search",
        "Search file contents with a regular expression. Returns path, line and text.",
        {
            "pattern": {"type": "string"},
            "glob": {"type": "string", "description": "Restrict to matching files."},
        },
        ["pattern"],
    ),
    _fn(
        "record_finding",
        "Report one security weakness. Every claim must be backed by quoted code.",
        {
            "title": {"type": "string"},
            "cwe": {"type": "string", "description": "For example CWE-89."},
            "severity": {"type": "string", "enum": [s.value for s in Severity]},
            "summary": {"type": "string"},
            "reasoning": {
                "type": "string",
                "description": "How untrusted input reaches the weak point, and why nothing stops it.",
            },
            "remediation": {"type": "string"},
            "evidence": {"type": "array", "items": EVIDENCE_SCHEMA},
        },
        ["title", "severity", "summary", "reasoning", "evidence"],
    ),
    _fn(
        "finish",
        "End the investigation when there is nothing more worth checking.",
        {"notes": {"type": "string"}},
        [],
    ),
]


class Toolbox:
    def __init__(self, ws: Workspace):
        self.ws = ws
        self.findings: list[Finding] = []
        self.finished = False
        self.notes = ""
        self._handlers: dict[str, Callable[..., str]] = {
            "list_files": self._list_files,
            "read_file": self._read_file,
            "search": self._search,
            "record_finding": self._record_finding,
            "finish": self._finish,
        }

    def call(self, name: str, arguments: dict[str, Any]) -> str:
        handler = self._handlers.get(name)
        if handler is None:
            return f"error: unknown tool {name!r}"
        try:
            out = handler(**arguments)
        except WorkspaceError as exc:
            out = f"error: {exc}"
        except TypeError as exc:
            out = f"error: bad arguments for {name}: {exc}"
        if len(out) > MAX_OUTPUT_CHARS:
            out = out[:MAX_OUTPUT_CHARS] + "\n[output truncated]"
        return out

    def _list_files(self, dir: str = ".", glob: str | None = None) -> str:
        files = self.ws.files(dir or ".", glob or None)
        if not files:
            return "no files matched"
        shown = files[:MAX_LISTED]
        more = f"\n[{len(files) - len(shown)} more not shown]" if len(files) > len(shown) else ""
        return "\n".join(shown) + more

    def _read_file(
        self, path: str, start_line: int = 1, end_line: int | None = None
    ) -> str:
        start = max(1, int(start_line or 1))
        total = len(self.ws.lines(path))
        end = min(total, int(end_line) if end_line else total, start + MAX_READ_LINES - 1)
        body = self.ws.read(path, start, end)
        tail = f"\n[lines {start}-{end} of {total}]"
        return body + tail

    def _search(self, pattern: str, glob: str | None = None) -> str:
        hits = self.ws.grep(pattern, glob or None)
        if not hits:
            return "no matches"
        return "\n".join(f"{h.path}:{h.line}: {h.text}" for h in hits)

    def _record_finding(self, **raw: Any) -> str:
        try:
            raw["evidence"] = [Evidence(**e) for e in raw.get("evidence") or []]
            finding = Finding(**raw)
        except (ValidationError, TypeError) as exc:
            return f"error: finding rejected, fix the fields and call again: {exc}"
        check = check_evidence(self.ws, finding)
        if not check.passed:
            return (
                "error: finding NOT recorded because a quote does not match the file "
                f"({check.detail}). Re-read the file and quote the code exactly."
            )
        finding.checks.append(check)
        finding.id = f"F{len(self.findings) + 1:03d}"
        self.findings.append(finding)
        return f"recorded as {finding.id}"

    def _finish(self, notes: str = "") -> str:
        self.finished = True
        self.notes = notes
        return "done"
