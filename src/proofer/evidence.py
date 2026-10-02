"""Mechanical citation check.

A model can describe a weakness convincingly while citing code that does not
exist. Before any finding is shown, every quote it relies on must be found in
the file it names. Line numbers that are slightly off are corrected, because
small models miscount lines far more often than they invent code.
"""

from __future__ import annotations

import re

from .findings import Check, Evidence, Finding
from .workspace import Workspace, WorkspaceError

CHECK_NAME = "evidence"
# Models often copy the line-number gutter along with the code.
_GUTTER = re.compile(r"^\s*\d+\|\s?")


def _norm(text: str) -> str:
    return " ".join(text.split())


def _quote_lines(quote: str) -> list[str]:
    return [n for n in (_norm(_GUTTER.sub("", line)) for line in quote.splitlines()) if n]


def locate(lines: list[str], quote: str) -> tuple[int, int] | None:
    """Find the quote as consecutive non-blank lines; return its 1-based span."""
    wanted = _quote_lines(quote)
    if not wanted:
        return None
    indexed = [(i + 1, _norm(line)) for i, line in enumerate(lines)]
    dense = [(n, text) for n, text in indexed if text]
    for i in range(len(dense) - len(wanted) + 1):
        window = dense[i : i + len(wanted)]
        if all(w in text for w, (_, text) in zip(wanted, window)):
            return window[0][0], window[-1][0]
    return None


def check_one(ws: Workspace, ev: Evidence) -> tuple[bool, str, Evidence]:
    try:
        lines = ws.lines(ev.path)
    except WorkspaceError as exc:
        return False, str(exc), ev
    span = locate(lines, ev.quote)
    if span is None:
        return False, f"quote not found in {ev.path}", ev
    start, end = span
    if (start, end) == (ev.start_line, ev.end_line):
        return True, "exact", ev
    fixed = ev.model_copy(update={"start_line": start, "end_line": end})
    return True, f"lines corrected from {ev.start_line}-{ev.end_line}", fixed


def check_evidence(ws: Workspace, finding: Finding) -> Check:
    """Verify every citation, correcting line numbers and dropping bad ones."""
    if not finding.evidence:
        return Check(name=CHECK_NAME, passed=False, detail="no evidence cited")
    notes: list[str] = []
    verified: list[Evidence] = []
    for ev in finding.evidence:
        passed, detail, fixed = check_one(ws, ev)
        same_place = any(
            (v.path, v.start_line, v.end_line, v.role) == (fixed.path, fixed.start_line, fixed.end_line, fixed.role)
            for v in verified
        )
        if passed and not same_place:
            verified.append(fixed)
        if detail != "exact":
            notes.append(f"{ev.path}: {detail}")
    # A finding may only rest on quotes that exist, so unverifiable citations
    # are removed, and a finding with none left fails.
    dropped = len(finding.evidence) - len(verified)
    if verified:
        finding.evidence = verified
    if dropped:
        notes.append(f"{dropped} unverifiable or duplicate citations removed")
    return Check(name=CHECK_NAME, passed=bool(verified), detail="; ".join(notes))
