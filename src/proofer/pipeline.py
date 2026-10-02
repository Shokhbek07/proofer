"""Run a review over a repository: leads, model pass, tiering."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import IO

from .agent import dump_trace, investigate
from .external import ScannerError, same_place, semgrep_available, semgrep_findings
from .findings import Check, Evidence, Finding, Tier
from .judge import plain_wording, review_file
from .leads import LEXICON, Lead, find_leads
from .llm import ChatClient
from .tools import Toolbox
from .workspace import Workspace

MODES = ("judge", "agent", "patterns", "semgrep")


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    discarded: int = 0
    leads: int = 0
    seconds: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    errors: list[str] = field(default_factory=list)

    def stats(self) -> dict[str, object]:
        return {
            "leads": self.leads,
            "findings": len(self.findings),
            "discarded_bad_citation": self.discarded,
            "seconds": round(self.seconds, 1),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "errors": self.errors,
        }


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int, str | None]] = set()
    kept: list[Finding] = []
    for f in findings:
        where = f.primary
        key = (where.path, where.start_line, f.cwe) if where else ("", 0, f.title)
        if key not in seen:
            seen.add(key)
            kept.append(f)
    return kept


def _assign_tiers(findings: list[Finding], scanner: list[Finding] | None) -> None:
    """`supported` means an independent scanner reported the same place.

    The model's own labels and its consistency across runs were both measured
    and neither separates true findings from false ones (E3, E6, E9).
    """
    for i, f in enumerate(findings, start=1):
        f.id = f"F{i:03d}"
        f.checks.append(plain_wording(f))
        if scanner is None:
            f.checks.append(Check(name="scanner agreement", passed=False,
                                  detail="no independent scanner was run"))
            f.tier = Tier.SUSPECTED
            continue
        agrees = same_place(f, scanner)
        f.checks.append(Check(name="scanner agreement", passed=agrees,
                              detail="semgrep reports the same place" if agrees else ""))
        f.tier = Tier.SUPPORTED if agrees else Tier.SUSPECTED


def pattern_findings(ws: Workspace, lead: Lead) -> list[Finding]:
    """Baseline with no model: every pattern hit is reported as a finding."""
    cwe_of = {cls: cwe for cls, cwe, _ in LEXICON}
    lines = ws.lines(lead.path)
    return [
        Finding(
            title=cls, cwe=cwe_of[cls] or None, summary=f"pattern match for {cls}",
            origin="patterns",
            evidence=[Evidence(path=lead.path, start_line=n, end_line=n,
                               quote=lines[n - 1], role="sink")],
        )
        for cls, nums in lead.hints.items() if cls != "request handler"
        for n in nums
    ]


def scan(
    ws: Workspace,
    client: ChatClient | None,
    mode: str = "judge",
    max_leads: int | None = None,
    max_steps: int = 24,
    progress: Callable[[str], None] | None = None,
    trace_file: IO[str] | None = None,
    variant: str = "plain",
    strip_comments: bool = False,
    corroborate: bool = True,
    trust_boundary: bool = True,
) -> ScanResult:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    say = progress or (lambda _msg: None)
    if mode == "semgrep":
        result = ScanResult(findings=_dedupe(semgrep_findings(ws)))
        _assign_tiers(result.findings, None)
        return result
    leads = find_leads(ws, max_leads)
    result = ScanResult(leads=len(leads))
    collected: list[Finding] = []

    for i, lead in enumerate(leads, start=1):
        if mode == "patterns":
            collected += pattern_findings(ws, lead)
            continue
        assert client is not None, "a model client is required for this mode"
        say(f"[{i}/{len(leads)}] {lead.path}")
        if mode == "judge":
            review = review_file(client, ws, lead, variant, strip_comments, trust_boundary)
            collected += review.findings
            result.discarded += len(review.discarded)
            result.seconds += review.seconds
            result.prompt_tokens += review.prompt_tokens
            result.completion_tokens += review.completion_tokens
            if review.error:
                result.errors.append(f"{lead.path}: {review.error}")
            say(f"      {len(review.findings)} kept, {len(review.discarded)} discarded, {review.seconds:.0f}s")
        else:
            toolbox = Toolbox(ws)
            trace = investigate(client, toolbox, lead.brief(), max_steps=max_steps)
            collected += toolbox.findings
            result.discarded += sum(
                1 for s in trace.steps if s.tool == "record_finding" and "NOT recorded" in s.output
            )
            result.seconds += trace.seconds
            result.prompt_tokens += trace.prompt_tokens
            result.completion_tokens += trace.completion_tokens
            if trace_file:
                trace_file.write(dump_trace(trace) + "\n")
                trace_file.flush()
            say(f"      {len(toolbox.findings)} kept, {len(trace.steps)} steps, {trace.seconds:.0f}s, {trace.stop_reason}")

    scanner: list[Finding] | None = None
    if corroborate and mode != "patterns" and semgrep_available():
        try:
            scanner = semgrep_findings(ws)
        except ScannerError as exc:
            result.errors.append(str(exc))
    result.findings = _dedupe(collected)
    _assign_tiers(result.findings, scanner)
    return result
