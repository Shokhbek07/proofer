"""Render findings for a human reader."""

from __future__ import annotations

from .findings import Finding, Tier

_ORDER = {Tier.CONFIRMED: 0, Tier.SUPPORTED: 1, Tier.SUSPECTED: 2, Tier.REJECTED: 3}
_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _hedged(f: Finding) -> bool:
    return any(c.name == "wording" and not c.passed for c in f.checks)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Best-verified first; within a tier, plainly worded before hedged."""
    return sorted(
        findings, key=lambda f: (_ORDER[f.tier], _hedged(f), _SEV[f.severity.value], f.id)
    )


def to_markdown(findings: list[Finding], target: str, model: str) -> str:
    shown = [f for f in sort_findings(findings) if f.tier != Tier.REJECTED]
    rejected = len(findings) - len(shown)
    out = [
        f"# Security review of `{target}`",
        "",
        f"Model: `{model}`.",
        f"{len(shown)} findings reported, {rejected} rejected during verification.",
        "",
        ("Tiers: `supported` means the finding has verified citations and an independent "
        "scanner reported the same place. `suspected` means verified citations only. "
        "Within a tier, findings worded with hedges such as \"could\" or \"potentially\" "
        "are listed last."),
        "",
    ]
    for f in shown:
        where = f.primary
        loc = f"{where.path}:{where.start_line}" if where else "no location"
        out += [
            f"## {f.id} {f.title}",
            "",
            f"- Tier: `{f.tier.value}`",
            f"- Severity: {f.severity.value}",
            f"- Weakness: {f.cwe or 'unclassified'}",
            f"- Location: `{loc}`",
            "",
            f.summary,
            "",
        ]
        if f.reasoning:
            out += ["**Why it is reachable:** " + f.reasoning, ""]
        for ev in f.evidence:
            out += [
                f"`{ev.path}:{ev.start_line}-{ev.end_line}` ({ev.role})",
                "```",
                ev.quote.rstrip(),
                "```",
                "",
            ]
        if f.remediation:
            out += ["**Fix:** " + f.remediation, ""]
        if f.checks:
            out.append("Checks:")
            for c in f.checks:
                mark = "pass" if c.passed else "fail"
                out.append(f"- {c.name}: {mark}" + (f" ({c.detail})" if c.detail else ""))
            out.append("")
    return "\n".join(out)
