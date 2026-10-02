"""Data model for findings and the checks applied to them."""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator


class Tier(StrEnum):
    """How much verification a finding has survived."""

    REJECTED = "rejected"
    SUSPECTED = "suspected"
    SUPPORTED = "supported"
    CONFIRMED = "confirmed"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Evidence(BaseModel):
    """A claim that specific code exists at a specific place."""

    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    quote: str = Field(description="Code copied verbatim from the cited lines.")
    role: str = Field(
        default="context",
        description="source, sink, propagation, missing_check, config, or context.",
    )


class Check(BaseModel):
    """Outcome of one verification step."""

    name: str
    passed: bool
    detail: str = ""


class Finding(BaseModel):
    id: str = ""
    title: str
    cwe: str | None = Field(default=None, description="For example CWE-89.")
    severity: Severity = Severity.MEDIUM
    summary: str
    reasoning: str = Field(
        default="", description="Why the weakness is reachable and not mitigated."
    )
    remediation: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    origin: str = "agent"
    tier: Tier = Tier.SUSPECTED
    checks: list[Check] = Field(default_factory=list)

    @field_validator("cwe", mode="before")
    @classmethod
    def _normalise_cwe(cls, value: object) -> str | None:
        """Models write `89`, `CWE-89`, or `CWE-89: SQL Injection`; keep one form."""
        match = re.search(r"\d+", str(value or ""))
        return f"CWE-{int(match.group())}" if match else None

    @property
    def primary(self) -> Evidence | None:
        """The location a reader should open first: the sink if one is cited."""
        for ev in self.evidence:
            if ev.role == "sink":
                return ev
        return self.evidence[0] if self.evidence else None
