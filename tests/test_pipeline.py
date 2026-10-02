"""Pipeline behaviour with a scripted client; no model involved."""

import json

from proofer.findings import Evidence, Finding, Tier
from proofer.llm import ChatResult
from proofer.pipeline import _assign_tiers, scan
from proofer.report import sort_findings
from proofer.workspace import Workspace

SINK = "    return os.system('ping ' + name)"


class Scripted:
    model = "scripted"

    def __init__(self, payload):
        self.payload = payload

    def chat(self, messages, tools=None, schema=None):
        return ChatResult(content=self.payload, seconds=1.5, prompt_tokens=10, completion_tokens=5)


def repo(tmp_path):
    (tmp_path / "views.py").write_text(
        "def run(request):\n    name = request.args['name']\n" + SINK + "\n"
    )
    return Workspace(tmp_path)


def raw(evidence):
    return {"title": "t", "cwe": "78", "severity": "high", "summary": "s",
            "reasoning": "r", "remediation": "m", "evidence": evidence}


def ev(line, quote, role):
    return {"path": "views.py", "start_line": line, "end_line": line, "quote": quote, "role": role}


def test_duplicates_are_merged_and_bad_citations_dropped(tmp_path):
    both_ends = raw([ev(2, "name = request.args['name']", "source"), ev(3, SINK, "sink")])
    one_end = raw([ev(2, "name = request.args['name']", "context")])
    payload = json.dumps({"findings": [both_ends, both_ends, one_end, raw([ev(3, "eval(x)", "sink")])]})
    result = scan(repo(tmp_path), Scripted(payload), corroborate=False)
    assert [f.id for f in result.findings] == ["F001", "F002"]
    assert [f.tier for f in result.findings] == [Tier.SUSPECTED, Tier.SUSPECTED]
    assert result.discarded == 1
    assert result.stats()["seconds"] == 1.5


def test_patterns_mode_needs_no_model(tmp_path):
    result = scan(repo(tmp_path), None, mode="patterns")
    assert [f.cwe for f in result.findings] == ["CWE-78"]
    assert result.findings[0].origin == "patterns"


def at(line, summary="s"):
    return Finding(title="t", summary=summary, evidence=[
        Evidence(path="a.py", start_line=line, end_line=line, quote="x")])


def test_scanner_agreement_decides_the_tier():
    agreed, alone, hedged = at(10), at(40), at(41, "An attacker could potentially do this")
    _assign_tiers([agreed, alone, hedged], scanner=[at(12)])
    assert [f.tier for f in (agreed, alone, hedged)] == [Tier.SUPPORTED, Tier.SUSPECTED, Tier.SUSPECTED]
    wording = [next(c for c in f.checks if c.name == "wording").passed for f in (agreed, alone, hedged)]
    assert wording == [True, True, False]


def test_without_a_scanner_nothing_is_supported():
    f = at(10)
    _assign_tiers([f], scanner=None)
    assert f.tier == Tier.SUSPECTED


def test_hedged_findings_are_listed_last_within_a_tier():
    findings = [at(1, "This might be reachable"), at(2, "User input reaches the query")]
    _assign_tiers(findings, scanner=None)
    assert [f.id for f in sort_findings(findings)] == ["F002", "F001"]
