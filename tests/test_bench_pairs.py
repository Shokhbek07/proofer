import pytest

from proofer.bench import (
    Module,
    PairTruth,
    TruthError,
    flagged_modules,
    materialise_pairs,
)
from proofer.findings import Evidence, Finding, Tier

TRUTH = PairTruth("lab", "vulnerabilities", "source/low.php", "source/impossible.php",
                  [Module("sqli", ["CWE-89"]), Module("exec", ["CWE-78"])])


def lab(tmp_path, modules=("sqli", "exec")):
    for m in modules:
        src = tmp_path / "lab" / "vulnerabilities" / m / "source"
        src.mkdir(parents=True)
        (src / "low.php").write_text(f"<?php // {m} low\n")
        (src / "impossible.php").write_text(f"<?php // {m} impossible\n")
    return tmp_path / "lab"


def finding(path, cwe, tier=Tier.SUSPECTED):
    return Finding(title="t", summary="s", cwe=cwe, tier=tier,
                   evidence=[Evidence(path=path, start_line=1, end_line=1, quote="x")])


def test_pairs_are_copied_under_neutral_names(tmp_path):
    vulnerable, secure = materialise_pairs(lab(tmp_path), tmp_path / "out", TRUTH)
    assert (vulnerable / "sqli" / "handler.php").read_text() == "<?php // sqli low\n"
    assert (secure / "exec" / "handler.php").read_text() == "<?php // exec impossible\n"
    names = {p.name for p in (tmp_path / "out").rglob("*.php")}
    assert names == {"handler.php"}


def test_missing_module_is_an_error(tmp_path):
    with pytest.raises(TruthError):
        materialise_pairs(lab(tmp_path, modules=("sqli",)), tmp_path / "out", TRUTH)


def test_only_findings_of_the_module_class_count():
    findings = [
        finding("sqli/handler.php", "CWE-89"),
        finding("sqli/handler.php", "CWE-327"),             # other class
        finding("exec/handler.php", "CWE-89"),              # wrong class for this module
        finding("exec/handler.php", "CWE-78", Tier.REJECTED),
    ]
    flagged, other = flagged_modules(findings, TRUTH)
    assert flagged == {"sqli"} and other == 2
