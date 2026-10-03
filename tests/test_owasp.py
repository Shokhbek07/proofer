from proofer.findings import Evidence, Finding
from proofer.owasp import (
    Case,
    flags_case,
    materialise_cases,
    neutralise,
    score_cases,
    split,
)

HEADER = "'''\nOWASP Benchmark for Python v0.1\n\nLicence text.\n'''\n\n"
BODY = (
    "from flask import request\n"
    "def init(app):\n"
    "\t@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])\n"
    "\tdef BenchmarkTest00001_get():\n"
    "\t\treturn render_template('web/pathtraver-00/BenchmarkTest00001.html')\n"
)


def test_neutralise_removes_header_and_category_names():
    out = neutralise(HEADER + BODY)
    assert out.startswith("from flask import request")
    assert "pathtraver" not in out
    assert "/benchmark/cases/BenchmarkTest00001" in out and "web/cases/BenchmarkTest00001.html" in out


def test_materialise_writes_cases_and_helpers(tmp_path):
    bench = tmp_path / "bench"
    (bench / "testcode").mkdir(parents=True)
    (bench / "helpers" / "resources").mkdir(parents=True)
    (bench / "helpers" / "utils.py").write_text("def escape_for_html(v):\n    return v\n")
    (bench / "helpers" / "resources" / "x.txt").write_text("data")
    (bench / "testcode" / "BenchmarkTest00001.py").write_text(HEADER + BODY)
    case = Case("BenchmarkTest00001", "pathtraver", True, 22)
    materialise_cases(bench, tmp_path / "out", [case])
    assert "pathtraver" not in (tmp_path / "out" / case.path).read_text()
    assert (tmp_path / "out" / "helpers" / "utils.py").is_file()
    assert not (tmp_path / "out" / "helpers" / "resources").exists()


def test_split_is_stratified_disjoint_and_repeatable():
    cases = [Case(f"T{i:03d}", cat, real, 1)
             for cat in ("xss", "sqli") for real in (True, False) for i in range(30)]
    cases = [Case(f"{c.category}-{c.real}-{c.name}", c.category, c.real, 1) for c in cases]
    train, holdout = split(cases, per_group_train=10, per_group_holdout=4)
    assert len(train) == 40 and len(holdout) == 16
    assert not {c.name for c in train} & {c.name for c in holdout}
    assert split(cases, 10, 4) == (train, holdout)
    small = [Case(f"s{i}", "xxe", True, 611) for i in range(5)]
    train, holdout = split(small, 10, 4)
    assert len(holdout) == 1 and len(train) == 4


def finding(path, cwe):
    return Finding(title="t", summary="s", cwe=cwe,
                   evidence=[Evidence(path=path, start_line=1, end_line=1, quote="x")])


def test_flags_and_score():
    real = Case("A", "sqli", True, 89)
    fake = Case("B", "sqli", False, 89)
    assert flags_case([finding("testcode/A.py", "CWE-564")], real)       # sibling class counts
    assert not flags_case([finding("testcode/A.py", "CWE-79")], real)    # other class does not
    assert not flags_case([finding("testcode/B.py", "CWE-89")], real)    # other file does not
    s = score_cases({"A": True, "B": True}, [real, fake])
    assert (s["tpr"], s["fpr"], s["score"]) == (1.0, 1.0, 0.0)
