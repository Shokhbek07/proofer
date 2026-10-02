import pytest

from proofer.evidence import check_evidence, locate
from proofer.findings import Evidence, Finding
from proofer.workspace import Workspace, WorkspaceError


@pytest.fixture
def ws(tmp_path):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "db.py").write_text(
        "import sqlite3\n"
        "\n"
        "def find(conn, name):\n"
        "    q = \"SELECT * FROM users WHERE name = '%s'\" % name\n"
        "    return conn.execute(q).fetchall()\n"
    )
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "x.js").write_text("execute(q)\n")
    (tmp_path / "outside.txt").write_text("secret\n")
    (repo / "link").symlink_to(tmp_path / "outside.txt")
    return Workspace(repo)


def finding(*evidence):
    return Finding(title="t", summary="s", evidence=list(evidence))


def test_paths_cannot_escape_root(ws):
    for bad in ("../outside.txt", "/etc/passwd", "app/../../outside.txt", "link"):
        with pytest.raises(WorkspaceError):
            ws.lines(bad)


def test_listing_skips_vendored_dirs_and_symlinks(ws):
    assert ws.files() == ["app/db.py"]


def test_grep_reports_line_numbers(ws):
    hits = ws.grep(r"execute\(")
    assert [(h.path, h.line) for h in hits] == [("app/db.py", 5)]


def test_grep_rejects_bad_regex(ws):
    with pytest.raises(WorkspaceError):
        ws.grep("(")


def test_read_numbers_lines(ws):
    assert ws.read("app/db.py", 3, 3) == "3| def find(conn, name):"


def test_exact_citation_passes(ws):
    f = finding(Evidence(path="app/db.py", start_line=5, end_line=5,
                         quote="return conn.execute(q).fetchall()"))
    check = check_evidence(ws, f)
    assert check.passed and check.detail == ""


def test_wrong_line_numbers_are_corrected(ws):
    f = finding(Evidence(path="app/db.py", start_line=40, end_line=41,
                         quote="  q = \"SELECT * FROM users WHERE name = '%s'\" % name\n\n"
                               "return conn.execute(q).fetchall()"))
    check = check_evidence(ws, f)
    assert check.passed
    assert (f.evidence[0].start_line, f.evidence[0].end_line) == (4, 5)


def test_invented_code_fails(ws):
    f = finding(Evidence(path="app/db.py", start_line=5, end_line=5,
                         quote="os.system(name)"))
    assert not check_evidence(ws, f).passed


def test_missing_file_and_empty_evidence_fail(ws):
    f = finding(Evidence(path="app/nope.py", start_line=1, end_line=1, quote="x"))
    assert not check_evidence(ws, f).passed
    assert not check_evidence(ws, finding()).passed


def test_locate_needs_consecutive_lines():
    lines = ["a = 1", "b = 2", "c = 3"]
    assert locate(lines, "a = 1\nc = 3") is None
    assert locate(lines, "b = 2\nc = 3") == (2, 3)


def test_line_number_gutter_in_quote_is_tolerated(ws):
    f = finding(Evidence(path="app/db.py", start_line=5, end_line=5,
                         quote="5|     return conn.execute(q).fetchall()"))
    assert check_evidence(ws, f).passed


def test_bad_citations_are_dropped_but_a_good_one_keeps_the_finding(ws):
    good = Evidence(path="app/db.py", start_line=5, end_line=5,
                    quote="return conn.execute(q).fetchall()")
    f = finding(good, good, Evidence(path="app/db.py", start_line=1, end_line=1, quote="eval(x)"))
    check = check_evidence(ws, f)
    assert check.passed and len(f.evidence) == 1
    assert "2 unverifiable or duplicate citations removed" in check.detail


def test_cwe_is_normalised():
    for raw in ("89", "CWE-89", "cwe-089: SQL Injection", 89):
        assert Finding(title="t", summary="s", cwe=raw).cwe == "CWE-89"
    assert Finding(title="t", summary="s", cwe="").cwe is None
