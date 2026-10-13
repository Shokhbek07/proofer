import json

from proofer.cli import main
from proofer.findings import Evidence, Finding
from proofer.realworld import RealItem, parse_ranges, score_item

DIFF = """diff --git a/app/views.py b/app/views.py
--- a/app/views.py
+++ b/app/views.py
@@ -10,2 +10,2 @@ def show(request):
-    return HttpResponse("<p>" + name)
-    # done
+    return HttpResponse("<p>" + escape(name))
+    # done
@@ -40,0 +41,2 @@ def delete(request, pk):
+    if obj.owner != request.user:
+        raise PermissionDenied
--- /dev/null
+++ b/app/new.py
@@ -0,0 +1 @@
+x = 1
"""


def finding(line, cwe="CWE-79", path="app/views.py"):
    return Finding(title="t", cwe=cwe, summary="s", origin="model",
                   evidence=[Evidence(path=path, start_line=line, end_line=line,
                                      quote="q", role="sink")])


def test_old_side_ranges_include_insertions():
    assert parse_ranges(DIFF) == {"app/views.py": [(10, 11), (40, 41)]}


def test_score_item_by_file_class_place_and_fix():
    item = RealItem("X-1", "o/r", "abc", ["CWE-79", "CWE-80"], ["app/views.py"])
    changes = {"app/views.py": [(10, 11), (40, 41)]}
    row = score_item([finding(12), finding(100, cwe="CWE-89")], [], item, changes)
    assert row["detected"] and row["detected_at_change"] and row["pair_correct"]
    assert row["other_findings_vulnerable"] == 1
    far = score_item([finding(80)], [finding(11)], item, changes)
    assert far["detected"] and not far["detected_at_change"]
    assert far["fixed_flagged"] and not far["pair_correct"]
    elsewhere = score_item([finding(12, path="app/other.py")], [], item, changes)
    assert not elsewhere["detected"]


def test_eval_real_end_to_end_without_a_model(tmp_path, capsys):
    source = tmp_path / "src"
    for side, line in (("vulnerable", "os.system('ping ' + request.args['h'])"),
                       ("fixed", "subprocess.run(['ping', request.args['h']])")):
        tree = source / "CASE-1" / side / "app"
        tree.mkdir(parents=True)
        (tree / "net.py").write_text(f"import os, subprocess\n\ndef ping(request):\n    {line}\n")
    (source / "CASE-1" / "changes.json").write_text(
        json.dumps({"fix": "abc", "parent": "def", "ranges": {"app/net.py": [[4, 4]]}})
    )
    truth = tmp_path / "truth.yaml"
    truth.write_text(
        "target: realworld\nitems:\n"
        "  - id: CASE-1\n    repo: o/r\n    fix: abc\n    cwe: [CWE-78]\n    files: [app/net.py]\n"
    )
    out = tmp_path / "out"
    code = main(["eval-real", "--mode", "patterns", "--source", str(source),
                 "--truth", str(truth), "--out", str(out)])
    assert code == 0
    summary = json.loads(next(out.glob("realworld-*.json")).read_text())["summary"]
    # The pattern baseline flags the shell call before the fix and the subprocess
    # call after it, so the pair is not counted as correct.
    assert summary["detected"] == 1.0 and summary["detected_at_change"] == 1.0
    assert summary["fixed_flagged"] == 1.0 and summary["pair_accuracy"] == 0.0
