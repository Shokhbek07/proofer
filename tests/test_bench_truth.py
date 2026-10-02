"""The seeded target and its ground truth must stay consistent."""

import py_compile
import shutil
import subprocess
from pathlib import Path

import pytest

from proofer.bench import Truth, materialise, region, score
from proofer.findings import Evidence, Finding

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "bench" / "targets" / "bakery"
TRUTH = Truth.load(ROOT / "bench" / "truth" / "bakery.yaml")
ALL_IDS = {w.id for w in TRUTH.weaknesses}


def finding(fid, path, line, cwe=None):
    return Finding(id=fid, title="t", summary="s", cwe=cwe,
                   evidence=[Evidence(path=path, start_line=line, end_line=line, quote="x")])


def line_of(root, item):
    lo, hi = region(root, item)
    return (lo + hi) // 2


def test_every_anchor_resolves_in_the_vulnerable_tree():
    for item in TRUTH.weaknesses + TRUTH.decoys:
        assert region(TARGET, item) is not None, item.id


def test_ids_are_unique():
    ids = [i.id for i in TRUTH.weaknesses + TRUTH.decoys]
    assert len(ids) == len(set(ids))


@pytest.fixture(scope="module")
def patched(tmp_path_factory):
    dest = tmp_path_factory.mktemp("twin") / "bakery"
    materialise(TARGET, dest, TRUTH, ALL_IDS)
    return dest


def test_patched_twin_is_valid_code(patched):
    for path in patched.rglob("*.py"):
        py_compile.compile(str(path), doraise=True)
    if shutil.which("node"):
        for path in patched.rglob("*.js"):
            subprocess.run(["node", "--check", str(path)], check=True)


def test_patched_twin_removes_every_vulnerable_snippet(patched):
    for w in TRUTH.weaknesses:
        for step in w.fix:
            if step["old"].strip() and step["old"] not in step["new"]:
                text = (patched / step.get("file", w.file)).read_text()
                assert step["old"] not in text, w.id


def test_each_weakness_can_be_patched_alone(tmp_path):
    for w in TRUTH.weaknesses:
        materialise(TARGET, tmp_path / w.id, TRUTH, {w.id})


def test_decoys_survive_patching(patched):
    for d in TRUTH.decoys:
        assert region(patched, d) is not None, d.id


def test_scoring_on_vulnerable_tree():
    v01, d01 = TRUTH.weaknesses[0], TRUTH.decoys[0]
    findings = [
        finding("F1", v01.file, line_of(TARGET, v01), "CWE-89"),
        finding("F2", v01.file, line_of(TARGET, v01), "CWE-89"),   # duplicate
        finding("F3", d01.file, line_of(TARGET, d01), "CWE-89"),   # decoy
        finding("F4", "orders-api/app/db.py", 1, "CWE-000"),       # nowhere
    ]
    s = score(findings, TARGET, TRUTH, patched=set())
    assert s.found == {"V01": ["F1", "F2"]}
    assert s.decoy_hits == {"D01": ["F3"]}
    assert s.unlisted == ["F4"]
    assert s.recall == pytest.approx(1 / len(TRUTH.weaknesses))
    assert s.precision == pytest.approx(1 / 3)


def test_reporting_a_fixed_weakness_is_a_false_positive(patched):
    for w in TRUTH.weaknesses:
        item = w.as_patched()
        span = region(patched, item)
        assert span is not None, f"{w.id}: patched location is ambiguous"
        f = finding("F1", item.file, (span[0] + span[1]) // 2, w.cwe[0])
        s = score([f], patched, TRUTH, patched=ALL_IDS)
        assert list(s.patched_hits) == [w.id] and not s.found


def test_planted_note_reaches_every_weak_file_and_keeps_truth_resolvable(tmp_path):
    from proofer.bench import PLANTED_NOTE, plant_instructions
    dest = tmp_path / "bakery"
    materialise(TARGET, dest, TRUTH, set())
    touched = plant_instructions(dest, TRUTH)
    assert set(touched) == {w.file for w in TRUTH.weaknesses}
    for rel in touched:
        assert PLANTED_NOTE in (dest / rel).read_text().splitlines()[0]
    for item in TRUTH.weaknesses + TRUTH.decoys:
        assert region(dest, item) is not None, item.id
    for path in dest.rglob("*.py"):
        py_compile.compile(str(path), doraise=True)
