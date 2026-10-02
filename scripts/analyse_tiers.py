"""Which cheap signals separate true findings from false ones?

Reads saved evaluation runs on the seeded benchmark, labels every finding
against ground truth, and reports precision with and without each signal.
Usage: uv run python scripts/analyse_tiers.py runs/eval/<file>.json [more files]
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from proofer.bench import Truth, materialise, score
from proofer.external import same_place, semgrep_findings
from proofer.findings import Finding
from proofer.judge import has_dataflow, plain_wording
from proofer.workspace import Workspace

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "bench" / "targets" / "bakery"
TRUTH = Truth.load(ROOT / "bench" / "truth" / "bakery.yaml")
ALL_IDS = {w.id for w in TRUTH.weaknesses}


def labelled(findings: list[Finding], root: Path, patched: set[str]) -> list[tuple[Finding, bool]]:
    s = score(findings, root, TRUTH, patched)
    true_ids = {fid for ids in s.found.values() for fid in ids}
    return [(f, f.id in true_ids) for f in findings]


def main(paths: list[str]) -> None:
    rows: list[tuple[bool, dict[str, bool]]] = []
    with tempfile.TemporaryDirectory() as tmp:
        twin = Path(tmp) / "bakery"
        materialise(TARGET, twin, TRUTH, ALL_IDS)
        semgrep = {"vulnerable": semgrep_findings(Workspace(TARGET)),
                   "patched": semgrep_findings(Workspace(twin))}
        for path in paths:
            for run in json.loads(Path(path).read_text())["runs"]:
                for side, root, patched in (("vulnerable", TARGET, set()), ("patched", twin, ALL_IDS)):
                    findings = [Finding(**raw) for raw in run[f"findings_{side}"]]
                    for f, is_true in labelled(findings, root, patched):
                        rows.append((is_true, {
                            "semgrep agrees": same_place(f, semgrep[side]),
                            "no hedging words": plain_wording(f).passed,
                            "cites both ends": has_dataflow(f).passed,
                            "severity high or critical": f.severity.value in ("high", "critical"),
                        }))

    total, true = len(rows), sum(t for t, _ in rows)
    print(f"{total} findings, {true} true, {total - true} false, precision {true / total:.3f}")
    print(f"{'signal':28} {'with: n':>8} {'precision':>10} {'without: n':>11} {'precision':>10} {'true kept':>10}")
    for name in rows[0][1]:
        on = [t for t, sig in rows if sig[name]]
        off = [t for t, sig in rows if not sig[name]]
        p_on = sum(on) / len(on) if on else float("nan")
        p_off = sum(off) / len(off) if off else float("nan")
        print(f"{name:28} {len(on):>8} {p_on:>10.3f} {len(off):>11} {p_off:>10.3f} {sum(on) / true:>10.3f}")


if __name__ == "__main__":
    main(sys.argv[1:])
