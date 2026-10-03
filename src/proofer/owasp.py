"""OWASP Benchmark for Python as a labelled case set.

Each test case is one small Flask handler that either contains a real weakness
of a known class or a safe look-alike. The benchmark is GPL-3.0 and is fetched
by `scripts/fetch_owasp_python.sh`, not vendored.
"""

from __future__ import annotations

import csv
import random
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .findings import Finding, Tier

# The answer key gives one CWE per category. Models often name a sibling, so a
# finding counts for the category when its CWE is in the matching set.
CLASSES: dict[str, set[int]] = {
    "pathtraver": {22, 23, 36, 73, 98},
    "cmdi": {78, 77, 88},
    "codeinj": {94, 95, 96},
    "deserialization": {502},
    "hash": {328, 327, 326, 916},
    "ldapi": {90},
    "redirect": {601},
    "securecookie": {614, 1004, 319, 311},
    "sqli": {89, 564},
    "trustbound": {501},
    "weakrand": {330, 331, 335, 336, 337, 338},
    "xpathi": {643, 91},
    "xss": {79, 80, 116},
    "xxe": {611, 776, 827},
}

_HEADER = re.compile(r"\A\s*'''.*?'''\s*\n", re.DOTALL)
# Route and template paths spell out the category, which would tell the model
# which weakness class to look for.
_CATEGORY_PATH = re.compile(r"(/benchmark/|web/)[a-z]+-\d+/")


@dataclass(frozen=True)
class Case:
    name: str
    category: str
    real: bool
    cwe: int

    @property
    def path(self) -> str:
        return f"testcode/{self.name}.py"

    @property
    def classes(self) -> set[str]:
        return {f"CWE-{n}" for n in CLASSES[self.category] | {self.cwe}}


def load_cases(benchmark: Path) -> list[Case]:
    cases: list[Case] = []
    with (benchmark / "expectedresults-0.1.csv").open() as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#"):
                continue
            name, category, real, cwe = (cell.strip() for cell in row[:4])
            cases.append(Case(name, category, real == "true", int(cwe)))
    return cases


def neutralise(source: str) -> str:
    """Drop the licence header and the category names embedded in paths."""
    text = _CATEGORY_PATH.sub(r"\1cases/", _HEADER.sub("", source, count=1))
    return text.replace("executing cmdi", "executing command")


def materialise_cases(benchmark: Path, dest: Path, cases: list[Case]) -> None:
    """Write the chosen cases, neutralised, next to the shared helpers they import."""
    if dest.exists():
        shutil.rmtree(dest)
    (dest / "testcode").mkdir(parents=True)
    shutil.copytree(benchmark / "helpers", dest / "helpers",
                    ignore=shutil.ignore_patterns("resources", "__pycache__"))
    for case in cases:
        text = (benchmark / "testcode" / f"{case.name}.py").read_text()
        (dest / case.path).write_text(neutralise(text))


def split(
    cases: list[Case], per_group_train: int, per_group_holdout: int, seed: int = 7
) -> tuple[list[Case], list[Case]]:
    """Stratified split by category and label; small groups give at most a third to holdout."""
    rng = random.Random(seed)
    groups: dict[tuple[str, bool], list[Case]] = {}
    for case in sorted(cases, key=lambda c: c.name):
        groups.setdefault((case.category, case.real), []).append(case)
    train: list[Case] = []
    holdout: list[Case] = []
    for key in sorted(groups):
        members = groups[key]
        rng.shuffle(members)
        n_hold = min(per_group_holdout, len(members) // 3)
        holdout += members[:n_hold]
        train += members[n_hold:n_hold + per_group_train]
    return train, holdout


def flags_case(findings: list[Finding], case: Case) -> bool:
    """Did the review report the case's weakness class in the case's file?"""
    return any(
        f.tier != Tier.REJECTED and f.cwe in case.classes
        and any(ev.path == case.path for ev in f.evidence)
        for f in findings
    )


def score_cases(flagged: dict[str, bool], cases: list[Case]) -> dict[str, float | int]:
    """True-positive rate, false-positive rate and their difference, as OWASP scores it."""
    real = [c for c in cases if c.real]
    fake = [c for c in cases if not c.real]
    tp = sum(flagged[c.name] for c in real)
    fp = sum(flagged[c.name] for c in fake)
    tpr = tp / len(real) if real else 0.0
    fpr = fp / len(fake) if fake else 0.0
    return {
        "real": len(real), "fake": len(fake), "true_positives": tp, "false_positives": fp,
        "tpr": round(tpr, 3), "fpr": round(fpr, 3), "score": round(tpr - fpr, 3),
    }
