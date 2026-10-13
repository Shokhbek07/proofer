"""Real security fixes from open-source projects, scored as vulnerable and fixed pairs.

Each item is one published advisory with its fix commit. The repository is
fetched at the fix and at its parent by `scripts/fetch_realworld.py`, which
also records which lines of the vulnerable version the fix changed. Only the
files the fix changed are reviewed, but the whole repository is present, so
the project map can draw on it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .bench import TruthError
from .findings import Finding, Tier

SLACK = 3  # lines either side of a changed range that still count as the place


@dataclass
class RealItem:
    id: str
    repo: str
    fix: str
    cwe: list[str]
    files: list[str]
    group: str = ""
    published: str = ""
    note: str = ""


@dataclass
class RealTruth:
    target: str
    items: list[RealItem] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> RealTruth:
        raw = yaml.safe_load(Path(path).read_text())
        items = [
            RealItem(
                id=r["id"], repo=r["repo"], fix=r["fix"], cwe=list(r["cwe"]),
                files=list(r["files"]), group=r.get("group", ""),
                published=str(r.get("published", "")),
                note=r.get("note", ""),
            )
            for r in raw.get("items", [])
        ]
        if len({i.id for i in items}) != len(items):
            raise TruthError("duplicate item id")
        return cls(raw["target"], items)


def item_dir(source: Path, item: RealItem) -> Path:
    return source / item.id


def load_changes(source: Path, item: RealItem) -> dict[str, list[tuple[int, int]]]:
    """Line ranges of the vulnerable version that the fix changed, per file."""
    path = item_dir(source, item) / "changes.json"
    if not path.is_file():
        raise TruthError(f"{item.id}: not fetched (run scripts/fetch_realworld.py)")
    raw = json.loads(path.read_text())
    return {f: [tuple(r) for r in ranges] for f, ranges in raw["ranges"].items()}


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")


def parse_ranges(diff: str) -> dict[str, list[tuple[int, int]]]:
    """Old-side line ranges from a `git diff -U0` listing.

    A pure insertion (`-a,0`) is placed between lines a and a + 1: that is
    where the missing check belonged.
    """
    ranges: dict[str, list[tuple[int, int]]] = {}
    current = None
    for line in diff.splitlines():
        if line.startswith("--- "):
            name = line[4:].strip()
            current = name[2:] if name.startswith("a/") else None
            if current:
                ranges.setdefault(current, [])
            continue
        m = _HUNK.match(line)
        if m and current:
            start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
            ranges[current].append((start, start + 1) if count == 0 else (start, start + count - 1))
    return ranges


def _in_class(finding: Finding, item: RealItem) -> bool:
    return finding.tier != Tier.REJECTED and finding.cwe in item.cwe


def _touches(finding: Finding, file: str, spans: list[tuple[int, int]]) -> bool:
    return any(
        ev.path == file and ev.start_line <= end + SLACK and ev.end_line >= start - SLACK
        for ev in finding.evidence
        for start, end in spans
    )


def score_item(
    vulnerable: list[Finding],
    fixed: list[Finding],
    item: RealItem,
    changes: dict[str, list[tuple[int, int]]],
) -> dict[str, object]:
    """Detection in the right file and class, at the changed lines, and on the fix."""
    files = set(item.files)

    def in_files(f: Finding) -> bool:
        return any(ev.path in files for ev in f.evidence)

    hits = [f for f in vulnerable if _in_class(f, item) and in_files(f)]
    at_change = [f for f in hits if any(_touches(f, path, changes.get(path, [])) for path in files)]
    still = [f for f in fixed if _in_class(f, item) and in_files(f)]
    return {
        "id": item.id,
        "detected": bool(hits),
        "detected_at_change": bool(at_change),
        "fixed_flagged": bool(still),
        "pair_correct": bool(hits) and not still,
        "other_findings_vulnerable": sum(1 for f in vulnerable if in_files(f) and f not in hits),
        "other_findings_fixed": sum(1 for f in fixed if in_files(f) and f not in still),
    }
