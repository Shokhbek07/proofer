"""Fetch the real-world benchmark: each fix commit and its parent, as two trees.

Usage:
    uv run python scripts/fetch_realworld.py [--truth bench/truth/realworld.yaml]

For every item it writes bench/external/realworld/<id>/vulnerable (the parent
commit), .../fixed (the fix commit) and .../changes.json (the lines of the
vulnerable version the fix changed). Repositories are fetched two commits deep
from GitHub and are only read as text afterwards; nothing in them is run.
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

from proofer.realworld import RealTruth, item_dir, parse_ranges


def git(repo: Path, *args: str, binary: bool = False) -> str | bytes:
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True)
    return out.stdout if binary else out.stdout.decode()


def extract(repo: Path, commit: str, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    data = git(repo, "archive", "--format=tar", commit, binary=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(dest, filter="data")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--truth", default="bench/truth/realworld.yaml")
    parser.add_argument("--dest", default="bench/external/realworld")
    args = parser.parse_args()
    truth = RealTruth.load(args.truth)
    dest = Path(args.dest)
    cache = dest / ".repos"
    for item in truth.items:
        out = item_dir(dest, item)
        if (out / "changes.json").is_file():
            print(f"{item.id}: already fetched")
            continue
        repo = cache / item.repo.replace("/", "__")
        if not (repo / ".git").is_dir():
            repo.mkdir(parents=True, exist_ok=True)
            git(repo, "init", "-q")
            git(repo, "remote", "add", "origin", f"https://github.com/{item.repo}.git")
        git(repo, "fetch", "-q", "--depth", "2", "origin", item.fix)
        parent = git(repo, "rev-parse", f"{item.fix}^").strip()
        extract(repo, parent, out / "vulnerable")
        extract(repo, item.fix, out / "fixed")
        missing = [f for f in item.files if not (out / "vulnerable" / f).is_file()]
        if missing:
            raise SystemExit(f"{item.id}: not in the vulnerable version: {missing}")
        # Whitespace-only edits (a reformatted block next to the fix) are not
        # where the weakness is, so they do not count as changed lines.
        diff = git(repo, "diff", "-U0", "--ignore-all-space", parent, item.fix, "--", *item.files)
        (out / "changes.json").write_text(json.dumps(
            {"fix": item.fix, "parent": parent, "ranges": parse_ranges(diff)}, indent=2
        ))
        print(f"{item.id}: {item.repo} {parent[:10]}..{item.fix[:10]}")


if __name__ == "__main__":
    main()
