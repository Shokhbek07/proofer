"""Draw candidates for the real-world benchmark from the GitHub Advisory Database.

Usage:
    uv run python scripts/select_realworld.py [--work data/cache/realworld-selection]

Steps, each cached in --work so a rerun does not query GitHub again:

1. advisories.json: every reviewed advisory published since 2025-01-01 (`gh api graphql`).
2. commits.json: metadata of the fix commit, for advisories in the window that
   cite exactly one GitHub commit.
3. The mechanical filters below, then a seeded random order, one advisory per
   repository, printed per group.

The manual check that follows (web code, the changed file holds the weakness,
file length) and every exclusion are recorded in bench/truth/realworld.yaml.
The selection was made on 2026-10-03, before any model was run on these items.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

WINDOW = ("2026-04-03", "2026-09-30")  # after the Gemma 4 release (2 April 2026)
SEED = 20261003
PER_GROUP = 40  # candidates printed per group; the truth file takes the first that pass

INJECTION = {22, 23, 36, 73, 77, 78, 79, 80, 88, 89, 94, 95, 116, 502, 601, 611, 918, 943, 1321, 1336}
MISSING_CHECK = {20, 284, 285, 287, 288, 290, 306, 346, 352, 639, 862, 863, 1284}

QUERY = """query($cursor:String){ securityAdvisories(first:100, after:$cursor,
  publishedSince:"2025-01-01T00:00:00Z", classifications:[GENERAL],
  orderBy:{field:PUBLISHED_AT, direction:ASC}) {
  pageInfo{hasNextPage endCursor}
  nodes{ ghsaId publishedAt withdrawnAt summary severity
    cwes(first:10){nodes{cweId}} references{url}
    vulnerabilities(first:25){nodes{package{ecosystem name}}} } } }"""
COMMIT_URL = re.compile(r"https://github\.com/([^/]+/[^/]+)/(?:pull/\d+/commits|commit)/([0-9a-f]{7,40})")
TEST_OR_DOC = re.compile(
    r"(^|/)(tests?|spec|__tests__|e2e|docs?|examples?|fixtures?|\.github|\.changeset|"
    r"changelog\.d|newsfragments)(/|$)|(_test|_spec|\.test|\.spec)\.[a-z]+$|(^|/)test_[^/]*$",
    re.IGNORECASE,
)
SOURCE = re.compile(r"\.(py|js|mjs|cjs|ts|tsx|jsx|vue|svelte|html?|jinja2?|j2|ejs|hbs)$", re.IGNORECASE)
COMMIT_FIELDS = (
    "{sha, date:.commit.committer.date, parents:[.parents[].sha], stats, "
    "files:[.files[]|{filename,status,additions,deletions,changes}]}"
)


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def fetch_advisories(path: Path) -> list[dict]:
    if path.is_file():
        return json.loads(path.read_text())
    nodes: list[dict] = []
    cursor = None
    while True:
        args = ["api", "graphql", "-f", f"query={QUERY}"] + (["-f", f"cursor={cursor}"] if cursor else [])
        page = json.loads(gh(*args))["data"]["securityAdvisories"]
        nodes += page["nodes"]
        if not page["pageInfo"]["hasNextPage"]:
            break
        cursor = page["pageInfo"]["endCursor"]
    path.write_text(json.dumps(nodes))
    return nodes


def cwe_numbers(advisory: dict) -> set[int]:
    return {
        int(n["cweId"][4:]) for n in advisory["cwes"]["nodes"]
        if n["cweId"].startswith("CWE-") and n["cweId"][4:].isdigit()
    }


def fix_commits(advisory: dict) -> list[tuple[str, str]]:
    found = {(m.group(1), m.group(2)) for r in advisory["references"] if (m := COMMIT_URL.match(r["url"]))}
    return sorted(found)


def in_scope(advisory: dict) -> bool:
    ecosystems = {v["package"]["ecosystem"] for v in advisory["vulnerabilities"]["nodes"]}
    commits = {(repo.lower(), sha[:12]) for repo, sha in fix_commits(advisory)}
    return (
        WINDOW[0] <= advisory["publishedAt"][:10] <= WINDOW[1]
        and not advisory["withdrawnAt"]
        and bool(ecosystems & {"PIP", "NPM"})
        and bool(cwe_numbers(advisory) & (INJECTION | MISSING_CHECK))
        and len(commits) == 1
    )


def fetch_commits(path: Path, advisories: list[dict]) -> list[dict]:
    """Commit metadata for every in-scope advisory; only missing ones are fetched."""
    cached = {r["ghsa"]: r for r in json.loads(path.read_text())} if path.is_file() else {}
    wanted = [a for a in advisories if in_scope(a)]

    def one(advisory: dict) -> dict:
        repo, sha = fix_commits(advisory)[0]
        try:
            commit = json.loads(gh("api", f"repos/{repo}/commits/{sha}", "--jq", COMMIT_FIELDS))
        except subprocess.CalledProcessError as exc:
            commit = {"error": exc.stderr[:200]}
        return {
            "ghsa": advisory["ghsaId"], "published": advisory["publishedAt"][:10], "repo": repo,
            "sha": sha, "cwes": sorted(cwe_numbers(advisory)), "summary": advisory["summary"],
            "commit": commit,
        }

    with ThreadPoolExecutor(8) as pool:
        fetched = list(pool.map(one, [a for a in wanted if a["ghsaId"] not in cached]))
    cached.update({r["ghsa"]: r for r in fetched})
    rows = [cached[a["ghsaId"]] for a in wanted]
    path.write_text(json.dumps(rows))
    return rows


def candidates(rows: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {"injection": [], "missing check": []}
    usable = []
    for row in rows:
        commit = row["commit"]
        if "error" in commit or len(commit["parents"]) != 1:
            continue
        source = [f for f in commit["files"] if SOURCE.search(f["filename"]) and not TEST_OR_DOC.search(f["filename"])]
        modified = [f for f in source if f["status"] == "modified"]
        if not 1 <= len(source) <= 3 or not modified or sum(f["changes"] for f in source) > 80:
            continue
        usable.append({**row, "files": [f["filename"] for f in modified],
                       "changes": sum(f["changes"] for f in source)})
    rng = random.Random(SEED)
    rng.shuffle(usable)
    seen: set[str] = set()
    for row in usable:
        repo = row["repo"].lower()
        if repo in seen:
            continue
        seen.add(repo)
        group = "injection" if set(row["cwes"]) & INJECTION else "missing check"
        groups[group].append(row)
    return groups


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", default="data/cache/realworld-selection")
    args = parser.parse_args()
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    advisories = fetch_advisories(work / "advisories.json")
    rows = fetch_commits(work / "commits.json", advisories)
    groups = candidates(rows)
    print(f"{len(advisories)} advisories, {len(rows)} in scope with one fix commit")
    for group, items in groups.items():
        print(f"\n## {group}: {len(items)} usable, one per repository; first {PER_GROUP} in seeded order")
        for k, row in enumerate(items[:PER_GROUP], start=1):
            cwes = ",".join(f"CWE-{c}" for c in row["cwes"])
            print(f"{k:>3}. {row['ghsa']} {row['published']} {row['repo']} {cwes} "
                  f"{row['sha'][:12]} changes={row['changes']} files={row['files']}\n"
                  f"     {row['summary'][:150]}")


if __name__ == "__main__":
    main()
