"""Build fine-tuning data: the large model writes reviews, the answer key filters them.

Usage:
    uv run python experiments/finetune/build_dataset.py [--limit N]

Resumable: teacher answers are appended to data/finetune/teacher.jsonl and
cases already present there are skipped.
"""

from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path

from pydantic import ValidationError

from proofer.evidence import _GUTTER, check_evidence
from proofer.findings import Evidence, Finding
from proofer.judge import (
    SYSTEM_PROMPT,
    TRUST_BOUNDARY,
    WALKTHROUGH_SCHEMA,
    build_prompt,
)
from proofer.leads import find_leads
from proofer.llm import OllamaClient
from proofer.llm_mlx import with_format_note
from proofer.owasp import Case, load_cases, materialise_cases, split
from proofer.workspace import Workspace

LABELS = {
    "pathtraver": "path traversal",
    "cmdi": "OS command injection",
    "codeinj": "code injection",
    "deserialization": "unsafe deserialisation",
    "hash": "weak hash algorithm",
    "ldapi": "LDAP injection",
    "redirect": "open redirect",
    "securecookie": "cookie sent without the Secure flag",
    "sqli": "SQL injection",
    "trustbound": "trust boundary violation, untrusted data stored in the session",
    "weakrand": "weak random number generator",
    "xpathi": "XPath injection",
    "xss": "cross-site scripting",
    "xxe": "XML external entity processing",
}
# Handler names contain the word "Benchmark", so only phrases about the key itself count.
MENTIONS_KEY = re.compile(
    r"answer key|ground truth|according to the (key|label)|is labell?ed|as instructed", re.IGNORECASE
)
FINDING_KEYS = ("title", "cwe", "severity", "summary", "reasoning", "remediation")
EVIDENCE_KEYS = ("path", "start_line", "end_line", "quote", "role")


def hint(case: Case) -> str:
    what = f"CWE-{case.cwe} ({LABELS[case.category]})"
    if case.real:
        return (
            f"Answer key for this file, which you must not mention: it contains one real "
            f"weakness of class {what}. Report that weakness, quoting the exact lines, "
            "and report nothing else."
        )
    return (
        f"Answer key for this file, which you must not mention: it does NOT contain a real "
        f"weakness of class {what}; something in the code makes it safe. Say in the analysis "
        "what makes it safe, and return an empty findings list."
    )


def target_from(raw: dict, case: Case, ws: Workspace) -> tuple[dict | None, str]:
    """Turn a teacher answer into a training target, or say why it is rejected."""
    analysis = [a for a in raw.get("analysis", []) if isinstance(a, str) and a.strip()]
    if not analysis:
        return None, "no analysis"
    if any(MENTIONS_KEY.search(a) for a in analysis):
        return None, "mentions the answer key"
    if not case.real:
        return {"analysis": analysis, "findings": []}, "ok"

    kept = []
    for item in raw.get("findings", []):
        try:
            finding = Finding(**{**item, "evidence": [Evidence(**e) for e in item.get("evidence", [])]})
        except (ValidationError, TypeError):
            continue
        if finding.cwe not in case.classes or not check_evidence(ws, finding).passed:
            continue
        text = " ".join(str(item.get(k, "")) for k in ("summary", "reasoning"))
        if MENTIONS_KEY.search(text):
            continue
        dumped = finding.model_dump(mode="json")
        kept.append({
            **{k: dumped[k] for k in FINDING_KEYS},
            # The teacher copies the line-number gutter into quotes; the student should not.
            "evidence": [
                {**{k: ev[k] for k in EVIDENCE_KEYS},
                 "quote": "\n".join(_GUTTER.sub("", ln) for ln in ev["quote"].splitlines())}
                for ev in dumped["evidence"]
            ],
        })
    if not kept:
        return None, "no verified finding of the labelled class"
    return {"analysis": analysis, "findings": kept[:2]}, "ok"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", default="bench/external/BenchmarkPython")
    parser.add_argument("--tree", default="data/cache/owasp_tree")
    parser.add_argument("--out", default="data/finetune")
    parser.add_argument("--teacher", default="gemma4:26b-a4b-it-qat")
    parser.add_argument("--per-group-train", type=int, default=14)
    parser.add_argument("--per-group-holdout", type=int, default=5)
    parser.add_argument("--limit", type=int, default=None, help="Label only the first N cases.")
    args = parser.parse_args()

    benchmark, tree, out = Path(args.benchmark), Path(args.tree), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    train, holdout = split(load_cases(benchmark), args.per_group_train, args.per_group_holdout)
    materialise_cases(benchmark, tree, train + holdout)
    ws = Workspace(tree)
    leads = {lead.path: lead for lead in find_leads(ws)}
    system = SYSTEM_PROMPT + TRUST_BOUNDARY

    teacher_file = out / "teacher.jsonl"
    done = {}
    if teacher_file.exists():
        for line in teacher_file.read_text().splitlines():
            row = json.loads(line)
            done[row["name"]] = row

    client = OllamaClient(args.teacher, think=False, max_tokens=2500)
    todo = [c for c in train if c.name not in done][: args.limit]
    with teacher_file.open("a") as handle:
        for i, case in enumerate(todo, start=1):
            prompt = build_prompt(ws, leads[case.path], "walkthrough")
            result = client.chat(
                [{"role": "system", "content": system},
                 {"role": "user", "content": f"{prompt}\n\n{hint(case)}"}],
                schema=WALKTHROUGH_SCHEMA,
            )
            try:
                target, why = target_from(json.loads(result.content), case, ws)
            except json.JSONDecodeError:
                target, why = None, "invalid JSON"
            row = {"name": case.name, "category": case.category, "real": case.real,
                   "status": why, "prompt": prompt, "target": target,
                   "raw": result.content if target is None else "",
                   "seconds": round(result.seconds, 1)}
            done[case.name] = row
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            handle.flush()
            print(f"[{i}/{len(todo)}] {case.name} {case.category} real={case.real}: {why} "
                  f"({result.seconds:.0f}s)", flush=True)

    accepted = [done[c.name] for c in train if c.name in done and done[c.name]["target"]]
    random.Random(7).shuffle(accepted)
    n_valid = max(1, len(accepted) // 10)

    def record(row: dict) -> str:
        messages = with_format_note(
            [{"role": "system", "content": system}, {"role": "user", "content": row["prompt"]}],
            WALKTHROUGH_SCHEMA,
        )
        messages.append({"role": "assistant",
                         "content": json.dumps(row["target"], ensure_ascii=False)})
        return json.dumps({"messages": messages}, ensure_ascii=False)

    (out / "valid.jsonl").write_text("\n".join(record(r) for r in accepted[:n_valid]) + "\n")
    (out / "train.jsonl").write_text("\n".join(record(r) for r in accepted[n_valid:]) + "\n")
    reasons: dict[str, int] = {}
    for c in train:
        if c.name in done:
            reasons[done[c.name]["status"]] = reasons.get(done[c.name]["status"], 0) + 1
    summary = {
        "train_cases": len(train), "labelled": sum(c.name in done for c in train),
        "accepted": len(accepted), "train_examples": len(accepted) - n_valid,
        "valid_examples": n_valid, "status_counts": reasons,
        "accepted_real": sum(r["real"] for r in accepted),
        "holdout": [c.name for c in holdout],
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "holdout"}, indent=2))


if __name__ == "__main__":
    main()
