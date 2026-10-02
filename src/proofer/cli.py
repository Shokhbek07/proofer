"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

from .bench import (
    PairTruth,
    Truth,
    TruthError,
    flagged_modules,
    materialise,
    materialise_pairs,
    plant_instructions,
    score,
)
from .external import ScannerError
from .judge import VARIANTS
from .leads import find_leads
from .llm import LLMError, OllamaClient
from .pipeline import MODES, scan
from .report import to_markdown
from .workspace import Workspace, WorkspaceError


def _progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _client(args: argparse.Namespace, seed: int = 7) -> OllamaClient | None:
    if args.mode in ("patterns", "semgrep"):
        return None
    think = {"on": True, "off": False}.get(args.think)
    return OllamaClient(args.model, host=args.host, num_ctx=args.num_ctx, think=think,
                        seed=seed, temperature=args.temperature, max_tokens=args.max_tokens)


def _review_options(args: argparse.Namespace) -> dict[str, object]:
    return {
        "variant": args.prompt,
        "strip_comments": args.strip_comments,
        "trust_boundary": not args.no_trust_boundary,
    }


def _cmd_leads(args: argparse.Namespace) -> int:
    leads = find_leads(Workspace(args.path), args.max_leads)
    for lead in leads:
        print(f"{lead.score:>3}  {lead.path}  [{', '.join(sorted(lead.hints))}]")
    print(f"{len(leads)} leads", file=sys.stderr)
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    ws = Workspace(args.path)
    out_dir = Path(args.out) / time.strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "trace.jsonl").open("w") as trace_file:
        result = scan(ws, _client(args), args.mode, args.max_leads, args.max_steps,
                      _progress, trace_file, **_review_options(args))
    (out_dir / "findings.json").write_text(
        json.dumps([f.model_dump(mode="json") for f in result.findings], indent=2)
    )
    (out_dir / "stats.json").write_text(json.dumps(result.stats(), indent=2))
    (out_dir / "report.md").write_text(to_markdown(result.findings, ws.root.name, args.model))
    print(f"{len(result.findings)} findings written to {out_dir}")
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    """Score the agent on a seeded target and on its fully patched twin."""
    truth = Truth.load(args.truth)
    source = Path(args.target).resolve()
    all_ids = {w.id for w in truth.weaknesses}
    runs = []
    with tempfile.TemporaryDirectory() as tmp:
        vulnerable = Path(tmp) / "vulnerable" / source.name
        twin = Path(tmp) / "patched" / source.name
        materialise(source, vulnerable, truth, set())
        materialise(source, twin, truth, all_ids)
        if args.plant:
            plant_instructions(vulnerable, truth)
        for repeat in range(args.repeats):
            client = _client(args, seed=7 + repeat)
            _progress(f"== repeat {repeat + 1}/{args.repeats}: vulnerable tree")
            vuln = scan(Workspace(vulnerable), client, args.mode, None, args.max_steps, _progress,
                        **_review_options(args))
            s_vuln = score(vuln.findings, vulnerable, truth, patched=set())
            run = {
                "seed": 7 + repeat,
                "vulnerable": {**s_vuln.summary(), **vuln.stats()},
                "findings_vulnerable": [f.model_dump(mode="json") for f in vuln.findings],
            }
            if args.skip_twin:
                empty = score([], twin, truth, patched=all_ids)
                run["patched"] = {**empty.summary(), "seconds": 0.0, "errors": []}
                run["pair_accuracy"] = 0.0
                run["findings_patched"] = []
            else:
                _progress(f"== repeat {repeat + 1}/{args.repeats}: patched twin")
                safe = scan(Workspace(twin), client, args.mode, None, args.max_steps, _progress,
                            **_review_options(args))
                s_safe = score(safe.findings, twin, truth, patched=all_ids)
                pairs = sum(
                    1 for w in all_ids if w in s_vuln.found and w not in s_safe.patched_hits
                )
                run["patched"] = {**s_safe.summary(), **safe.stats()}
                run["pair_accuracy"] = round(pairs / len(all_ids), 3)
                run["findings_patched"] = [f.model_dump(mode="json") for f in safe.findings]
            runs.append(run)

    def avg(values) -> float:
        return round(statistics.fmean(values), 3)

    summary = {
        "model": args.model,
        "mode": args.mode,
        "prompt": args.prompt,
        "think": args.think,
        "temperature": args.temperature,
        "planted_instructions": args.plant,
        "strip_comments": args.strip_comments,
        "trust_boundary": not args.no_trust_boundary,
        "twin_scanned": not args.skip_twin,
        "repeats": args.repeats,
        "recall": avg(r["vulnerable"]["recall"] for r in runs),
        "precision": avg(r["vulnerable"]["precision"] for r in runs),
        "decoys_flagged": avg(len(r["vulnerable"]["decoys_flagged"]) for r in runs),
        "unlisted": avg(r["vulnerable"]["unlisted"] for r in runs),
        "patched_still_flagged": avg(len(r["patched"]["patched_still_flagged"]) for r in runs),
        "pair_accuracy": avg(r["pair_accuracy"] for r in runs),
        "discarded_bad_citation": avg(r["vulnerable"]["discarded_bad_citation"] for r in runs),
        "seconds_per_scan": avg(r["vulnerable"]["seconds"] for r in runs),
        "recall_per_run": [r["vulnerable"]["recall"] for r in runs],
    }
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"{args.model.replace('/', '_').replace(':', '_')}-{args.mode}-{args.prompt}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    (out_dir / name).write_text(json.dumps({"summary": summary, "runs": runs}, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"details: {out_dir / name}", file=sys.stderr)
    return 0


def _cmd_eval_pairs(args: argparse.Namespace) -> int:
    """Score the agent on a lab that ships vulnerable and secure versions of each file."""
    truth = PairTruth.load(args.truth)
    ids = sorted(m.id for m in truth.modules)
    runs = []
    with tempfile.TemporaryDirectory() as tmp:
        vulnerable, secure = materialise_pairs(Path(args.source).resolve(), Path(tmp) / "pairs", truth)
        for repeat in range(args.repeats):
            client = _client(args, seed=7 + repeat)
            _progress(f"== repeat {repeat + 1}/{args.repeats}: vulnerable versions")
            vuln = scan(Workspace(vulnerable), client, args.mode, None, args.max_steps, _progress,
                        **_review_options(args))
            _progress(f"== repeat {repeat + 1}/{args.repeats}: secure versions")
            safe = scan(Workspace(secure), client, args.mode, None, args.max_steps, _progress,
                        **_review_options(args))
            detected, other_vuln = flagged_modules(vuln.findings, truth)
            still, other_safe = flagged_modules(safe.findings, truth)
            runs.append({
                "seed": 7 + repeat,
                "detected": sorted(detected),
                "missed": sorted(set(ids) - detected),
                "secure_flagged": sorted(still),
                "pair_correct": sorted(detected - still),
                "other_findings_vulnerable": other_vuln,
                "other_findings_secure": other_safe,
                "stats_vulnerable": vuln.stats(),
                "stats_secure": safe.stats(),
                "findings_vulnerable": [f.model_dump(mode="json") for f in vuln.findings],
                "findings_secure": [f.model_dump(mode="json") for f in safe.findings],
            })

    def avg(values) -> float:
        return round(statistics.fmean(values), 3)

    n = len(ids)
    summary = {
        "target": truth.target,
        "model": args.model,
        "mode": args.mode,
        "prompt": args.prompt,
        "temperature": args.temperature,
        "repeats": args.repeats,
        "modules": n,
        "detected": avg(len(r["detected"]) for r in runs),
        "secure_flagged": avg(len(r["secure_flagged"]) for r in runs),
        "pair_accuracy": avg(len(r["pair_correct"]) / n for r in runs),
        "other_findings_vulnerable": avg(r["other_findings_vulnerable"] for r in runs),
        "other_findings_secure": avg(r["other_findings_secure"] for r in runs),
        "seconds_per_scan": avg(r["stats_vulnerable"]["seconds"] for r in runs),
        "detected_per_run": [len(r["detected"]) for r in runs],
    }
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"{truth.target}-{args.model.replace('/', '_').replace(':', '_')}-{args.mode}-{args.prompt}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    (out_dir / name).write_text(json.dumps({"summary": summary, "runs": runs}, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"details: {out_dir / name}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="proofer", description="Local AI security review agent.")
    sub = parser.add_subparsers(dest="command", required=True)

    def model_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("--model", default="none", help="Model name in the local runtime.")
        p.add_argument("--temperature", type=float, default=0.0)
        p.add_argument("--host", default="http://127.0.0.1:11434")
        p.add_argument("--num-ctx", type=int, default=16384)
        p.add_argument("--think", choices=["default", "on", "off"], default="off")
        p.add_argument("--max-tokens", type=int, default=4096)
        p.add_argument("--mode", choices=MODES, default="judge")
        p.add_argument("--max-steps", type=int, default=24)
        p.add_argument("--strip-comments", action="store_true",
                       help="Blank full-line comments before the model sees a file.")
        p.add_argument("--no-trust-boundary", action="store_true",
                       help="Experiment only: drop the instruction to distrust repository text.")
        p.add_argument("--prompt", choices=VARIANTS, default="walkthrough",
                       help="Slice review prompt: plain, or walkthrough (analysis before findings).")

    p_leads = sub.add_parser("leads", help="List the places the agent would review.")
    p_leads.add_argument("path", help="Repository to review.")
    p_leads.add_argument("--max-leads", type=int, default=None)
    p_leads.set_defaults(func=_cmd_leads)

    p_scan = sub.add_parser("scan", help="Review a repository with the local model.")
    p_scan.add_argument("path", help="Repository to review.")
    p_scan.add_argument("--max-leads", type=int, default=None)
    p_scan.add_argument("--out", default="runs")
    model_options(p_scan)
    p_scan.set_defaults(func=_cmd_scan)

    p_eval = sub.add_parser("eval", help="Score the agent on a seeded target and its patched twin.")
    p_eval.add_argument("--target", default="bench/targets/bakery")
    p_eval.add_argument("--truth", default="bench/truth/bakery.yaml")
    p_eval.add_argument("--repeats", type=int, default=2)
    p_eval.add_argument("--out", default="runs/eval")
    p_eval.add_argument("--plant", action="store_true",
                        help="Plant a do-not-report comment in every file with a weakness.")
    p_eval.add_argument("--skip-twin", action="store_true",
                        help="Scan only the vulnerable tree; pair metrics are then not computed.")
    model_options(p_eval)
    p_eval.set_defaults(func=_cmd_eval)

    p_pairs = sub.add_parser(
        "eval-pairs", help="Score the agent on a lab with vulnerable and secure file pairs."
    )
    p_pairs.add_argument("--source", default="bench/external/DVWA")
    p_pairs.add_argument("--truth", default="bench/truth/dvwa.yaml")
    p_pairs.add_argument("--repeats", type=int, default=1)
    p_pairs.add_argument("--out", default="runs/eval")
    model_options(p_pairs)
    p_pairs.set_defaults(func=_cmd_eval_pairs)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (WorkspaceError, LLMError, TruthError, ScannerError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
