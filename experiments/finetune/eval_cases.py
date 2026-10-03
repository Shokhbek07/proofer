"""Score a model on the held-out OWASP cases.

Usage:
    uv run python experiments/finetune/eval_cases.py --backend ollama --model gemma4:26b-a4b-it-qat
    uv run --group finetune python experiments/finetune/eval_cases.py --backend mlx \
        --model data/cache/ornith-9b-mlx-4bit [--adapter data/finetune/adapter]
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from proofer.judge import review_file
from proofer.leads import find_leads
from proofer.llm import OllamaClient
from proofer.owasp import flags_case, load_cases, score_cases
from proofer.workspace import Workspace


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=["ollama", "mlx"], required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--adapter", default=None)
    parser.add_argument("--benchmark", default="bench/external/BenchmarkPython")
    parser.add_argument("--tree", default="data/cache/owasp_tree")
    parser.add_argument("--summary", default="data/finetune/summary.json")
    parser.add_argument("--out", default="runs/finetune")
    parser.add_argument("--label", required=True, help="Short name for the result file.")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    if args.backend == "mlx":
        from proofer.llm_mlx import MLXClient
        client = MLXClient(args.model, args.adapter)
    else:
        client = OllamaClient(args.model, think=False)

    holdout_names = set(json.loads(Path(args.summary).read_text())["holdout"])
    cases = [c for c in load_cases(Path(args.benchmark)) if c.name in holdout_names][: args.limit]
    ws = Workspace(args.tree)
    leads = {lead.path: lead for lead in find_leads(ws)}

    flagged: dict[str, bool] = {}
    rows = []
    errors = 0
    started = time.monotonic()
    for i, case in enumerate(cases, start=1):
        review = review_file(client, ws, leads[case.path], "walkthrough")
        flagged[case.name] = flags_case(review.findings, case)
        errors += bool(review.error)
        rows.append({
            "name": case.name, "category": case.category, "real": case.real,
            "flagged": flagged[case.name], "findings": len(review.findings),
            "discarded": len(review.discarded), "error": review.error,
            "seconds": round(review.seconds, 1),
            "cwes": [f.cwe for f in review.findings],
        })
        print(f"[{i}/{len(cases)}] {case.name} {case.category} real={case.real} "
              f"flagged={flagged[case.name]} {review.error}", flush=True)

    summary = {
        "label": args.label, "backend": args.backend, "model": args.model,
        "adapter": args.adapter, **score_cases(flagged, cases),
        "errors": errors, "minutes": round((time.monotonic() - started) / 60, 1),
        "by_category": {
            cat: score_cases(flagged, [c for c in cases if c.category == cat])
            for cat in sorted({c.category for c in cases})
        },
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"owasp-{args.label}.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "by_category"}, indent=2))


if __name__ == "__main__":
    main()
