"""Summarise repeated evaluation runs: mean, minimum and maximum per metric.

Usage:
    uv run python scripts/summarise_runs.py RESULT.json [RESULT.json ...]

Accepts the files written by `proofer eval`, `eval-pairs` and `eval-real`, one or
more runs each, and groups them by target and configuration. For every group it
prints one Markdown table of metrics over the runs, then how many runs found each
weakness, module or item.
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

from proofer.realworld import RealTruth


def bakery_rows(run: dict) -> tuple[dict[str, float], dict[str, tuple[bool, bool]]]:
    vuln, patched = run["vulnerable"], run["patched"]
    metrics = {
        "found (of 17)": len(vuln["found"]),
        "precision": vuln["precision"],
        "decoys flagged": len(vuln["decoys_flagged"]),
        "patched still flagged": len(patched["patched_still_flagged"]),
        "pair accuracy": run["pair_accuracy"],
        "errors": len(vuln["errors"]) + len(patched["errors"]),
        "seconds": round(vuln["seconds"] + patched["seconds"]),
    }
    flagged = set(patched["patched_still_flagged"])
    per = {w: (w in vuln["found"], w in vuln["found"] and w not in flagged)
           for w in [f"V{n:02d}" for n in range(1, 18)]}
    return metrics, per


def dvwa_rows(run: dict) -> tuple[dict[str, float], dict[str, tuple[bool, bool]]]:
    metrics = {
        "detected (of 10)": len(run["detected"]),
        "secure flagged": len(run["secure_flagged"]),
        "pairs correct": len(run["pair_correct"]),
        "errors": len(run["stats_vulnerable"]["errors"]) + len(run["stats_secure"]["errors"]),
        "seconds": round(run["stats_vulnerable"]["seconds"] + run["stats_secure"]["seconds"]),
    }
    modules = sorted(set(run["detected"]) | set(run["missed"]))
    per = {m: (m in run["detected"], m in run["pair_correct"]) for m in modules}
    return metrics, per


def real_rows(run: dict, groups: dict[str, str]) -> tuple[dict[str, float], dict[str, tuple[bool, bool]]]:
    items = run["items"]

    def count(key: str, group: str | None = None) -> int:
        return sum(1 for r in items if r[key] and (group is None or groups.get(r["id"]) == group))

    metrics: dict[str, float] = {
        "detected (of 24)": count("detected"),
        "detected at change": count("detected_at_change"),
        "fixed flagged": count("fixed_flagged"),
        "pairs correct": count("pair_correct"),
    }
    for group in sorted(set(groups.values())):
        metrics[f"pairs correct, {group}"] = count("pair_correct", group)
        metrics[f"detected at change, {group}"] = count("detected_at_change", group)
    metrics.update({
        "other findings, vulnerable": sum(r["other_findings_vulnerable"] for r in items),
        "other findings, fixed": sum(r["other_findings_fixed"] for r in items),
        "errors": sum(len(r["stats_vulnerable"]["errors"]) + len(r["stats_fixed"]["errors"]) for r in items),
        "largest prompt (tokens)": max(
            max(r["stats_vulnerable"].get("largest_prompt_tokens", 0),
                r["stats_fixed"].get("largest_prompt_tokens", 0)) for r in items
        ),
        "seconds": round(sum(r["stats_vulnerable"]["seconds"] + r["stats_fixed"]["seconds"] for r in items)),
    })
    per = {r["id"]: (r["detected_at_change"], r["pair_correct"]) for r in items}
    return metrics, per


def main() -> None:
    groups = {i.id: i.group for i in RealTruth.load("bench/truth/realworld.yaml").items}
    runs: dict[tuple, list[tuple[int, dict, dict]]] = defaultdict(list)
    per_label: dict[tuple, tuple[str, str]] = {}
    for name in sys.argv[1:]:
        data = json.loads(Path(name).read_text())
        s = data["summary"]
        target = s.get("target", "bakery")
        key = (target, s["model"], s["mode"], s.get("prompt", ""), s.get("context", "none"),
               s["temperature"])
        for run in data["runs"]:
            if target == "realworld":
                metrics, per = real_rows(run, groups)
                per_label[key] = ("detected at change", "pair correct")
            elif target == "dvwa":
                metrics, per = dvwa_rows(run)
                per_label[key] = ("detected", "pair correct")
            else:
                metrics, per = bakery_rows(run)
                per_label[key] = ("found", "pair correct")
            runs[key].append((run.get("seed", 0), metrics, per))

    for key, rows in runs.items():
        rows.sort(key=lambda r: r[0])
        target, model, mode, prompt, context, temperature = key
        print(f"\n## {target}: {model} {mode} {prompt} context={context} "
              f"temperature={temperature}, {len(rows)} runs (seeds {[r[0] for r in rows]})\n")
        print("| Metric | mean | min | max | per run |")
        print("|---|---|---|---|---|")
        for metric in rows[0][1]:
            values = [r[1][metric] for r in rows]
            fmt = (lambda v: f"{v:.3f}") if any(isinstance(v, float) and not v.is_integer()
                                                for v in values) else (lambda v: f"{v:g}")
            print(f"| {metric} | {statistics.fmean(values):.2f} | {fmt(min(values))} | "
                  f"{fmt(max(values))} | {', '.join(fmt(v) for v in values)} |")
        first, second = per_label[key]
        print(f"\n| Item | runs {first} | runs {second} |")
        print("|---|---|---|")
        for item in rows[0][2]:
            a = sum(1 for r in rows if r[2].get(item, (False, False))[0])
            b = sum(1 for r in rows if r[2].get(item, (False, False))[1])
            print(f"| {item} | {a} of {len(rows)} | {b} of {len(rows)} |")


if __name__ == "__main__":
    main()
