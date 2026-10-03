# Proofer - project memory

Proofer is a local AI security review agent, built as the Safia ML Engineer case study.
The brief is `ML_Engineer_CaseStudy.pdf` in the repo root.
Deadline is 2026-10-15.

## Intended outcome

A command line agent that reviews a codebase or small platform on a laptop, using a local model, and reports security weaknesses with evidence.
Every reported finding carries a verification tier, so a reader knows how much to trust it.
The repository must let a reviewer install it, run it on a sample target, and reproduce the evaluation numbers.

## Central idea

A small local model is a weak oracle but a useful hypothesis generator.
The system earns trust through grounding and verification, not through model confidence.
Every finding has its quoted lines checked against the file.
Tiers: `suspected` (verified citations), `supported` (an independent scanner reports the same place).
A `confirmed` tier (reproduced against a local lab container) was planned and is not built; see O7 in `docs/DECISIONS.md`.
The default model is Gemma 4 26B-A4B with the analysis-first prompt (`--prompt walkthrough`).

## Constraints

- Local model for all reasoning in the product path.
- Only analyse and test code and containers that live on this machine and are owned or intentionally vulnerable labs.
- Never scan, probe, or send traffic to third-party systems; the tool must enforce this, not just document it.
- The scanned repository is untrusted input and must not be able to steer the agent.
- No time spent on UI polish.

## Target environment

- Apple M4 Pro, 24 GB unified memory, macOS 15.
- Python 3.12 managed with `uv`.
- Ollama on `127.0.0.1:11434` as the default model runtime.
- Docker Desktop for lab targets.

## Scope

Multi-language source review (Python, JavaScript and TypeScript first, others through language-agnostic tooling), plus dependencies, secrets, and container or infrastructure configuration.

## Where things are recorded

- `REPORT.md` is the full report for reviewers, written from the two logs below; keep it in step with them.
- `results/` holds the raw result files behind every reported number, copied from the ignored `runs/`.
- `docs/DECISIONS.md` holds settled and open decisions with their reasons.
- `docs/EXPERIMENTS.md` holds each experiment, including the ones that failed.
- Update both as work proceeds; the final submission explanation is written from them.

## Working rules

- Do not commit, push, or publish without explicit authorization from Shokhbek.
- Report evaluation numbers exactly as measured, including bad ones.
- Load one large model at a time: on 2026-10-03 three at once exhausted the 24 GB and panicked the kernel (REPORT.md section 8).
