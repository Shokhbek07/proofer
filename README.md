# Proofer

A local AI security review agent, built for the Safia ML Engineer case study.

Proofer reviews a codebase on your own machine with a local model and reports security weaknesses.
Its central idea is that a small local model is a weak oracle but a useful hypothesis generator, so the system earns trust through evidence and verification instead of model confidence.

Status: work in progress.
See `docs/DECISIONS.md` for what is settled and why, and `docs/EXPERIMENTS.md` for what was measured, including what failed.

## How it works

1. **Leads without the model.** Every source and deployment file is reviewed. Pattern matching ranks them and supplies hints.
2. **The model judges a narrow slice.** One file at a time, with the definitions of the local helpers it imports. It must first describe each handler and which protection is present or missing, then list findings. The answer is schema-constrained JSON with bounded fields.
3. **Citations are checked mechanically.** Every quoted line must exist in the file it names. Invented code is discarded before anyone sees it.
4. **Findings carry a tier.** `supported` means an independent scanner (Semgrep) reported the same place, which was never wrong in our measurements. `suspected` means verified citations only. Findings worded with hedges such as "could" are listed last, because they were right about half as often.

The repository under review is treated as untrusted input.
The model only ever sees it through a read-only, path-jailed workspace, and the model endpoint must be on the local machine.

## Setup

Requirements: macOS or Linux, [uv](https://docs.astral.sh/uv/), and [Ollama](https://ollama.com).

```bash
uv sync
```

```bash
ollama pull gemma4:26b-a4b-it-qat
```

## Use

List what would be reviewed, without a model:

```bash
uv run proofer leads bench/targets/bakery
```

Review a repository:

```bash
uv run proofer scan path/to/repo --model gemma4:26b-a4b-it-qat --prompt walkthrough
```

Results are written to `runs/<timestamp>/` as `report.md`, `findings.json` and `stats.json`.

Score a model on the seeded benchmark and its patched twin:

```bash
uv run proofer eval --model gemma4:26b-a4b-it-qat --prompt walkthrough --repeats 1
```

Score it on DVWA, an independent lab that ships vulnerable and secure versions of each handler.
DVWA is fetched at a pinned commit and only read as text; nothing in it is run.

```bash
scripts/fetch_dvwa.sh
```

```bash
uv run proofer eval-pairs --model gemma4:26b-a4b-it-qat --prompt walkthrough
```

Baselines that need no model: `--mode patterns` and `--mode semgrep` work with both commands.

## Fine-tuning experiment

E11 in `docs/EXPERIMENTS.md` tunes a 9B model on reviews written by the 26B one; the tuned model is not used (D15).
It needs Apple silicon, the optional `finetune` dependency group, OWASP Benchmark for Python, and about seven hours.

```bash
scripts/fetch_owasp_python.sh
```

```bash
uv run --group finetune python -c "from huggingface_hub import snapshot_download; snapshot_download('ornith-ai/Ornith-1.5-9B-MLX-4bit', revision='a48173b246ac705be75c05bedf1a0666db522d53', local_dir='data/cache/ornith-9b-mlx-4bit')"
```

```bash
uv run --group finetune python experiments/finetune/build_dataset.py
```

```bash
sh experiments/finetune/run.sh
```

Run nothing else that loads a large model while it trains or scores: on 24 GB, two at once exhausted memory and crashed the machine.

## Boundaries

Only run this against code you own or intentionally vulnerable local labs.
Proofer does not scan or send traffic to remote systems.

## Tests

```bash
uv run pytest -q
```
