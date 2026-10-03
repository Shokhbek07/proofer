# Raw results

Every number in `REPORT.md` and `docs/EXPERIMENTS.md` comes from a file in this folder.
The files are copied unchanged from the ignored `runs/` folder, where the tools write them.
Times in file names are local time (UTC+5).

## `eval/` - seeded bakery benchmark and DVWA

Files without a `dvwa-` prefix are bakery runs from `proofer eval`; `dvwa-` files are from `proofer eval-pairs`.
Each file holds a `summary` and the full findings of every run, on both the vulnerable and the fixed version.

| File | Experiment | What it is |
|---|---|---|
| `hf.co_ornith-ai_Ornith-1.5-9B-GGUF_Q8_0-judge-20261002-114239.json` | E3 | Ornith-1.5-9B, plain prompt |
| `gemma4_26b-a4b-it-qat-judge-20261002-114912.json` | E3, E4, E5 | Gemma 4 26B, plain prompt |
| `gemma4_26b-a4b-it-qat-agent-20261002-122510.json` | E4 | Gemma 4 26B, tool loop |
| `gemma4_26b-a4b-it-qat-judge-walkthrough-20261002-123544.json` | E5 | Gemma 4 26B, analysis first |
| `dvwa-none-patterns-plain-20261002-131004.json` | E7 | DVWA, own patterns |
| `gemma4_26b-a4b-it-qat-judge-walkthrough-20261002-133127.json` | E6 | Three runs at temperature 0.7, seeds 7, 8, 9 |
| `none-semgrep-plain-20261002-133452.json` | E7 | Bakery, Semgrep |
| `dvwa-none-semgrep-plain-20261002-133506.json` | E7 | DVWA, Semgrep |
| `dvwa-gemma4_26b-a4b-it-qat-judge-walkthrough-20261002-133732.json` | E7 | DVWA, Gemma 4 analysis first, before the two fixes |
| `dvwa-gemma4_26b-a4b-it-qat-judge-plain-20261002-134032.json` | E7 | DVWA, Gemma 4 plain prompt |
| `dvwa-gemma4_26b-a4b-it-qat-judge-walkthrough-20261002-134704.json` | E7, E8 | DVWA, Gemma 4 analysis first, after the two fixes |
| `gemma4_26b-a4b-it-qat-judge-walkthrough-20261002-135311.json` | E7, E8, E10 | Bakery, Gemma 4 analysis first, after the two fixes (also the E10 clean baseline) |
| `hf.co_unsloth_Qwen3.8-27B-GGUF_UD-Q4_K_S-judge-walkthrough-20261002-142927.json` | E8 | Bakery, Qwen3.8-27B |
| `dvwa-hf.co_unsloth_Qwen3.8-27B-GGUF_UD-Q4_K_S-judge-walkthrough-20261002-145327.json` | E8 | DVWA, Qwen3.8-27B |
| `gemma4_26b-a4b-it-qat-judge-walkthrough-20261002-150320.json` | E10 | Planted note, comments kept, trust-boundary instruction on |
| `gemma4_26b-a4b-it-qat-judge-walkthrough-20261002-151047.json` | E10 | Clean tree, comments stripped |
| `gemma4_26b-a4b-it-qat-judge-walkthrough-20261002-151922.json` | E10 | Planted note, comments stripped |
| `gemma4_26b-a4b-it-qat-judge-walkthrough-20261002-152728.json` | E10 | Planted note, comments kept, trust-boundary instruction off |
| `data_cache_ornith-9b-mlx-4bit-judge-walkthrough-20261003-071423.json` | E11 | Bakery, student untuned |
| `dvwa-data_cache_ornith-9b-mlx-4bit-judge-walkthrough-20261003-072135.json` | E11 | DVWA, student untuned |
| `data_cache_ornith-9b-mlx-4bit-judge-walkthrough-tuned-20261003-072743.json` | E11 | Bakery, student tuned, step 900 |
| `dvwa-data_cache_ornith-9b-mlx-4bit-judge-walkthrough-tuned-20261003-073254.json` | E11 | DVWA, student tuned, step 900 |
| `data_cache_ornith-9b-mlx-4bit-judge-walkthrough-tuned-20261003-094846.json` | E11 | Bakery, student tuned, step 600 |
| `dvwa-data_cache_ornith-9b-mlx-4bit-judge-walkthrough-tuned-20261003-095130.json` | E11 | DVWA, student tuned, step 600 |

The E10 runs score only the vulnerable tree, so their `pair_accuracy` of 0.0 means "not measured", not a result.
In the E11 student runs launched from the Terminal panel, Semgrep failed (see `REPORT.md`), so every finding there is `suspected`; no E11 score depends on the tier.

Not saved: the E1 pattern baseline on the bakery benchmark (run before result files were written) and the E2 probes, which were single calls.
The E9 numbers are recomputed from the E6 and E7 files by `scripts/analyse_tiers.py`.

## `finetune/` - E11

| File | What it is |
|---|---|
| `dataset-summary.json` | Teacher labelling counts and the names of the 125 held-out cases |
| `train.log` | Training log, including validation loss every 150 steps |
| `owasp-teacher.json`, `.log` | Gemma 4 26B on the held-out cases, normal prompt |
| `owasp-student-untuned.json`, `.log` | Student before tuning |
| `owasp-student-tuned.json`, `.log` | Student after 900 steps, the pre-registered model |
| `owasp-student-tuned-600.json`, `.log` | Student at step 600, lowest validation loss |
| `bakery.log`, `dvwa.log` | Console output of the student's bakery and DVWA runs |

Each `owasp-*.json` has one row per held-out case: class, label, whether it was flagged, the CWEs reported, any error, and the seconds taken.

Not included: the training examples, the teacher's raw answers and the adapter weights.
The examples contain OWASP Benchmark source code, which is not redistributed here; `experiments/finetune/build_dataset.py` regenerates them.
