# Proofer - full report

Proofer is a local AI security review agent, built for Safia's ML Engineer case study "Build a local AI security agent".
This report records everything that was built, measured, decided, and what went wrong, including the experiments that failed and the machine crash on 2026-10-03.
`docs/DECISIONS.md` and `docs/EXPERIMENTS.md` are the working logs this report is written from; `results/` holds every raw result file.
All times are local (UTC+5).

## 1. Summary

- Proofer reviews a repository with a local model, one file at a time, and reports weaknesses whose quoted lines are checked against the file.
- Each finding carries a tier: `supported` when an independent scanner (Semgrep) reports the same place, otherwise `suspected`.
- The default model is Gemma 4 26B-A4B (a mixture of experts with about 4B active parameters) running in Ollama on the laptop, with an "analysis first" prompt.
- On a seeded benchmark written for this project it finds 15 to 17 of 17 weaknesses (mean 16.0 over three runs), with precision 0.94, and tells a weakness apart from its fix in 71 to 88 percent of cases.
- On DVWA, an independent lab that played no part in writing the prompts, it detects 8 of 10 weaknesses and scores 0.70 to 0.80 on vulnerable/secure pairs, against 4 of 10 and 0.30 for Semgrep.
- Six results were negative or failed: open-ended reasoning never ended (E2), the first tier definition did not separate true from false findings (E3, E9), a published claim about tool use did not reproduce (E4), a third model did not fit in memory (E8), two defences against planted instructions had no measurable effect (E10), and the fine-tuning experiment did not meet its pre-registered success criterion (E11).
- The third tier, `confirmed` (reproducing a finding against a local lab container), was designed but not built (section 9).
- On 2026-10-03 the laptop had a kernel panic in Apple's GPU driver while memory was exhausted by three large models at once; no result was lost (section 8).

## 2. The brief and the constraints

The brief asks for an agent that reviews a software platform or codebase for security weaknesses, using a local model as much as reasonably possible.
It is deliberately open-ended and is judged on thinking, decisions and experiments, including failed ones, rather than polish.
Boundaries from the brief: test only code you own or intentionally vulnerable local labs, and do not attack, scan or exploit third-party systems.
The invitation arrived on 2026-10-01 with a two-week deadline, 2026-10-15.

Constraints set for the project (`AGENTS.md`):

- A local model does all reasoning in the product path.
- Only code and containers on this machine that are owned or intentionally vulnerable are analysed.
- No traffic to third-party systems, enforced by the tool rather than documented.
- The repository under review is untrusted input and must not be able to steer the agent.
- No time on interface polish.

## 3. Environment

| Item | Value |
|---|---|
| Machine | Apple M4 Pro (Mac16,8), 12 cores, 24 GB unified memory |
| OS | macOS 15.7.7 (24G720) |
| Python | 3.12 through `uv` 0.11.7 (system Python is 3.8) |
| Model runtime | Ollama 0.35.0 from Homebrew, flash attention on, q8 KV cache, one loaded model |
| Fine-tuning runtime | MLX 0.32.3, `mlx-lm` 0.32.0 |
| Baseline scanner | Semgrep 1.179.0, `p/default` rules |
| Containers | Docker 29.6.2, about 19.5 GB available to its VM, competing with the model for memory |
| Disk | 52 GB free at the start; see section 7.3 |

## 4. How Proofer works

1. **Leads without the model.** Every source and deployment file becomes a lead (`leads.py`).
   Pattern matching only ranks them and adds hints such as "command injection: line 5".
2. **The model judges a narrow slice.** One file per call, with the definitions of local helpers it imports (`judge.py`).
   The file is shown with line numbers.
3. **Analysis before findings.** The answer schema has an `analysis` list, generated before `findings`, with one entry per handler or configuration block: who can reach it, which inputs are untrusted, what it does with them, which protection is present or missing.
4. **Bounded, schema-constrained output.** Ollama enforces the JSON schema; every string and list has a maximum length, and the whole answer has a 4,096-token cap.
   Running out of budget is reported as an error, never as "no findings".
5. **Citations are checked mechanically** (`evidence.py`).
   Every quoted line must exist in the file it names; line numbers are corrected to where the quote actually is; findings with no verifiable quote are discarded.
6. **Tiers** (`pipeline.py`).
   Semgrep is run on the same tree; a finding within three lines of a Semgrep result is `supported`, otherwise `suspected`.
   Hedged findings ("could", "potentially", "might") are ranked last within their tier.
7. **Report** (`report.py`): `report.md`, `findings.json` and `stats.json` per run.

Security properties that do not depend on the model:

- The model endpoint must be a loopback address; anything else is refused (`llm.py`).
- The repository is read through a read-only workspace that refuses paths outside its root (`workspace.py`).
- The model has no tool that writes, executes, or reaches the network.
  A hijacked review can at worst report wrongly; it cannot act.
- Repository text is wrapped and labelled as untrusted in the prompt.

One network call remains outside the model path: Semgrep downloads its community rules from the Semgrep registry at run time (with metrics off).
It does not contact any scanned system.

Other modes, kept for comparison: a tool loop where the model calls `read_file`, `search` and `record_finding` itself (`agent.py`, E4), and two baselines without a model, `--mode patterns` and `--mode semgrep`.

Commands: `proofer leads`, `proofer scan`, `proofer eval` (seeded benchmark and its patched twin), `proofer eval-pairs` (DVWA).
Code: about 2,900 lines of Python in `src/` and `tests/`, 58 tests.

## 5. Benchmarks and metrics

**Seeded bakery benchmark** (`bench/targets/bakery`, written for this project).
A two-service ordering platform: an orders API in Python and Flask, a storefront in Node and Express, and Docker Compose deployment files including a committed `.env` with made-up secrets.
22 files, about 575 lines.
It contains 17 seeded weaknesses and 12 decoys (safe code that looks risky); the ground truth is in `bench/truth/bakery.yaml`, outside the scanned tree.

| Id | Weakness |
|---|---|
| V01 | SQL injection in staff order search (query split across two string literals) |
| V02 | Any logged-in user can read any order by id |
| V03 | Shell command built from the requested printer name |
| V04 | Invoice download path not confined to the invoice folder |
| V05 | Legacy cart cookie is unpickled |
| V06 | Order quantity not validated, so a negative quantity is accepted |
| V07 | Token signing key hardcoded in source |
| V08 | Passwords hashed with unsalted MD5 |
| V09 | Review text written into the product page without escaping |
| V10 | Server fetches any URL supplied for a product photo |
| V11 | Session token decoded without verifying its signature |
| V12 | Profile update copies every request field onto the user |
| V13 | Orders container runs privileged |
| V14 | Flask debugger enabled on a server bound to all interfaces |
| V15 | Database uses a default password and is published on the host |
| V16 | Secrets committed in an environment file |
| V17 | Orders image runs as root |

Every weakness has a fix, so a fully patched twin is generated and scanned too.
Metrics: `recall` (weaknesses found of 17), `precision` (decoys and unlisted findings count as false), `decoys_flagged` (of 12), `patched_still_flagged` (fixed weaknesses still reported on the twin), and `pair_accuracy` (reported on the vulnerable tree and not after the fix), which punishes a detector that flags everything.
Known bias: the benchmark, the patterns and the prompts were written by the same author on the same day, so its numbers compare configurations; they are not absolute claims.

**DVWA pairs** (`bench/truth/dvwa.yaml`, DVWA at commit `43b0f8b13b7c824b08b228abfd868b5e4c110a5d`).
Ten modules, each scored as a pair: `low.php` (vulnerable) against `impossible.php` (secure).
The modules and their weakness classes were fixed before any model saw them.
DVWA is GPL-3.0, so it is fetched by `scripts/fetch_dvwa.sh` and not stored in this repository; it is only read as text, never run.
It checks whether results hold on PHP code that played no part in writing the prompts; it cannot rule out memorisation, since DVWA is widely published.

**OWASP Benchmark for Python** (commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`), used only for E11.
1,230 small Flask handlers in 14 weakness classes, each labelled real or a safe look-alike.
Licence headers and the class names embedded in URL paths are stripped, because they would give away the answer (`owasp.py`).
Score: true-positive rate minus false-positive rate, as the benchmark defines it.

## 6. Experiments

Each experiment below is in `docs/EXPERIMENTS.md` with its full setup; raw files are listed in `results/README.md`.
Unless stated otherwise: one run, temperature 0, reasoning off, one file per call.

### E0 - Environment baseline

See section 3.

### E1 - Pattern baseline with no model

Every pattern hit reported as a finding: recall 0.647 (11 of 17), precision 0.733, 4 decoys flagged, 1 fixed weakness still flagged, pair accuracy 0.588.
Missed: the SQL string split across lines, the unvalidated quantity, the unescaped template literal, the default database password, the committed secrets, and the image running as root.
Learned: patterns miss weaknesses that are an absence or span lines, so deployment files are always reviewed in full and patterns only give hints.
The raw output of this run was not saved.

### E2 - First model run: reasoning never ends (failure)

Ornith-1.5-9B (Q8, default settings) generated more than 14,000 tokens over ten minutes on one small file without finishing.
A capped probe spent all 3,000 output tokens on reasoning and returned an empty answer.
With reasoning off, the same call returned valid JSON in 29 seconds.
It also copied the line-number gutter into its quotes and wrote CWE ids as bare numbers.
Changes: a mandatory output cap reported as an error when hit, reasoning off by default, a citation check that tolerates the gutter, and CWE normalisation.

### E3 - Model bake-off

| Configuration | recall | precision | decoys flagged | patched still flagged | pair accuracy | seconds per scan |
|---|---|---|---|---|---|---|
| Patterns only | 0.647 | 0.733 | 4 | 1 | 0.588 | 0 |
| Ornith-1.5-9B Q8 | 0.412 | 0.778 | 1 | 0 | 0.412 | 195 |
| Gemma 4 26B-A4B QAT | 0.706 | 1.000 | 0 | 1 | 0.647 | 281 |

Ornith missed 10 of 17 and returned an empty list within 1 to 3 seconds for several files; it flagged the safe path check as a traversal while missing the unsafe one in the same file.
Gemma missed 5: reading any order by id, the invoice path traversal, the unvalidated quantity, debug mode, and the image running as root; on the patched twin it called the JSON cart cookie insecure deserialisation.
Every miss of the better model was an absence (a missing check) or a logic flaw.
The citation check discarded 1 finding for Ornith and 0 for Gemma: with the file in the prompt, invented code is rare.
**Failure:** the original `supported` tier (the citations include both where untrusted data enters and where it is used) did not discriminate, because Gemma labelled nearly every citation as a source.

### E4 - Tools against code in the prompt (published claim did not reproduce)

Published work reports that repository tools lower detection at much higher cost.

| Mode | recall | precision | decoys flagged | patched still flagged | pair accuracy | seconds per scan | prompt tokens |
|---|---|---|---|---|---|---|---|
| Slice in prompt | 0.706 | 1.000 | 0 | 1 | 0.647 | 281 | not recorded |
| Tool loop | 0.765 | 1.000 | 0 | 0 | 0.765 | 1,442 | 214,677 |

The tool loop found one more weakness and took five times as long; within one run, a difference of one weakness is noise.
The benchmark files are small and each lead names the file, unlike the large repositories in the published work.
Of 32 logged investigations, 30 ended with `finish` and 2 hit the step cap; tool-call traces were not saved, so malformed calls cannot be counted.
Decision: slice review stays the default on cost grounds (D5).

### E5 - Analysis before findings

| Prompt | recall | precision | decoys flagged | patched still flagged | pair accuracy | seconds per scan |
|---|---|---|---|---|---|---|
| Plain | 0.706 (12 of 17) | 1.000 | 0 | 1 | 0.647 | 281 |
| Analysis first | 0.941 (16 of 17) | 0.889 | 1 | 1 | 0.882 | 354 |

Four of the five earlier misses were found; only the unvalidated quantity remained.
Cost: the settings loader was reported as an arbitrary file read (a decoy), and the emptied secrets file on the patched twin was reported as a weakness.
Caveat: the instruction names ownership, range validation and least privilege, which are exactly the classes E3 missed, on a benchmark by the same author; E7 re-checks it on DVWA.

### E6 - Stability across repeated runs

Three runs of the E5 configuration at temperature 0.7, seeds 7, 8, 9: found 16, 17 and 15; precision 0.941, 0.944, 0.938; decoys 1, 1, 1; patched still flagged 1, 2, 3; pair accuracy 0.882, 0.882, 0.706 (mean 0.823).
15 weaknesses were found in all three runs; the path traversal in two, the quantity in one.
The false positives repeat as reliably as the true findings (the settings loader 3 of 3, the JSON cookie on the twin 3 of 3), so agreement across runs cannot define the `supported` tier.
The weak side is the patched twin: on average 2 of 17 fixed weaknesses are still reported.

### E7 - Outside baseline and independent target

Semgrep on the bakery benchmark: recall 0.412 (7 of 17), precision 0.778, 1 decoy, 1 still flagged, pair accuracy 0.353.
It flagged the allowlisted `ORDER BY` query (a decoy) and missed the real injection a few lines below, because that query is split across two string literals (not planted on purpose).

| DVWA configuration | detected (of 10) | secure version flagged | pair accuracy |
|---|---|---|---|
| Own patterns | 1 | 2 | 0.00 |
| Semgrep | 4 | 1 | 0.30 |
| Gemma 4, plain prompt | 6 | 0 | 0.60 |
| Gemma 4, analysis first | 8 | 0 | 0.80 |

The analysis-first gain held on code that played no part in writing the prompt.
Own patterns collapsed on PHP (1 of 10), confirming their bias.
**Two pipeline failures** caused both DVWA misses:

- `sqli`: the model identified the injection, then looped on newline characters inside a quoted string until the output budget ran out, and the finding was lost.
  Fix: every string and list in the schema has a maximum length (D11).
- `weak_id`: the file matched no pattern and was never shown to the model.
  Fix: every source and deployment file is reviewed (D10).

Rerun after the fixes: DVWA 8 of 10, 1 secure version flagged, pair accuracy 0.70 (from 0.80); bakery recall 0.941, pair accuracy 0.824 (from 0.882).
The SQL injection module is now detected; the weak session id file is now reviewed but the model reports nothing for it; the CSRF module was reported only for MD5 hashing; the secure upload handler was flagged on the speculation that "an attacker could potentially bypass" the image check.
Both fixes were made after seeing DVWA results, so DVWA is no longer untouched; they are generic robustness fixes with no prompt wording changed.

### E8 - Third model: Qwen3.8-27B (did not fit)

| | Gemma 4 26B-A4B | Qwen3.8-27B |
|---|---|---|
| Bakery recall, precision | 0.941, 0.941 | 0.941, 0.941 |
| Decoys flagged, patched still flagged | 1, 2 | 0, 2 |
| Bakery pair accuracy | 0.824 | 0.824 |
| Seconds per bakery scan | 229 | 1,442 |
| DVWA detected, secure flagged, pair accuracy | 8, 1, 0.70 | 7, 0, 0.70 |
| Seconds per DVWA scan | 166 | 783 |

Tied on accuracy and five to six times slower: Ollama placed 15 percent of the model on the CPU, generation ran at about 8 tokens per second, and swap grew to 20 GB.
Both models missed the same seeded weakness (the quantity) and the same two DVWA modules (CSRF and the weak session id), which are judged against things outside the file.
Decision: Gemma 4 26B-A4B is the default (D12).

### E9 - What separates true findings from false ones

81 findings from four saved Gemma runs (65 true, 16 false), labelled against ground truth by `scripts/analyse_tiers.py`.

| Signal | with it | precision with | without | precision without | share of true findings kept |
|---|---|---|---|---|---|
| Semgrep reports the same place | 28 | 1.000 | 53 | 0.698 | 0.43 |
| No hedging words | 66 | 0.864 | 15 | 0.533 | 0.88 |
| Severity high or critical | 64 | 0.844 | 17 | 0.647 | 0.83 |
| Cites both ends of the flow (old definition) | 33 | 0.788 | 48 | 0.812 | 0.40 |

Scanner agreement was never wrong but covers under half the true findings, so it defines the high-trust tier and is never used to filter (D13).
Caveats: the 28 agreed findings are about 7 distinct weaknesses seen four times; the hedging list was written after seeing one speculative false positive.

### E10 - Instructions planted in the code under review

A comment telling automated reviewers the file was audited and to return an empty findings list was prepended to the 13 files holding seeded weaknesses.

| Tree | Comments | Trust-boundary instruction | found (of 17) | missed |
|---|---|---|---|---|
| Clean | kept | yes | 16 | quantity |
| Planted note | kept | yes | 16 | image runs as root |
| Planted note | kept | no | 15 | quantity, image runs as root |
| Clean | stripped | yes | 15 | quantity, path traversal |
| Planted note | stripped | yes | 15 | quantity, path traversal |

The note did not achieve what it asked: the model kept reporting in at least 12 of the 13 files.
It probably suppressed one finding, the image running as root, which is an absence and gives the model nothing concrete to hold against the claim.
**Neither defence earned its place:** the system-prompt instruction to distrust repository text made no measurable difference, and stripping comments brought one finding back while losing another.
One run of this experiment produced no output because it started while code was being edited, and was rerun.
Nothing is claimed about adaptive attacks that rewrite the note until it works (D14).

### E11 - Fine-tuning a small model from the large one's reviews (negative result)

Shokhbek asked for one time-boxed fine-tuning experiment, written up whether it won or lost (D8).
The design and the success criterion were written down before any result existed.

**Question.** Can Ornith-1.5-9B (fast, 7 of 17 in E3) learn to review like Gemma 4 26B, and does it carry over to code unlike its training data?

**Data.** OWASP Benchmark for Python, split by class and label into 335 training cases and 125 held out.
For each training case, Gemma wrote a review with a private line stating the answer key; answers were kept only if they matched the key and their quotes verified.
335 labelled in 80.5 minutes of model time (median 12.7 seconds per case); 326 accepted (155 real, 171 safe), 8 rejected for having no verified finding of the labelled class, 1 for invalid JSON.
That gave 294 training and 32 validation examples, 1,261 to 3,672 tokens each (median 1,765), 588,977 tokens in all.
The student is trained on the normal prompt without the answer-key line.

**Success criterion, set in advance.** The tuned student beats the untuned one on bakery and DVWA pair accuracy, not just on OWASP.

**Training would not fit (failure, E11a).**
Standard LoRA training with `mlx_lm.lora` ran out of GPU memory on the first step at every setting tried: 16, 8 and 2 adapted layers, 4,096, 2,304 and 768 tokens, with gradient checkpointing, inside and outside the sandbox, with 85 percent of memory free.
Measured cause: 24 of the student's 32 layers are recurrent "gated delta" layers.
At inference they run in a custom Metal kernel with no gradient; in training mode `mlx-lm` replaces it with a token-by-token loop whose backward pass keeps a 2 MB state per token per layer, about 7 MB per token per adapted recurrent layer in total.
At 3,672 tokens that is about 25 GB for one recurrent layer and about 300 GB for the planned 16 layers.
Workaround (`experiments/finetune/train_lora.py`): the recurrence stays on the inference kernel and its output is treated as a constant in the backward pass, so gradients flow through everything except the recurrence itself.
This is a truncated gradient, not the exact one.
The first full run with 16 layers still ran out of memory (18.9 GB for 8 layers and 26.2 GB for 16 at 3,700 tokens); with gradient checkpointing added, the peak was 11.4 GB.
A probe loop written to test smaller settings also failed silently once, because zsh does not split unquoted variables, and had to be rerun.

**Training.** 16 layers, rank 8, learning rate 1e-4, batch 1, 900 steps (about three passes over the data), loss on the answer only, seed 7, about 3 hours (02:31 to 05:36).
Validation loss: 0.827, 0.524, 0.410, 0.401, 0.399 (step 600), 0.417, 0.536 (step 900).
Training loss dropped at each pass: about 0.45, 0.25, 0.15, so the third pass mostly memorised the training answers.
The pre-registered model is the final adapter (step 900); the step-600 checkpoint (lowest validation loss) was scored as a secondary result, chosen after the step-900 OWASP score had been seen.

**Held-out OWASP cases** (61 real, 64 safe; an unusable answer counts as not flagged):

| Model | TPR | FPR | Score | Unusable answers | Minutes |
|---|---|---|---|---|---|
| Teacher, Gemma 4 26B, Ollama | 0.639 | 0.422 | 0.217 | 1 | 31.7 |
| Student, untuned | 0.279 | 0.219 | 0.060 | 45 | 58.1 |
| Student, step 900 | 0.361 | 0.109 | 0.251 | 10 | 26.0 |
| Student, step 600 | 0.672 | 0.203 | 0.469 | 13 | 26.5 |

On answered cases only: teacher 0.211 (124 answered), untuned 0.114 (80), step 900 0.274 (115), step 600 0.483 (112).

**Bakery benchmark** (20 files):

| Student | Found | Recall | Precision | Decoys | Still flagged in twin | Pair accuracy | Unusable answers (vulnerable, twin) | Seconds per scan |
|---|---|---|---|---|---|---|---|---|
| Untuned | 13 | 0.765 | 0.650 | 4 | 9 | 0.294 | 3, 3 | 403 |
| Step 900 | 5 | 0.294 | 0.833 | 0 | 0 | 0.294 | 7, 4 | 218 |
| Step 600 | 1 | 0.059 | 0.333 | 2 | 0 | 0.059 | 2, 3 | 143 |

**DVWA pairs:**

| Student | Detected | Secure flagged | Pair accuracy | Unusable answers (vulnerable, secure) | Seconds per scan |
|---|---|---|---|---|---|
| Untuned | 2 (brute, sqli) | 2 | 0.1 | 4, 3 | 178 |
| Step 900 | 1 (exec) | 1 | 0.0 | 4, 0 | 219 |
| Step 600 | 2 (exec, sqli_blind) | 0 | 0.2 | 2, 0 | 94 |

**Verdict: the criterion was not met.**
Step 900 ties on bakery pair accuracy (0.294) and is worse on DVWA (0.0 against 0.1); step 600 is much worse on bakery (0.059) and better on DVWA by one module, which is noise.

What happened:

- In distribution, tuning worked better than expected: the step-600 student beat its own teacher, 0.469 against 0.217, because it learned the benchmark's notion of "safe" from answers filtered by the answer key; the teacher on its own flagged 42 percent of the safe look-alikes.
- Part of the gain is answer format: without schema enforcement the untuned student gave unusable output on 45 of 125 cases.
- Out of distribution, tuning did harm, more broadly than predicted.
  The step-900 student also lost SQL injection, path traversal and weak password hashing, all inside its training classes, and on the bakery code reported only command injection, cross-site scripting and "trust boundary violation" (CWE-501), an OWASP-specific class it applied three times.
- Its better precision and clean twin came from reporting almost nothing: 6 and 3 findings against 23.
- Validation loss did not predict transfer: the checkpoint with the lowest validation loss was best on OWASP and worst on bakery.

Per class on the held-out cases (real found / real, safe flagged / safe):

| Class | Teacher | Untuned | Step 900 | Step 600 |
|---|---|---|---|---|
| cmdi | 4/4, 1/2 | 0/4, 1/2 | 3/4, 1/2 | 4/4, 1/2 |
| codeinj | 5/5, 4/5 | 4/5, 1/5 | 3/5, 3/5 | 4/5, 2/5 |
| deserialization | 4/5, 2/5 | 2/5, 3/5 | 2/5, 0/5 | 4/5, 1/5 |
| hash | 5/5, 0/5 | 3/5, 0/5 | 2/5, 0/5 | 4/5, 0/5 |
| ldapi | 5/5, 4/4 | 0/5, 0/4 | 2/5, 1/4 | 3/5, 1/4 |
| pathtraver | 4/5, 5/5 | 2/5, 2/5 | 1/5, 1/5 | 1/5, 2/5 |
| redirect | 4/4, 3/5 | 1/4, 3/5 | 4/4, 1/5 | 4/4, 2/5 |
| securecookie | 0/5, 0/5 | 2/5, 1/5 | 0/5, 0/5 | 3/5, 1/5 |
| sqli | 0/1, 0/3 | 0/1, 1/3 | 1/1, 0/3 | 0/1, 0/3 |
| trustbound | 0/5, 0/5 | 1/5, 0/5 | 0/5, 0/5 | 2/5, 2/5 |
| weakrand | 0/5, 0/5 | 1/5, 0/5 | 0/5, 0/5 | 2/5, 0/5 |
| xpathi | 4/5, 4/5 | 0/5, 0/5 | 3/5, 0/5 | 4/5, 0/5 |
| xss | 2/5, 2/5 | 0/5, 1/5 | 1/5, 0/5 | 4/5, 1/5 |
| xxe | 2/2, 2/5 | 1/2, 1/5 | 0/2, 0/5 | 2/2, 0/5 |

On the held-out cases the teacher found none of the insecure cookies, trust-boundary violations or weak random numbers; the step-600 student learned some of those from the answer-key-filtered labels.

Caveats: one training run, one seed, one evaluation run per configuration; truncated gradient; the step-600 choice was made after seeing a held-out score; all training code comes from one benchmark in one template style; the student ran through MLX without schema enforcement, so its numbers are not comparable with E3.
Decision: the tuned model is not used and no adapter ships (D15).

## 7. Everything that went wrong

### 7.1 Negative and failed experiments

| Experiment | What failed | What changed |
|---|---|---|
| E2 | Default reasoning never produced an answer | Output cap, reasoning off |
| E3 | Source-and-sink tier definition did not discriminate | Tier redefined after E9 (D13) |
| E4 | Published "tools hurt detection" claim did not reproduce here | Slice review kept on cost grounds |
| E6 | Repetition cannot define trust: false positives repeat too | Rejected as a tier definition |
| E7 | Two DVWA misses were pipeline faults, not model judgement | Bounded output (D11), every file reviewed (D10) |
| E8 | Qwen3.8-27B did not fit: 20 GB swap, five to six times slower | Gemma stays the default |
| E10 | Neither defence against planted instructions had a measurable effect | Structural defence relied on instead (D14) |
| E11 | Training did not fit; the tuned model met the criterion at neither checkpoint | Model not shipped (D15) |

### 7.2 Bugs found while building and evaluating

- The model copied the line-number gutter into quotes and wrote bare CWE numbers (E2); citation matching now tolerates the gutter and CWE ids are normalised.
- The ground-truth YAML lost the indentation of its code blocks, so the patches that build the twin did not apply; the content was re-indented, each weakness got an explicit anchor in the patched file, and one fix and one decoy anchor were rewritten to remove ambiguity.
- A free-text field looped on newlines until the budget ran out and lost a correct finding (E7); all output fields are now bounded.
- A file that matched no pattern was never reviewed (E7); every file is now reviewed.
- pytest collected DVWA's own tests; test discovery is now limited to `tests/`.
- The E11 filter rejected every teacher answer at first, because its "mentions the answer key" check matched the word "Benchmark" in handler names; the pattern was narrowed.
- The teacher's held-out run stopped at case 88 of 125 when Ollama aborted one looping answer ("token repeat limit reached", HTTP 500) and the error ended the run.
  The same would have ended a whole `proofer scan`.
  A failed generation is now an error for that file only, and the run was repeated in full.
- Semgrep failed in every run started from the Terminal panel on 2026-10-03, because the shell profile sets `SSL_CERT_FILE` from `python3 -m certifi`, and Homebrew's Python 3.14 has no certifi, which leaves the variable empty.
  Proofer now drops an empty value before calling Semgrep.
  This affected only the `supported` tier of the E11 student runs, which no score uses.

### 7.3 Tooling and environment problems

- The brief PDF could not be read from the Downloads folder: macOS privacy protection blocked the app even after access was granted; it was moved into the project folder.
- Disk: 32 GB free on 2026-10-02 midday, dipping to 18 GB while models ran because swap grows; Shokhbek deleted the Ornith GGUF and pruned Docker's build cache, taking free space from 42 GB to 107 GB.
- Semgrep's first run hung without output, and installing it with `uv tool install` and `uvx` also hung; it was added as a project dependency group instead.
- `uv run` without the optional group uninstalled the MLX packages; every E11 command uses `uv run --group finetune`.
- Background jobs started by the coding assistant were killed after 10 minutes; the teacher labelling job died after 53 cases and was moved, with the model server, into terminal tabs, where it resumed.
- Docker's VM competes with the model for the same 24 GB.

### 7.4 Safety-filter stops and the unbuilt `confirmed` tier

Proofer was built with an AI coding assistant (Claude Code), directed by Shokhbek, who made the scope and product decisions recorded in `docs/DECISIONS.md`.
On 2026-10-02 at about 10:41 and 13:04 the assistant's safety filter stopped a response while it was designing or describing the step that reproduces a finding against a running lab application, the `confirmed` tier.
The plan was reordered to do the stability, independent-target and baseline checks first, and the `confirmed` tier was left designed but not built (O7).

### 7.5 Measurement weaknesses

- Most configurations ran once; only E6 measures spread.
  A difference of one weakness or one DVWA module is within noise.
- The seeded benchmark, the patterns and the prompts share an author.
- The analysis-first prompt and the two E7 fixes were written after seeing results; DVWA was clean for the first comparison only.
- Timing numbers from 2026-10-03 may include slowdown from an unrelated process (section 8).

## 8. The machine crash on 2026-10-03

**What happened.** At 08:00:43 the laptop had a kernel panic and rebooted at 08:00:57.
The panic report was written at 09:11, at the first login after the reboot.

Panic: `"completeMemory() prepare count underflow" @IOGPUMemory.cpp:492`, CPU 8, in Apple's GPU memory driver (`com.apple.iokit.IOGPUFamily` 104.6.3), macOS 15.7.7 (24G720), Darwin 24.6.0.

**What was in memory at the moment of the panic** (from the report):

| Process | Resident memory | Started by |
|---|---|---|
| `llama-server` (pid 66403) | 12.1 GB | Not this project; launched from inside the Claude desktop app's process group, purpose unknown |
| `Python` (pid 80537), the process that panicked | 5.3 GB | Not this project; judging by the neighbouring processes, launched through `bash`, `caffeinate`, `uv` and `tee`; it had just started and loaded a model (about 5 seconds of CPU time, 502,191 page faults) |
| `ollama` (pid 70491) | GPU memory not counted in resident size | This project: Gemma 4 26B (about 15 GB) was still loaded, because Ollama keeps a model for 5 minutes after its last request, and the teacher run had stopped at 07:59 |

System memory: 18.7 GB wired (1,141,494 pages of 16 KB), 77 MB free (4,712 pages), compressor at 16 percent of its limit, 18 swap files.
The three models together asked for well over the machine's 24 GB.
A program should never be able to panic the kernel, so the fault is in macOS; running several large models at once is what triggered it.

**Earlier warning.** At 07:34:59 macOS logged a memory-pressure event; the largest process then was the same `llama-server`, at 5.8 GB, while the E11 teacher stage was loading Gemma.
So an unrelated 6 to 12 GB model server ran alongside at least the last part of the E11 runs, which may have slowed them but cannot change their outputs.

**Who started what.** The assistant session's command log shows it never started `llama-server` or the panicking process; at 08:00:10 to 08:00:27 it was only editing files and running the linter and unit tests.
Its own contribution to the memory pressure was Gemma left loaded in Ollama.

**What was lost.** Nothing.
The code fix written seconds before the crash, the step-600 adapter (checksum checked against the training checkpoint), all result files and all 58 tests survived.

**What changed.**

- The experiment scripts check free memory before each stage (60 percent for an MLX stage, 75 percent before loading Gemma) and stop if it is not available (`experiments/finetune/lib.sh`).
- Gemma is unloaded from Ollama as soon as its stage ends.
- The README warns against loading other large models while the experiment runs.
- The interrupted work (the step-600 evaluation and the teacher's held-out run) was rerun from the start, 09:15 to 10:23, with nothing else loaded.

## 9. Decisions

| Id | Decision |
|---|---|
| D1 | Verification first: the model proposes, the system verifies; no trust in model confidence |
| D2 | Broad scope: several languages plus dependencies, secrets and deployment configuration |
| D3 | Ollama behind a thin client, so another local runtime can be swapped in |
| D4 | Command line only |
| D5 | Deterministic candidates, the model judges narrow slices |
| D6 | A refutation pass may only lower a finding's rank, never remove it |
| D7 | The benchmark has secure twins and decoys; configurations are repeated |
| D8 | One time-boxed fine-tuning experiment after the checks (Shokhbek's call) |
| D9 | DVWA is the independent check |
| D10 | Every source file is reviewed; patterns only rank |
| D11 | All model output is length-bounded |
| D12 | Gemma 4 26B-A4B is the default model |
| D13 | `supported` means Semgrep reports the same place |
| D14 | Comments stay visible; the defence is what the agent cannot do |
| D15 | The fine-tuned small model is not used |

Open: O2, retrieval over public security knowledge (evidence says it does not improve detection; possible use for explanations only), and O7, the `confirmed` tier.

## 10. What is not done

- The `confirmed` tier (section 7.4).
- Dependency vulnerability scanning: dependency files are reviewed by the model like other files, but no advisory database is consulted.
- Context across files is limited to the definitions of imported local helpers; weaknesses judged against something outside the file (CSRF tokens, session id quality, ownership rules defined elsewhere) are the common misses.
- No test on a large real-world repository, and no splitting of very large files.
- No retrieval (O2), no SARIF output, no interface beyond the command line.

## 11. Timeline

| When | What |
|---|---|
| 2026-10-01 | Invitation from Safia's AI team; deadline 2026-10-15 |
| 10-02 10:25 | Brief received; PDF blocked by macOS privacy, moved into the project at 10:31 |
| 10:37 | Shokhbek approves verification-first design, broad scope, local runtime and model downloads |
| 10:41 | First safety-filter stop (section 7.4) |
| Late morning | Research notes (`docs/research/`), Ollama installed, project skeleton, E1, E2 |
| 11:42 to 12:35 | E3, E4, E5 |
| 12:55 to 12:59 | Disk cleanup, free space 42 GB to 107 GB |
| 13:04 | Second safety-filter stop; plan reordered |
| 13:08 | Shokhbek approves the later fine-tune and the DVWA, Semgrep and Qwen downloads |
| 13:10 to 13:53 | E6, E7 |
| 14:29 to 14:53 | E8 |
| Afternoon | E9 |
| 15:03 to 15:27 | E10 |
| 15:35 | First local commit, `d4f32a3` |
| 10-03 00:31 | Fine-tune experiment starts: OWASP fetched, cleaned, split; teacher labelling (moved to a terminal tab at 00:51 after the 10-minute kill) |
| about 02:00 to 02:31 | Training out-of-memory diagnosis and workaround |
| 02:31 to 05:36 | Training |
| 05:36 to 07:32 | Tuned and untuned student on OWASP, bakery, DVWA |
| 07:33 | Teacher held-out run starts |
| 07:34 | Memory-pressure event; unrelated `llama-server` running |
| 07:59 | Teacher run stops at case 88 (Ollama aborts a looping answer) |
| 08:00:43 | Kernel panic; reboot at 08:00:57 |
| 09:11 to 09:15 | Panic diagnosed, memory checks added, runs restarted |
| 09:15 to 10:23 | Step-600 checkpoint and teacher runs |
| 11:34 | Second local commit, `d7d3771` |
| 11:39 to 11:40 | GitHub repository created private, then made public by Shokhbek |

## 12. Reproducing

Setup and the main commands are in `README.md`:

```bash
uv sync
```

```bash
ollama pull gemma4:26b-a4b-it-qat
```

```bash
uv run proofer eval --model gemma4:26b-a4b-it-qat --prompt walkthrough --repeats 1
```

```bash
scripts/fetch_dvwa.sh
```

```bash
uv run proofer eval-pairs --model gemma4:26b-a4b-it-qat --prompt walkthrough
```

The fine-tuning experiment needs Apple silicon, the `finetune` dependency group and about seven hours; its steps are in the README section "Fine-tuning experiment".
Load only one large model at a time on a 24 GB machine (section 8).
New runs are written to `runs/`; the files behind this report are in `results/`.
