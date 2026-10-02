# Decisions

Each entry records what was decided, why, and what was rejected.
Dates are absolute.

## Settled

### D1 - Verification-first design (2026-10-02)

The model proposes; the system verifies.
A finding is reported with one of three tiers: `suspected`, `supported`, or `confirmed`.
Reason: models in the 14B to 24B range that fit this laptop produce many plausible but wrong findings, so unverified output is not useful to a developer.
Rejected: asking the model for a confidence score and trusting it.

### D2 - Broad scope (2026-10-02)

The agent covers several languages plus dependencies, secrets, and container or infrastructure configuration, not only Python web apps.
Reason: the brief says "software platform or codebase", and a real platform is rarely one language.
Consequence: breadth must come from language-agnostic mechanisms (text and syntax-tree search, existing multi-language scanners, checks at the HTTP boundary), not from per-language custom logic.

### D3 - Local runtime behind a thin client (2026-10-02)

Ollama is the default runtime because a reviewer can reproduce it with one install and one pull.
The agent talks to it through a small client interface so another local runtime can be swapped in.
Rejected for now: running models in-process, which ties the agent to one runtime.

### D4 - Command line only (2026-10-02)

The brief asks not to spend time on interface polish.

### D5 - Deterministic candidates, model as judge of narrow slices (2026-10-02)

Pattern matching and existing scanners decide where to look.
The model receives one small slice of code per candidate and decides whether the weakness is real, citing the lines.
Reason: published results put small open models below a rule-based scanner at finding vulnerable files in a whole repository, and detection drops sharply as context grows (see `docs/research/prior-art.md`).
Rejected: letting the model explore the repository freely as the primary discovery method.
Still to measure: whether giving the model read and search tools helps or hurts compared with putting the slice in the prompt (experiment E2).

### D6 - Refutation ranks, it does not reject (2026-10-02)

This revises D1.
A second model pass that argues against a finding only lowers its rank; it cannot remove it.
Reason: in published work, LLM filtering helped only large models and suppressed true positives with weaker ones.
The tiers are now: `suspected` (citations verified), `supported` (citations verified and the cited lines include both where untrusted data enters and where it is used), `confirmed` (a deterministic validator observed the effect in a local lab container).
The verdict for `confirmed` is never a model opinion.

### D7 - Benchmark uses secure twins and repeated runs (2026-10-02)

Every seeded weakness has a patched variant, and the benchmark includes safe code that looks risky.
Each configuration is run more than once and the spread is reported.
Reason: a detector that flags everything looks good on vulnerable code alone, and single-run agent scores are unstable.

### D8 - One time-boxed fine-tuning experiment, after the checks (2026-10-02)

Shokhbek's call: run a one-day fine-tune of a small model later, and write it up whether it wins or loses.
It comes after the stability repeats and the independent check, because those decide whether the current result is real.
Constraints known in advance: this laptop can tune models up to roughly 14B, so the tuned model will be smaller than the current best; the public datasets are mostly C and C++ with weak labels.
Reason for doing it anyway: the brief values an experiment that was tried and learned from, and the published evidence against fine-tuning has not been checked on our targets.

### D9 - DVWA is the independent check (2026-10-02)

Ten DVWA modules are scored as vulnerable and secure file pairs (`bench/truth/dvwa.yaml`).
The modules and their weakness classes were fixed before any model was run on them.
DVWA is fetched at a pinned commit and not vendored, because it is GPL-3.0.
What it checks: whether results hold on code and a language (PHP) that played no part in writing the prompts or patterns.
What it does not check: memorisation, since DVWA is widely published and models have certainly seen it.

### D10 - Every source file is reviewed; patterns only rank (2026-10-02)

This revises D5 and settles O8.
A file that matches no pattern is still shown to the model.
Reason: on DVWA the weak session id handler matched nothing and was never reviewed (E7), and the weaknesses patterns cannot point at are mostly missing checks, which are also what the model adds most value on.
Cost: more model calls on large repositories, bounded by `--max-leads`.

### D11 - All model output is length-bounded (2026-10-02)

Every string and list in the output schema has a maximum length, in addition to the overall output cap.
Reason: constrained decoding looped inside a free-text field and lost a correct finding (E7).

### D12 - Gemma 4 26B-A4B is the default model (2026-10-02)

This settles O1.
Three models were measured on the same pipeline (E3, E8).
Ornith-1.5-9B was below the no-model pattern baseline on recall.
Qwen3.8-27B tied Gemma 4 on accuracy but ran five to six times slower and pushed the machine into heavy swap.
Gemma 4 26B-A4B gives the best accuracy per minute on the target hardware.
The model is a command line option, so a reviewer with more memory can choose differently.

### D13 - `supported` means an independent scanner agrees (2026-10-02)

This revises D6 and settles O6.
A finding is `supported` when its citations verify and Semgrep reports within three lines of a cited span; otherwise it is `suspected`.
Findings worded with hedges are ranked last within their tier.
Reason: measured on saved runs (E9), scanner agreement had precision 1.00 against 0.70 without it, hedged findings 0.53 against 0.86, and the model's own source and sink labels did not separate true from false at all.
Rejected: agreement across repeated runs, because the model's false positives repeat as reliably as its true findings (E6).
Limit: the tier covers under half of the true findings, so it is used to rank and never to filter.

### D14 - Comments stay visible; the defence is what the agent cannot do (2026-10-02)

This settles O5.
Comments are shown to the model by default, and `--strip-comments` is available.
Reason: a static planted note cost at most one finding, and stripping comments gave that finding back while losing another (E10). Neither the stripping nor the trust-boundary instruction made a measurable net difference.
The protection that does not depend on the model is structural: read-only tools, no execution, no network, a local-only model endpoint, and path confinement.
Not claimed: robustness to adaptive attacks that iterate on the planted text.

## Open

- O2: Retrieval over public security knowledge. Evidence says it does not raise detection accuracy on open models. Proposed use: explanations and fixes only, plus one small ablation to check the claim on our benchmark.
- O7: Dynamic confirmation against a local lab container, the `confirmed` tier, is designed but not built.
