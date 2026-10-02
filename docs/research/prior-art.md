# Prior art and evidence (2026-10-02)

This is a literature pass done before building, to find evidence that could change the design.
Verification status is marked per item:
`[A]` means the claim was checked against the paper abstract or primary page on 2026-10-02,
`[S]` means it comes from a secondary read of the source and should be re-checked before being quoted in the submission.

## Existing systems and what they teach

- **Vulnhuntr** (Protect AI): follows the call chain from entry point to sink with an LLM. Python only. Its README reports that open models failed to produce structured output. `[S]` https://github.com/protectai/vulnhuntr
- **Naptime and Big Sleep** (Google): variant analysis from a known fix, with a sanitizer crash as the verdict rather than model opinion. `[S]` https://projectzero.google/2024/10/from-naptime-to-big-sleep.html
- **IRIS**: the LLM labels taint sources and sinks, CodeQL does the dataflow. 55 detected against 27 for CodeQL alone, with GPT-4. `[A]` Small models found many but at 92 to 96 percent false discovery, and an LLM filtering pass helped only the largest models and hurt the small ones. `[S]` https://arxiv.org/abs/2405.17238
- **DARPA AIxCC finalists**: every finding needed a proof input. LLM-judged triage got 9 to 10 of 13 right against 100 percent for proof-backed findings. About 40 percent of patches that passed checks were semantically wrong. `[S]` https://arxiv.org/abs/2602.07666
- **XBOW**: the LLM explores, deterministic validators decide (planted canary or flag, headless browser for script injection). `[S]` https://xbow.com/blog/top-1-how-xbow-did-it
- **Semgrep study of coding agents**: 14 to 18 percent true-positive rate, and identical runs gave 3, 6, then 11 findings. `[S]` https://semgrep.dev/blog/2025/finding-vulnerabilities-in-modern-web-apps-using-claude-code-and-openai-codex/
- **claude-code-security-review**: diff-only, exclusion list, second-pass filter; its README says it is not hardened against prompt injection. `[S]` https://github.com/anthropics/claude-code-security-review
- **Heelan with o3**: a known bug was found in 8 of 100 runs at 3.3k lines of context and 1 of 100 at 12k lines. `[S]` https://sean.heelan.io/2025/05/22/how-i-used-o3-to-find-cve-2025-37899-a-remote-zeroday-vulnerability-in-the-linux-kernels-smb-implementation/

## Measured detection ability

- **PrimeVul**: a model scoring 68 percent F1 on BigVul scored 3 percent on a de-duplicated, correctly labelled set; GPT-4 was below random on vulnerable and patched pairs. `[S]` https://arxiv.org/abs/2403.18624
- **VLoc Bench** (September 2026, 500 real vulnerabilities, 290 repositories): the strongest system reaches 0.229 file-level F1. `[A]` Small open models were reported below Semgrep, and their true-negative rate on patched repositories was 0.56 to 0.68 against 0.91 for Semgrep. `[S]` https://arxiv.org/abs/2609.15939
- **SecLens**: compares code-in-prompt with tool-use settings. `[A]` Tool use was reported to lower detection at 10 to 100 times the cost. `[S]` https://arxiv.org/abs/2604.01637
- **Vul-RAG replication on open-weight models**: plateau at about 0.30 pairwise accuracy regardless of model size or recency. `[A]` https://arxiv.org/abs/2606.04739
- **Fine-tuning**: tuned detectors key on surface patterns and break under semantics-preserving edits. `[S]` https://arxiv.org/abs/2601.22655
- **False-positive filtering with agents**: strong models cut the OWASP Benchmark false-positive rate from 92 to 6 percent; with a weaker backbone the agent loop did not beat plain prompting and suppressed 145 true positives. `[S]` https://arxiv.org/abs/2601.22952

## Local benchmark targets with ground truth

| Target | Stack | Ground truth | Secure twin | Licence |
|---|---|---|---|---|
| OWASP BenchmarkPython | Python | CSV, 452 real and 778 fake cases | built in | GPL-3.0 |
| OWASP BenchmarkJava | Java servlets | CSV, 1,415 real and 1,325 fake cases | built in | GPL-2.0 |
| DVWA | PHP | 19 modules with four levels each | `impossible.php` | GPL-3.0 |
| VAmPI | Flask | README and OpenAPI | `vulnerable=0` switch | MIT |
| DVNA | Node and Express | guide | `fixes` branches | MIT |
| Juice Shop | TypeScript and Express | `vuln-code-snippet` markers, 35 with fix files | per snippet | MIT |
| ossf-cve-benchmark | JS and TS, 200+ real CVEs | pre and post patch commits | yes | MIT |

No ground-truthed public target was found for Go, secrets, or container and infrastructure configuration.

## Knowledge sources and their licences

- MITRE CWE: XML and CSV, reuse permitted with copyright notice.
- OWASP Cheat Sheets, ASVS, WSTG: CC-BY-SA-4.0, Markdown.
- Semgrep community rules: internal use only, no redistribution, so they cannot be bundled in this repository.
- CodeQL: queries are MIT, but the CLI is free only for public code.
- Fine-tuning datasets (BigVul, CrossVul, CVEfixes, DiverseVul, PrimeVul, MegaVul) are function-level, mostly C and C++, with label accuracy between 25 and 60 percent for all but PrimeVul. `[S]`

## Prompt injection through repository content

- Comments, pull request titles and hidden HTML have been used to hijack code review agents into leaking secrets. `[S]` https://www.securityweek.com/claude-code-gemini-cli-github-copilot-agents-vulnerable-to-prompt-injection-via-comments/
- Adaptive "this is safe" comments flip LLM detectors more than 90 percent of the time; prompt-level defences are weak, comment sanitisation and isolation work. `[S]` https://arxiv.org/abs/2607.24964
- Counter-evidence: a large trial found static adversarial comments had no significant effect, and stripping comments hurt weaker models. `[S]` https://arxiv.org/abs/2602.16741

## What this changes

1. The small model should not be the discoverer. Candidates come from deterministic tooling, and the model judges narrow slices.
2. An LLM refutation pass is not a reliable gate at this model size. It can rank, but it must not reject.
3. Fine-tuning and Vul-RAG style retrieval are unlikely to raise detection accuracy and the available data is a poor match for web languages.
4. Scores need secure twins and repeated runs, because single-run numbers are unstable.
5. Context must stay small, and the conflicting evidence on comment stripping makes it an experiment to run, not an assumption.
