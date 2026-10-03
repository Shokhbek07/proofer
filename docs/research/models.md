# Local models and runtimes (2026-10-02)

A survey of what fits on the target laptop (Apple M4 Pro, 24 GB) before running our own bake-off.
Benchmark scores below are vendor-reported unless marked independent, and were collected by a secondary read of the source pages.
Tags and repository ids marked `[pulled]` were confirmed by downloading them on 2026-10-02.

## Shortlist

| Model | Id | Size | Notes |
|---|---|---|---|
| Ornith-1.5-9B | `hf.co/ornith-ai/Ornith-1.5-9B-GGUF:Q8_0` `[pulled]` | 9.8 GB | 9.2B dense, Qwen 3.5 architecture, MIT. Small vendor with self-reported scores. Thinks by default. |
| Gemma 4 26B-A4B | `gemma4:26b-a4b-it-qat` `[pulled]` | 15 GB | 25B mixture of experts with about 4B active, Apache-2.0. Open tool-parser issues in Ollama. |
| Qwen3.8-27B | `hf.co/unsloth/Qwen3.8-27B-GGUF:UD-Q4_K_S` | 15.4 GB | 27.8B dense, Apache-2.0. Strongest reported coding scores, slow on Apple Silicon, memory is tight at 32k context. |
| gpt-oss-20b | `gpt-oss:20b` | 14 GB | Open Ollama bug with its own tool calls. Reserve. |
| Devstral Small 2 | `devstral-small-2:24b` | 15 GB | Vendor suggests 32 GB. Reserve. |

## Security-specialised models

- Cisco Antares-1B localises vulnerable files from a CWE description; possible cheap pre-filter, not a reviewer.
- VulnLLM-R-7B does function-level detection for C, C++, Python and Java, without tool calling.
- Foundation-Sec-8B-Reasoning and WhiteRabbitNeo have no published code review evaluation.
- No independent evaluation of any of these on code review was found.

## Runtime

- Ollama is the easiest for a reviewer to reproduce, and its native API lets the client set the context size per request.
- Its default context is small and its OpenAI-compatible endpoint cannot change it, so this project uses the native endpoint.
- llama.cpp `llama-server` has the fewest open tool-parser bugs and is the fallback if tool calling proves unreliable.
- Schema-constrained JSON output cannot be combined with tools in llama-server, which is one more reason findings are produced in a tool-free call.

## Fine-tuning feasibility on this machine

- LoRA is practical up to about 8B, QLoRA up to about 14B; 27B is not.
- Measured later (E11a): that estimate holds for plain transformer models only.
  The Qwen 3.5 family has recurrent layers whose training path in `mlx-lm` costs about 7 MB per token per layer, so on those the limit is sequence length, not parameter count.
- A few thousand examples would take hours per epoch.
- Serving a tuned Qwen or Gemma model needs a fuse, convert, quantise chain.
- See decision D8 for the one time-boxed experiment that was run, and E11 for its result.

## Sources

- https://ollama.com/library/gemma4/tags
- https://huggingface.co/ornith-ai/Ornith-1.5-9B-GGUF
- https://huggingface.co/unsloth/Qwen3.8-27B-GGUF
- https://huggingface.co/openai/gpt-oss-20b
- https://huggingface.co/mistralai/Devstral-Small-2-24B-Instruct-2512
- https://huggingface.co/fdtn-ai/antares-1b
- https://huggingface.co/Virtue-AI-HUB/VulnLLM-R-7B
- https://docs.ollama.com/context-length
- https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md
- https://github.com/ml-explore/mlx-lm/blob/main/mlx_lm/LORA.md
