"""LoRA training for the student, with the recurrent mixers held constant.

The student (Qwen 3.5 architecture) alternates three recurrent "gated delta"
layers with one attention layer. In training mode mlx-lm unrolls the
recurrence token by token so that it can be differentiated, and the backward
pass then keeps a 2 MB state per token per layer. Measured here: about 7 MB per
token for each adapted recurrent layer, which is about 90 GB for six such
layers at 2,300 tokens. It does not fit in 24 GB at any useful length.

This wrapper keeps the recurrence on the inference kernel and treats its
output as a constant. Gradients still reach the adapters through the residual
stream, the MLPs, the attention layers and the gate and output projection of
each recurrent layer. They do not flow through the recurrence itself, so the
adapters on its q, k, v and gate inputs receive no update. This is a truncated
gradient, not the exact one.

Usage (all other arguments are those of `mlx_lm.lora`):
    uv run --group finetune python experiments/finetune/train_lora.py \
        --model data/cache/ornith-9b-mlx-4bit --train --data data/finetune ...
"""

from __future__ import annotations

import mlx.core as mx
from mlx_lm import lora
from mlx_lm.models import qwen3_5

_update = qwen3_5.gated_delta_update


def constant_recurrence(q, k, v, a, b, A_log, dt_bias, state=None, mask=None, **options):
    options["use_kernel"] = True
    q, k, v, a, b = (mx.stop_gradient(t) for t in (q, k, v, a, b))
    out, state = _update(q, k, v, a, b, A_log, dt_bias, state, mask, **options)
    return mx.stop_gradient(out), mx.stop_gradient(state)


if __name__ == "__main__":
    qwen3_5.gated_delta_update = constant_recurrence
    lora.main()
