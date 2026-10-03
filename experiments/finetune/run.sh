#!/bin/sh
# E11 end to end, after build_dataset.py has written data/finetune.
# Each stage loads one model, so they run one after another. About six hours on an M4 Pro.
# The last stage needs `ollama serve` running with gemma4:26b-a4b-it-qat pulled.
set -u
STUDENT=data/cache/ornith-9b-mlx-4bit
ADAPTER=data/finetune/adapter
RUN="uv run --group finetune"
LOG=runs/finetune
mkdir -p "$LOG"

. experiments/finetune/lib.sh

stage "train"
need_free 60
$RUN python experiments/finetune/train_lora.py --model $STUDENT --train --data data/finetune \
    --mask-prompt --grad-checkpoint --num-layers 16 --batch-size 1 --iters 900 --learning-rate 1e-4 \
    --max-seq-length 4096 --steps-per-report 25 --steps-per-eval 150 --val-batches 16 \
    --save-every 150 --seed 7 --adapter-path $ADAPTER 2>&1 | tee "$LOG/train.log"
[ -f "$ADAPTER/adapters.safetensors" ] || { echo "training produced no adapter, stopping"; exit 1; }

stage "OWASP holdout, tuned"
need_free 60
$RUN python experiments/finetune/eval_cases.py --backend mlx --model $STUDENT --adapter $ADAPTER \
    --label student-tuned 2>&1 | tee "$LOG/owasp-student-tuned.log"
stage "OWASP holdout, untuned"
need_free 60
$RUN python experiments/finetune/eval_cases.py --backend mlx --model $STUDENT \
    --label student-untuned 2>&1 | tee "$LOG/owasp-student-untuned.log"

for ADAPT in "" "--adapter $ADAPTER"; do
    stage "bakery ${ADAPT:-untuned}"
    need_free 60
    $RUN proofer eval --backend mlx --model $STUDENT $ADAPT --repeats 1 2>&1 | tee -a "$LOG/bakery.log"
    stage "DVWA ${ADAPT:-untuned}"
    need_free 60
    $RUN proofer eval-pairs --backend mlx --model $STUDENT $ADAPT 2>&1 | tee -a "$LOG/dvwa.log"
done

stage "OWASP holdout, teacher with the normal prompt"
need_free 75
$RUN python experiments/finetune/eval_cases.py --backend ollama --model gemma4:26b-a4b-it-qat \
    --label teacher 2>&1 | tee "$LOG/owasp-teacher.log"
unload_teacher
stage "done"
