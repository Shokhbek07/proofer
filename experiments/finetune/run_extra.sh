#!/bin/sh
# Added after the main run (see E11): the step-600 checkpoint, which had the lowest
# validation loss, and the teacher stage, rerun after one aborted generation stopped it.
set -u
STUDENT=data/cache/ornith-9b-mlx-4bit
ADAPTER=data/finetune/adapter-600
RUN="uv run --group finetune"
LOG=runs/finetune
. experiments/finetune/lib.sh

stage "OWASP holdout, step-600 checkpoint"
need_free 60
$RUN python experiments/finetune/eval_cases.py --backend mlx --model $STUDENT --adapter $ADAPTER \
    --label student-tuned-600 2>&1 | tee "$LOG/owasp-student-tuned-600.log"
stage "bakery, step-600 checkpoint"
need_free 60
$RUN proofer eval --backend mlx --model $STUDENT --adapter $ADAPTER --repeats 1 2>&1 | tee -a "$LOG/bakery.log"
stage "DVWA, step-600 checkpoint"
need_free 60
$RUN proofer eval-pairs --backend mlx --model $STUDENT --adapter $ADAPTER 2>&1 | tee -a "$LOG/dvwa.log"
stage "OWASP holdout, teacher with the normal prompt"
need_free 75
$RUN python experiments/finetune/eval_cases.py --backend ollama --model gemma4:26b-a4b-it-qat \
    --label teacher 2>&1 | tee "$LOG/owasp-teacher.log"
unload_teacher
stage "done"
