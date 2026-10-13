#!/bin/sh
# E12 to E14 (docs/EXPERIMENTS.md): real security fixes, the project map, and repeats.
# Run from the repository root with Docker and every other model stopped.
#
# Each stage is one configuration with one seed and writes its own result file, so a stop
# loses at most one stage. Stages are interleaved by seed, so a partial run still compares
# the two arms on the same seeds. A finished stage leaves a marker in $LOG/done and is
# skipped when the script is started again.
#
# The per-stage memory guard is 68% free. The crash on 2026-10-03 came from three large
# models resident at once; the rule is one at a time, which this script keeps by unloading
# the model after every stage. With Docker stopped the machine idles near 74% free (macOS
# and the desktop app), and one loaded Gemma (measured 15.8 GB) drops it to about 10%, so a
# 75% gate can never be met. 68% clears the idle floor yet still blocks if a second large
# model or Docker is loaded, because that would push free well below 68%.
set -u
MODEL=gemma4:26b-a4b-it-qat
FREE=68
LOG=runs/followup
OUT=runs/followup/eval
mkdir -p "$LOG/done" "$OUT"
. experiments/lib.sh

# run NAME MINIMUM_FREE_PERCENT PROOFER_ARGUMENTS...
run() {
    name=$1
    free_needed=$2
    shift 2
    # Clean pause: `touch runs/followup/PAUSE` stops the run at the next stage
    # boundary with no half-finished stage. Delete the flag and relaunch to resume.
    if [ -f "$LOG/PAUSE" ]; then
        echo "=== paused ($LOG/PAUSE present); stopping before $name"
        exit 0
    fi
    if [ -f "$LOG/done/$name" ]; then
        echo "=== $name: done earlier, skipped"
        return
    fi
    stage "$name"
    need_free "$free_needed"
    if uv run proofer "$@" --out "$OUT" >"$LOG/$name.log" 2>&1; then
        touch "$LOG/done/$name"
        tail -n 3 "$LOG/$name.log"
    else
        echo "stage $name failed; see $LOG/$name.log"
    fi
    unload_teacher
}

# Baselines with no model, on the files each fix changed.
run real-patterns 0 eval-real --mode patterns
run real-semgrep 0 eval-real --mode semgrep

for seed in 7 8 9 10 11; do
    for context in none map; do
        run "real-$context-$seed" $FREE eval-real --model $MODEL --temperature 0.7 --seed $seed \
            --context $context
        run "bakery-$context-$seed" $FREE eval --model $MODEL --temperature 0.7 --seed $seed \
            --repeats 1 --context $context
        run "dvwa-$context-$seed" $FREE eval-pairs --model $MODEL --temperature 0.7 --seed $seed \
            --context $context
    done
done
stage "done"
