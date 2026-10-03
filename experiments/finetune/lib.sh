# Shared by run.sh and run_extra.sh.
# On 2026-10-03 the teacher model left loaded in Ollama, an unrelated 12 GB llama-server and a
# freshly loaded MLX model together exhausted memory, and the GPU driver panicked the kernel.
# So each stage checks for headroom first, and Ollama's model is unloaded when it is done.

stage() { echo "=== $1 ($(date +%H:%M))"; }

need_free() {
    free=$(memory_pressure | awk '/free percentage/ {print $5 + 0}')
    if [ "$free" -lt "$1" ]; then
        echo "only ${free}% of memory free, this stage needs $1%; stopping"
        exit 1
    fi
}

unload_teacher() {
    curl -s -m 60 http://127.0.0.1:11434/api/generate \
        -d '{"model": "gemma4:26b-a4b-it-qat", "keep_alive": 0}' >/dev/null || true
}
