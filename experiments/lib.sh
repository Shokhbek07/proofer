# Shared by the experiment run scripts.
# On 2026-10-03 the teacher model left loaded in Ollama, an unrelated 12 GB llama-server and a
# freshly loaded MLX model together exhausted memory, and the GPU driver panicked the kernel.
# So each stage checks for headroom first, and Ollama's model is unloaded when it is done.

stage() { echo "=== $1 ($(date +%H:%M))"; }

# Waits up to two minutes, since memory comes back gradually after a model is unloaded.
need_free() {
    tries=0
    while :; do
        free=$(memory_pressure | awk '/free percentage/ {print $5 + 0}')
        [ "$free" -ge "$1" ] && return 0
        tries=$((tries + 1))
        if [ "$tries" -ge 24 ]; then
            echo "only ${free}% of memory free, this stage needs $1%; stopping"
            exit 1
        fi
        sleep 5
    done
}

unload_teacher() {
    curl -s -m 60 http://127.0.0.1:11434/api/generate \
        -d '{"model": "gemma4:26b-a4b-it-qat", "keep_alive": 0}' >/dev/null || true
}
