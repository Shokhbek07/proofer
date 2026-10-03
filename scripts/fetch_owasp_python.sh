#!/bin/sh
# Fetch OWASP Benchmark for Python at the commit the experiments used.
# It is only read as source text; nothing in it is executed or served.
set -eu
dest="bench/external/BenchmarkPython"
commit="f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
if [ ! -d "$dest/.git" ]; then
    git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git "$dest"
fi
git -C "$dest" fetch --quiet origin "$commit"
git -C "$dest" checkout --quiet "$commit"
echo "OWASP BenchmarkPython ready at $dest ($commit)"
