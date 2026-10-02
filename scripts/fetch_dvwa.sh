#!/bin/sh
# Fetch DVWA at the commit the ground truth was written against.
# It is only read as source text; nothing in it is executed or served.
set -eu
dest="bench/external/DVWA"
commit="43b0f8b13b7c824b08b228abfd868b5e4c110a5d"
if [ ! -d "$dest/.git" ]; then
    git clone https://github.com/digininja/DVWA.git "$dest"
fi
git -C "$dest" fetch --quiet origin "$commit"
git -C "$dest" checkout --quiet "$commit"
echo "DVWA ready at $dest ($commit)"
