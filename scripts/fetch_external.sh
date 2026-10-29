#!/usr/bin/env bash
# Fetch external inputs at the commits pinned in PREREGISTRATION.md.
# They live in ext/ (git-ignored) so the repo stays small.
set -euo pipefail

STP_COMMIT=13f15f4bccc8e33510f281406eb59b542fd34b24
SIGMA_COMMIT=05d1031f537e830b76da53bae2400c5814c89165

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT="$ROOT/ext"
mkdir -p "$EXT"

fetch() {  # fetch <url> <dir> <commit> [sparse-path]
  local url=$1 dir=$2 commit=$3 sparse=${4:-}
  if [ ! -d "$dir/.git" ]; then
    git init -q "$dir"
    git -C "$dir" remote add origin "$url"
  fi
  if [ -n "$sparse" ]; then
    git -C "$dir" sparse-checkout set "$sparse"
  fi
  git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$commit"
  git -C "$dir" checkout -q FETCH_HEAD
  echo "$(basename "$dir"): $(git -C "$dir" rev-parse HEAD)"
}

fetch https://github.com/center-for-threat-informed-defense/summiting-the-pyramid.git "$EXT/stp" "$STP_COMMIT"
fetch https://github.com/SigmaHQ/sigma.git "$EXT/sigma" "$SIGMA_COMMIT" rules/windows
