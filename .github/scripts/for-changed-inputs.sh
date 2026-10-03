#!/usr/bin/env bash
# Usage: for-changed-inputs.sh BASE_REF HEAD_REF COMMAND [ARGS...]
#
# Runs COMMAND with the mitre_input/ request files (*.yaml, *.yml) that were added, modified or
# renamed between BASE_REF and HEAD_REF appended as arguments. An empty or all-zero BASE_REF
# (manual runs, or the first push of a branch) selects every request file instead.
set -euo pipefail

base=$1
head=$2
shift 2

pathspec=(':(glob)mitre_input/*.yaml' ':(glob)mitre_input/*.yml')
list=$(mktemp)
trap 'rm -f "$list"' EXIT

if [[ -z "$base" || "$base" =~ ^0+$ ]]; then
  git ls-files -z -- "${pathspec[@]}" > "$list"
else
  git diff -z --name-only --diff-filter=AMR "$base" "$head" -- "${pathspec[@]}" > "$list"
fi

mapfile -d '' -t files < "$list"
if (( ${#files[@]} == 0 )); then
  echo "No request files to process."
  exit 0
fi

printf 'Processing %s\n' "${files[@]}"
"$@" "${files[@]}"
