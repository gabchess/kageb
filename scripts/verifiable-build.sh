#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(git -C "$script_dir" rev-parse --show-toplevel)"
config="$root/verifiable-build.json"

solana_verify="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["solana_verify"])' "$config")"
build_image="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["build_image"])' "$config")"

command -v docker >/dev/null
command -v solana-verify >/dev/null
test "$(solana-verify --version)" = "$solana_verify"

solana-verify build "$root" \
  --workspace-path "$root" \
  --library-name kageb_program \
  --base-image "$build_image"

test -s "$root/target/deploy/kageb_program.so"
