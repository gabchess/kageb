#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"
root="$(git -C "$script_dir" rev-parse --show-toplevel)"
cd "$root"

cargo_bin="$(resolve_cargo)"
solana_bin="$(resolve_solana)"
export PATH="$(dirname "$cargo_bin"):$(dirname "$solana_bin"):$PATH"
export CARGO="$cargo_bin"

./scripts/check-toolchain.sh
./scripts/scan-public.sh
python3 ./scripts/check-licenses.py

"$cargo_bin" fmt --all -- --check
"$cargo_bin" clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="${RUSTDOCFLAGS:+$RUSTDOCFLAGS }-D warnings" \
  "$cargo_bin" doc --workspace --all-features --locked --no-deps

"$cargo_bin" build-sbf --manifest-path crates/kageb-program/Cargo.toml -- --locked
"$cargo_bin" build-sbf --manifest-path crates/kageb-token-fixture/Cargo.toml -- --locked
"$cargo_bin" test --workspace --locked

trace_output="$("$cargo_bin" run --locked --quiet -p kageb-host --bin kageb -- trace)"
grep -Fq "DIRECT: 4 wallet-linked orders visible" <<< "$trace_output"
grep -Fq "KAGEB: 0 individual orders visible" <<< "$trace_output"
grep -Fq "no decoy trades" <<< "$trace_output"

./scripts/check-local-demo.sh
