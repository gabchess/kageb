#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"
root="$(git -C "$script_dir" rev-parse --show-toplevel)"
cd "$root"

cargo_bin="$(resolve_cargo)"
solana_bin="$(resolve_solana)"
export PATH="$(dirname "$cargo_bin"):$(dirname "$solana_bin"):$PATH"
first="$(mktemp)"
second="$(mktemp)"
trap 'rm -f "$first" "$second"' EXIT

LC_ALL=C TZ=UTC "$cargo_bin" run --locked --quiet -p kageb-host --bin kageb -- demo local > "$first"
LC_ALL=C TZ=UTC "$cargo_bin" run --locked --quiet -p kageb-host --bin kageb -- demo local > "$second"

if ! cmp -s "$first" "$second"; then
  echo "local demo output changed between identical runs" >&2
  diff -u "$first" "$second" >&2 || true
  exit 1
fi

grep -Fqx "SETTLED: one aggregate" "$first"
grep -Fqx "QUORUM: all 3 two-share paths agree" "$first"
grep -Fqx "RESULTS: authenticated balances persisted" "$first"
grep -Fqx "BALANCED: zero residual; no venue leg" "$first"
grep -Fqx "EXPIRED: underfilled; reservations released" "$first"
grep -Fqx "OBSERVER: direct 4 orders; KageB 1 aggregate" "$first"
cat "$first"
echo "local demo is deterministic"
