#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"
root="$(git -C "$script_dir" rev-parse --show-toplevel)"
cd "$root"

evidence="${1:-evidence/devnet.json}"
rpc="${KAGEB_DEVNET_RPC:-https://api.devnet.solana.com}"
cargo_bin="$(resolve_cargo)"
solana_bin="$(resolve_solana)"
export PATH="$(dirname "$cargo_bin"):$(dirname "$solana_bin"):$PATH"
expected_commit="5baf9651925ac2fd546b28604ecc0fe2f49d45ae"

if [[ ! -f "$evidence" || -L "$evidence" ]]; then
  echo "a regular evidence file is required" >&2
  exit 1
fi

actual_commit="$(python3 - "$evidence" <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as source:
    print(json.load(source)["content"]["public_commit"])
PY
)"
if [[ "$actual_commit" != "$expected_commit" ]]; then
  echo "evidence names an unexpected public checkpoint" >&2
  exit 1
fi

./scripts/check-toolchain.sh
"$cargo_bin" run --locked --quiet -p kageb-host --bin kageb -- \
  verify evidence "$evidence" --rpc "$rpc"
