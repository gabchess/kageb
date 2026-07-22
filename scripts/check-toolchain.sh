#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"

cargo_bin="$(resolve_cargo)"
rustc_bin="$(resolve_rustc)"
solana_bin="$(resolve_solana)"
export PATH="$(dirname "$cargo_bin"):$(dirname "$solana_bin"):$PATH"

rustc_version="$("$rustc_bin" --version)"
case "$rustc_version" in
  "rustc 1.95.0 "*) ;;
  *)
    echo "expected rustc 1.95.0, found: $rustc_version" >&2
    exit 1
    ;;
esac

solana_version="$("$solana_bin" --version)"
case "$solana_version" in
  "solana-cli 4.0.1 "*) ;;
  *)
    echo "expected Solana CLI 4.0.1, found: $solana_version" >&2
    exit 1
    ;;
esac

sbf_version="$("$cargo_bin" build-sbf --version | sed -n '1p')"
if [[ "$sbf_version" != "cargo-build-sbf 4.0.0" ]]; then
  echo "expected cargo-build-sbf 4.0.0, found: $sbf_version" >&2
  exit 1
fi

printf '%s\n%s\n%s\n' "$rustc_version" "$solana_version" "$sbf_version"
