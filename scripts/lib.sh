#!/usr/bin/env bash

resolve_candidate() {
  local candidate="$1"
  if [[ "$candidate" == */* ]]; then
    [[ -x "$candidate" ]] && printf '%s\n' "$candidate"
  else
    command -v "$candidate" 2>/dev/null
  fi
}

resolve_cargo() {
  local resolved
  if [[ -n "${CARGO:-}" ]]; then
    resolved="$(resolve_candidate "$CARGO" || true)"
    if [[ -z "$resolved" ]]; then
      echo "CARGO does not name an executable" >&2
      return 1
    fi
    printf '%s\n' "$resolved"
    return
  fi
  if resolved="$(command -v cargo 2>/dev/null)"; then
    printf '%s\n' "$resolved"
    return
  fi
  if [[ -n "${HOME:-}" && -x "$HOME/.cargo/bin/cargo" ]]; then
    printf '%s\n' "$HOME/.cargo/bin/cargo"
    return
  fi
  echo "cargo was not found; set CARGO, add cargo to PATH, or install it at HOME/.cargo/bin/cargo" >&2
  return 1
}

resolve_rustc() {
  local resolved cargo_bin
  if [[ -n "${RUSTC:-}" ]]; then
    resolved="$(resolve_candidate "$RUSTC" || true)"
    if [[ -z "$resolved" ]]; then
      echo "RUSTC does not name an executable" >&2
      return 1
    fi
    printf '%s\n' "$resolved"
    return
  fi
  if resolved="$(command -v rustc 2>/dev/null)"; then
    printf '%s\n' "$resolved"
    return
  fi
  cargo_bin="$(resolve_cargo)"
  if [[ -x "$(dirname "$cargo_bin")/rustc" ]]; then
    printf '%s\n' "$(dirname "$cargo_bin")/rustc"
    return
  fi
  echo "rustc was not found; set RUSTC or add rustc to PATH" >&2
  return 1
}

resolve_solana() {
  local resolved
  if [[ -n "${SOLANA:-}" ]]; then
    resolved="$(resolve_candidate "$SOLANA" || true)"
    if [[ -z "$resolved" ]]; then
      echo "SOLANA does not name an executable" >&2
      return 1
    fi
    printf '%s\n' "$resolved"
    return
  fi
  if resolved="$(command -v solana 2>/dev/null)"; then
    printf '%s\n' "$resolved"
    return
  fi
  if [[ -n "${HOME:-}" && -x "$HOME/.local/share/solana/install/active_release/bin/solana" ]]; then
    printf '%s\n' "$HOME/.local/share/solana/install/active_release/bin/solana"
    return
  fi
  echo "solana was not found; set SOLANA, add solana to PATH, or install the CLI under HOME" >&2
  return 1
}
