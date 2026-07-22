#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(git -C "$script_dir" rev-parse --show-toplevel)"
cd "$root"

files="$(mktemp)"
trap 'rm -f "$files"' EXIT
{
  git ls-files -z
  git ls-files --others --exclude-standard -z
} > "$files"

scan_all() {
  local label="$1"
  local pattern="$2"
  local found=0
  while IFS= read -r -d '' file; do
    if [[ -f "$file" ]] && grep -I -H -n -E -- "$pattern" "$file"; then
      found=1
    fi
  done < "$files"
  if [[ "$found" -ne 0 ]]; then
    echo "$label scan failed" >&2
    return 1
  fi
}

scan_evidence() {
  local pattern="$1"
  local found=0
  while IFS= read -r -d '' file; do
    if [[ "$file" == evidence/* && -f "$file" ]] \
      && grep -I -H -n -i -E -- "$pattern" "$file"; then
      found=1
    fi
  done < "$files"
  if [[ "$found" -ne 0 ]]; then
    echo "private evidence term scan failed" >&2
    return 1
  fi
}

secret_pattern='-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|g''h[pousr]_[A-Za-z0-9_]{20,}|github_''pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_''live_[A-Za-z0-9]{16,}|\[[[:space:]]*[0-9]{1,3}([[:space:]]*,[[:space:]]*[0-9]{1,3}){63}[[:space:]]*\]'
private_path_pattern='/''Users/|/home/''gava/|[A-Za-z]:\\Users\\'
internal_pattern='[.]''arcana/|[.]''Codex/|[.]''codex/|AGENTS''[.]md|CLAUDE''[.]md|AR''CANA|Forge dis''patch|Annie in''box|session-log-with-''handoff|(^|[^[:alnum:]])AR-''[0-9]+'
private_evidence_pattern='plain''text|signed_''intent|cipher''text|decryp''tion|reser''vation|[.]kageb-''private|keyper-attestation-''key'

scan_all "secret" "$secret_pattern"
scan_all "private path" "$private_path_pattern"
scan_all "internal language" "$internal_pattern"
scan_evidence "$private_evidence_pattern"

echo "public repository scan passed"
