#!/usr/bin/env bash
# Repository check (TK-1, TK-11, TK-12).
#
# 1. Refuses private keys and certificates in tracked files.
# 2. Refuses strings from a deny-list supplied outside the repository:
#    FORBIDDEN_PATTERNS (newline-separated extended regular expressions),
#    set as a CI secret. The list itself is never committed — committing it
#    would publish the very strings it guards.
#
# Usage: scripts/check-repo.sh [--history]
#   --history  also scan every commit reachable from HEAD (run before publishing).
#   REQUIRE_DENYLIST=1 makes a missing deny-list an error (set in CI on this repository).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
fail=0

key_re='-----BEGIN ([A-Z ]*PRIVATE KEY|CERTIFICATE|CERTIFICATE REQUEST|X509 CRL)-----'
scan_scope="tracked files"
if [[ "${1:-}" == "--history" ]]; then
  scan_scope="history"
fi

grep_tracked() { # $1 = ERE; prints matches as file:line
  git grep -nIE -e "$1" -- . ':!scripts/check-repo.sh' || true
}

grep_history() { # $1 = ERE; prints matches as commit:file:line
  local revs
  revs=$(git rev-list --all)
  [[ -z "$revs" ]] && return 0
  # shellcheck disable=SC2086
  git grep -nIE -e "$1" $revs -- . ':!scripts/check-repo.sh' || true
}

search() {
  if [[ "$scan_scope" == "history" ]]; then grep_history "$1"; else grep_tracked "$1"; fi
}

hits=$(search "$key_re")
if [[ -n "$hits" ]]; then
  echo "Private keys or certificates found ($scan_scope):"
  echo "$hits" | sed 's/^/  /'
  fail=1
fi

if [[ -n "${FORBIDDEN_PATTERNS:-}" ]]; then
  n=0
  while IFS= read -r pat; do
    [[ -z "$pat" || "$pat" == \#* ]] && continue
    n=$((n + 1))
    hits=$(search "$pat")
    if [[ -n "$hits" ]]; then
      # Do not echo the pattern or the matching text: CI logs are public.
      echo "Deny-list entry #$n matched in ($scan_scope):"
      echo "$hits" | cut -d: -f1-2 | sort -u | sed 's/^/  /'
      fail=1
    fi
  done <<< "$FORBIDDEN_PATTERNS"
  echo "Deny-list: $n entries checked."
elif [[ "${REQUIRE_DENYLIST:-0}" == "1" ]]; then
  echo "FORBIDDEN_PATTERNS is not set; the deny-list check is required here."
  fail=1
else
  echo "FORBIDDEN_PATTERNS is not set; deny-list check skipped."
fi

if [[ $fail -ne 0 ]]; then
  echo "Repository check FAILED."
  exit 1
fi
echo "Repository check passed ($scan_scope)."
