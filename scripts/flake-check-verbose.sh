#!/usr/bin/env bash
# Run VM checks one at a time with live build logs (-L). Easier to follow than parallel flake check.
set -euo pipefail
cd "$(dirname "$0")/.."

checks=(auth credentials envVars instances secrets stdio systemd)
failed=()

echo "=== flake checks (x86_64-linux, sequential, -L) started $(date -Iseconds) ==="

for c in "${checks[@]}"; do
  echo ""
  echo "========== .#checks.x86_64-linux.${c} =========="
  if nix build ".#checks.x86_64-linux.${c}" -L --no-link; then
    echo ">>> PASS: ${c}"
  else
    echo ">>> FAIL: ${c}"
    failed+=("$c")
  fi
done

echo ""
if ((${#failed[@]})); then
  echo "=== finished $(date -Iseconds): FAILED ${failed[*]} ==="
  exit 1
fi
echo "=== finished $(date -Iseconds): all passed ==="
