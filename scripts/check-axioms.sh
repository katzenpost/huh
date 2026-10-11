#!/usr/bin/env bash
# Fail if any theorem in an Huh module depends on an axiom beyond Lean's own
# (propext, Classical.choice, Quot.sound): no sorry, no native_decide, no declared axiom.
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(lake env lean scripts/Axioms.lean 2>&1) || { echo "$out"; echo "FAIL" >&2; exit 1; }
echo "$out"
