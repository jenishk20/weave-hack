#!/usr/bin/env bash
# demo/check.sh — clean, camera-friendly Quarantine check for the demo.
#
# Usage:  bash demo/check.sh <package>
# Shows a tidy banner + the verdict + the W&B Weave trace link, with all the
# noisy weave/login lines and the shell-function wrapper stripped out.

set -uo pipefail

REPO="/Users/jenishkothari/Northeastern/Projects/weave-hack"
PKG="${1:?usage: bash demo/check.sh <package>}"

cd "$REPO"
# shellcheck disable=SC1091
source myenv/bin/activate
set -a; source .env 2>/dev/null; set +a

bar() { printf '%s\n' "────────────────────────────────────────────────────────────"; }

echo ""
bar
echo "  🤖  CODING AGENT wants to install:   $PKG"
echo "  🛡️   PACKAGE QUARANTINE is inspecting it before it touches your machine…"
bar
echo ""

# Call the venv binary directly (bypasses the zsh function wrapper -> no noise).
ERR="$(mktemp)"
OUT="$("$REPO/myenv/bin/quarantine" check "$PKG" 2>"$ERR" | grep -v '^\[weave\]')"
WEAVE_URL="$(grep -oE 'https://wandb.ai/[^ ]+/r/call/[a-z0-9-]+' "$ERR" | head -1)"
rm -f "$ERR"

echo "$OUT"
echo ""
bar
if printf '%s' "$OUT" | grep -q 'decision=allow'; then
  echo "  ✅  VERDICT: ALLOWED — package passed the safety harness. Installing."
else
  echo "  🚨  VERDICT: BLOCKED — package never reaches your real workspace."
fi
[ -n "$WEAVE_URL" ] && echo "  📊  Recorded in W&B Weave:  $WEAVE_URL"
bar
echo ""
