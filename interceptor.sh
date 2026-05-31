#!/usr/bin/env bash
# interceptor.sh — drop-in npm shim that scans before every install.
#
# Usage:
#   source interceptor.sh          # activates for current shell session
#   echo "source $(pwd)/interceptor.sh" >> ~/.bashrc   # make it permanent
#
# Requires: server.py running (uvicorn server:app --port 8765)

QUARANTINE_SERVER="${QUARANTINE_SERVER:-http://127.0.0.1:8765}"

npm() {
  local subcmd="$1"

  # Intercept: npm install <package-name>  (single named package, not bare install)
  if [[ "$subcmd" == "install" || "$subcmd" == "i" ]] && [[ -n "$2" && "$2" != -* ]]; then
    local package="$2"
    echo ""
    echo "[quarantine] Scanning '$package' before install..."

    local response
    response=$(curl -sf -X POST "$QUARANTINE_SERVER/scan" \
      -H "Content-Type: application/json" \
      -d "{\"package\": \"$package\"}" 2>&1)

    if [[ $? -ne 0 ]]; then
      echo "[quarantine] WARNING: scanner unreachable at $QUARANTINE_SERVER"
      echo "[quarantine] Proceeding unscanned — start server.py to enable scanning."
      command npm "$@"
      return $?
    fi

    local decision risk summary safe_alt
    decision=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['verdict']['decision'])" 2>/dev/null)
    risk=$(echo "$response"     | python3 -c "import sys,json; print(json.load(sys.stdin)['verdict']['risk'])" 2>/dev/null)
    summary=$(echo "$response"  | python3 -c "import sys,json; print(json.load(sys.stdin)['verdict']['summary'])" 2>/dev/null)
    safe_alt=$(echo "$response" | python3 -c "
import sys, json
d = json.load(sys.stdin)
r = d.get('remediation') or {}
print(r.get('safe_alternative') or '')
" 2>/dev/null)

    if [[ "$decision" == "block" ]]; then
      echo ""
      echo "╔══════════════════════════════════════════════════════════════╗"
      echo "║  QUARANTINE — INSTALL BLOCKED                               ║"
      echo "╠══════════════════════════════════════════════════════════════╣"
      printf "║  Package  : %-49s║\n" "$package"
      printf "║  Risk     : %-49s║\n" "$risk"
      printf "║  Reason   : %-49s║\n" "${summary:0:49}"
      if [[ -n "$safe_alt" ]]; then
        printf "║  Use instead: npm install %-36s║\n" "$safe_alt"
      fi
      echo "╚══════════════════════════════════════════════════════════════╝"
      echo ""
      return 1
    else
      echo "[quarantine] ALLOW — '$package' is clean."
      echo ""
      command npm "$@"
      return $?
    fi
  else
    # Pass everything else through unchanged (npm run, npm ci, npm ls, etc.)
    command npm "$@"
  fi
}
