#!/usr/bin/env bash
# Seed fake credentials (honeytokens) into the container before detonation.
# Owner: Person A (YOU).
#
# Usage:  seed_honeytokens.sh <UNIQUE_CANARY>
# The canary is a per-run unique string. If we later see it in an outbound
# connect()/payload, we KNOW this package read and exfiltrated it.
set -euo pipefail

CANARY="${1:-CANARY_MISSING}"

mkdir -p /root/.aws /root/.ssh

cat > /root/.aws/credentials <<EOF
[default]
aws_access_key_id = AKIA${CANARY}
aws_secret_access_key = secret_${CANARY}
EOF

cat > /app/.env <<EOF
OPENAI_API_KEY=sk-${CANARY}
DATABASE_URL=postgres://user:${CANARY}@db.internal/app
EOF

cat > /root/.ssh/id_rsa <<EOF
-----BEGIN OPENSSH PRIVATE KEY-----
FAKEKEY_${CANARY}
-----END OPENSSH PRIVATE KEY-----
EOF

# Also expose via env so `printenv`-style stealers (like the LiteLLM payload) bite.
export AWS_ACCESS_KEY_ID="AKIA${CANARY}"
export AWS_SECRET_ACCESS_KEY="secret_${CANARY}"

echo "[seed] honeytokens planted with canary ${CANARY}"