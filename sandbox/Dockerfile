# Detonation image for the Sandbox Agent.
# Owner: Person A (YOU).
# Build once at startup:  docker build -t quarantine-sandbox ./sandbox
#
# Node/Python (to run package install hooks) + strace (to watch connect()/open()).
FROM node:20-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strace ca-certificates python3 python3-pip python3-setuptools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Honeytoken seeder is baked in; the Sandbox Agent runs it with a unique canary.
COPY seed_honeytokens.sh /usr/local/bin/seed_honeytokens.sh
RUN chmod +x /usr/local/bin/seed_honeytokens.sh

# Container is driven via `docker exec` from the Sandbox Agent; keep it alive.
CMD ["sleep", "infinity"]
