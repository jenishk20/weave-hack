# Detonation image for the Sandbox Agent.
# Owner: Person A (YOU).
# Build once at startup:  docker build -t quarantine-sandbox ./sandbox
#
# Node (to run npm) + strace (to watch connect()/open() syscalls during install).
FROM node:20-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Honeytoken seeder is baked in; the Sandbox Agent runs it with a unique canary.
COPY seed_honeytokens.sh /usr/local/bin/seed_honeytokens.sh
# Strip Windows CRLF line endings so bash can parse the script on Linux
RUN sed -i 's/\r$//' /usr/local/bin/seed_honeytokens.sh \
    && chmod +x /usr/local/bin/seed_honeytokens.sh

# Container is driven via `docker exec` from the Sandbox Agent; keep it alive.
CMD ["sleep", "infinity"]