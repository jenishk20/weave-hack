"""
sandbox.py — SANDBOX / DETONATION AGENT (tool agent, no LLM).

Job: detonate the package in a disposable Docker container seeded with
honeytokens, monitor the OS boundary (network connect attempts + sensitive
file reads), and return a TelemetryBlob.

Owner: Person A (YOU).

STATUS: STUB. Returns mock telemetry so the chain runs. Replace the body with
real Docker logic. Your ONLY deliverable to the team is a correct TelemetryBlob.

Real lifecycle (per package):
  1. (once at startup) docker build -t quarantine-sandbox ./sandbox
  2. docker run -d --network=none quarantine-sandbox            -> container_id
  3. docker exec <id> bash seed_honeytokens.sh <UNIQUE_CANARY>
  4. docker exec <id> strace -f -e trace=open,openat,connect npm install <pkg>
  5. read strace log (+ proxy log if used); parse:
       - connect() syscalls         -> NetworkAttempt
       - opens of ~/.aws/.ssh/.env  -> FileAccess(is_sensitive=True)
       - canary string in any payload/connect -> canary_leaked = True
  6. docker rm -f <id>   (ALWAYS tear down, even on error)
"""
from __future__ import annotations

import weave_shim as W
from contracts import TelemetryBlob, NetworkAttempt, FileAccess


@W.op
def sandbox_agent(package: str, version: str = "latest") -> TelemetryBlob:
    # ---- MOCK (delete once Docker logic lands) ----
    if package == "evil-demo-pkg":
        return TelemetryBlob(
            package=package, version=version,
            network_attempts=[
                NetworkAttempt(
                    dest_host="exfil.attacker.example", dest_ip="203.0.113.7",
                    port=443, payload_contains_canary=True,
                    raw_snippet="POST /collect  body=CANARY_AWS_KEY_8f3a...",
                )
            ],
            file_accesses=[
                FileAccess(path="/root/.aws/credentials", operation="open", is_sensitive=True),
                FileAccess(path="/app/.env", operation="open", is_sensitive=True),
            ],
            install_scripts={"postinstall": "node steal.js  # reads creds, POSTs out"},
            canary_leaked=True,
            exit_code=0,
            duration_ms=1820,
        )
    return TelemetryBlob(
        package=package, version=version,
        network_attempts=[],
        file_accesses=[],
        install_scripts={},
        canary_leaked=False,
        exit_code=0,
        duration_ms=900,
    )
    # ---- TODO real Docker implementation (see module docstring) ----