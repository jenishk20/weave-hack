"""
sandbox.py — SANDBOX / DETONATION AGENT (tool agent, no LLM).

Job: detonate the package in a disposable Docker container seeded with
honeytokens, watch the OS boundary with strace (file opens + network connects),
and return a TelemetryBlob.

Owner: Person A.

This is the Python version of the manual docker steps:
  docker run -> seed_honeytokens.sh -> docker cp -> strace node postinstall.js
Your ONLY deliverable to the team is a correct TelemetryBlob. Because this
function is @W.op-decorated, its inputs + the returned TelemetryBlob show up in
the Weave trace automatically.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
import uuid

import weave_shim as W
from contracts import TelemetryBlob, NetworkAttempt, FileAccess

IMAGE = "quarantine-sandbox"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Paths that a benign install should NEVER read. Touching these = red flag.
SENSITIVE_MARKERS = ("/.aws/", "/.ssh/", "credentials", "id_rsa", ".env")

# Set to True for the "safe product" mode (no egress possible). False lets the
# package actually reach the network so we can capture the connect() attempt
# (and, with a proxy/catcher, the payload). For the demo, False is richer.
SEAL_NETWORK = False


def _run(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def _read_postinstall(pkg_dir: str) -> str:
    p = os.path.join(pkg_dir, "postinstall.js")
    try:
        with open(p) as f:
            return f.read()[:2000]
    except Exception:
        return ""


def _parse_strace(log: str, canary: str) -> tuple[list[FileAccess], list[NetworkAttempt], bool]:
    """Turn the raw strace log into structured telemetry (your manual grep, in code)."""
    file_accesses: list[FileAccess] = []
    seen: set[str] = set()
    # openat(..., "/root/.aws/credentials", ...) = 17   (positive fd = success)
    for m in re.finditer(r'openat\([^,]+,\s*"([^"]+)"[^)]*\)\s*=\s*(-?\d+)', log):
        path, ret = m.group(1), m.group(2)
        if ret.startswith("-"):          # failed open (e.g. ENOENT) -> ignore
            continue
        if any(mark in path for mark in SENSITIVE_MARKERS) and path not in seen:
            seen.add(path)
            file_accesses.append(FileAccess(path=path, operation="open", is_sensitive=True))

    network_attempts: list[NetworkAttempt] = []
    # connect(..., sin_port=htons(443), sin_addr=inet_addr("203.0.113.7"), ...)
    for m in re.finditer(r'connect\([^)]*sin_port=htons\((\d+)\)[^)]*inet_addr\("([^"]+)"\)', log):
        port, ip = int(m.group(1)), m.group(2)
        if ip.startswith("127.") or port in (0, 53):   # drop localhost / DNS / setup noise
            continue
        network_attempts.append(NetworkAttempt(dest_host=None, dest_ip=ip, port=port))

    # strace of openat/connect won't contain the HTTPS payload, so the canary
    # almost never appears here. Real canary-in-payload proof comes from the
    # proxy/catcher upgrade. Keep the check anyway in case of plaintext.
    canary_leaked = canary in log
    return file_accesses, network_attempts, canary_leaked


@W.op
def sandbox_agent(package: str, version: str = "latest") -> TelemetryBlob:
    container = f"det-{uuid.uuid4().hex[:8]}"
    canary = f"CANARY_{uuid.uuid4().hex[:8]}"
    pkg_dir = os.path.join(REPO_ROOT, package)   # local package to detonate (demo path)
    started = time.time()

    try:
        # 1) start a fresh disposable room
        net = ["--network=none"] if SEAL_NETWORK else []
        run = _run(["docker", "run", "-d", "--name", container, *net, IMAGE])
        if run.returncode != 0:
            raise RuntimeError(f"docker run failed: {run.stderr.strip()}")

        # 2) plant the honeytokens with a unique canary
        _run(["docker", "exec", container, "seed_honeytokens.sh", canary])

        # 3) carry the package in + 4) detonate under strace
        scripts: dict[str, str] = {}
        log = ""
        if os.path.isdir(pkg_dir):
            _run(["docker", "cp", pkg_dir, f"{container}:/tmp/target"])
            # Inject the honeytoken env vars (with the canary) directly into the
            # detonation process, so `process.env.*` is populated too — not just
            # the seeded files. (The seed script's `export` can't reach this
            # separate exec, hence the -e flags here.)
            deton = _run(["docker", "exec",
                          "-e", f"AWS_ACCESS_KEY_ID=AKIA{canary}",
                          "-e", f"AWS_SECRET_ACCESS_KEY=secret_{canary}",
                          "-e", f"OPENAI_API_KEY=sk-{canary}",
                          container, "sh", "-c",
                          "strace -f -e trace=openat,connect "
                          "node /tmp/target/postinstall.js 2>/tmp/strace.log; "
                          "cat /tmp/strace.log"])
            log = deton.stdout
            scripts = {"postinstall": _read_postinstall(pkg_dir)}
        # (else: no local package dir — nothing to detonate in this v1)

        # 5) parse the log into structured telemetry
        files, nets, leaked = _parse_strace(log, canary)
        return TelemetryBlob(
            package=package, version=version,
            network_attempts=nets, file_accesses=files,
            install_scripts=scripts, canary_leaked=leaked,
            exit_code=0, duration_ms=int((time.time() - started) * 1000),
        )

    except Exception as e:
        # If docker isn't available, don't break the chain for teammates.
        return TelemetryBlob(
            package=package, version=version,
            install_scripts={"error": str(e)}, canary_leaked=False,
            exit_code=-1, duration_ms=int((time.time() - started) * 1000),
        )

    finally:
        # 6) ALWAYS destroy the room
        _run(["docker", "rm", "-f", container])