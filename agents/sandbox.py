"""
sandbox.py — SANDBOX / DETONATION AGENT (tool agent, no LLM).

Job: detonate the package in a disposable Docker container seeded with
honeytokens, monitor the OS boundary (network connect attempts + sensitive
file reads via strace), and return a TelemetryBlob.

Lifecycle per scan:
  1. docker build -t quarantine-sandbox ./sandbox  (cached after first run)
  2. docker run -d --network=none --cap-add=SYS_PTRACE quarantine-sandbox
  3. docker exec ... bash /sandbox/seed_honeytokens.sh <CANARY>
  4. docker exec ... strace -f -e trace=open,openat,connect npm install <pkg>
  5. cat /tmp/strace.log and parse connects + sensitive opens
  6. docker rm -f <container>  (always, even on error)
"""
from __future__ import annotations

import os
import re
import subprocess
import time
import uuid

import weave_shim as W
from contracts import FileAccess, NetworkAttempt, TelemetryBlob

_SENSITIVE_PATHS = frozenset([
    "/root/.aws/credentials", "/root/.aws/config",
    "/app/.env", "/.env",
    "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
    # NOTE: .npmrc and .gitconfig are intentionally excluded —
    # npm reads them during every install as part of normal operation.
])

_SANDBOX_IMAGE = "quarantine-sandbox"
_WEAVE_HACK_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SANDBOX_BUILD_CTX = os.path.join(_WEAVE_HACK_ROOT, "sandbox")

_CONNECT_RE = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET[6]?,\s*sin_port=htons\((\d+)\),'
    r'\s*sin_addr=inet_addr\("([^"]+)"\)',
    re.IGNORECASE,
)
_OPEN_RE = re.compile(r'(?:open|openat)\([^"]*"([^"]+)"', re.IGNORECASE)


@W.op
def sandbox_agent(package: str, version: str = "latest") -> TelemetryBlob:
    pkg_spec = package if version == "latest" else f"{package}@{version}"
    canary = f"CANARY-{uuid.uuid4().hex[:12].upper()}"
    container_id: str | None = None
    start_ms = int(time.time() * 1000)

    try:
        print(f"[sandbox] Preparing isolated environment...")
        _silent(["docker", "build", "-t", _SANDBOX_IMAGE, _SANDBOX_BUILD_CTX])

        result = _silent(
            ["docker", "run", "-d", "--network=none", "--cap-add=SYS_PTRACE",
             "--add-host=webhook.site:192.0.2.1",
             _SANDBOX_IMAGE],
            capture=True,
        )
        container_id = result.stdout.strip()

        _silent(["docker", "exec", container_id,
                 "bash", "/usr/local/bin/seed_honeytokens.sh", canary])

        print(f"[sandbox] Detonating {package} under strace...")

        # If the package is a local directory (e.g. evil-demo-pkg), copy it in first
        local_path = os.path.join(_WEAVE_HACK_ROOT, package)
        if os.path.isdir(local_path):
            _silent(["docker", "cp", local_path, f"{container_id}:/tmp/{package}"])
            install_target = f"/tmp/{package}"
        else:
            install_target = pkg_spec

        strace_result = _exec(
            container_id,
            ["strace", "-f", "-s", "512", "-e", "trace=open,openat,connect",
             "-o", "/tmp/strace.log",
             "npm", "install", "--prefix", "/app", install_target],
            capture=True,
        )
        exit_code = strace_result.returncode if strace_result else -1

        log_result = _exec(container_id, ["cat", "/tmp/strace.log"], capture=True)
        strace_log = log_result.stdout if log_result else ""

        network_attempts = _parse_connects(strace_log, canary)
        file_accesses = _parse_opens(strace_log)
        canary_leaked = _detect_canary_leak(strace_log, canary, network_attempts)

        install_scripts: dict[str, str] = {}
        pkg_json_result = _exec(
            container_id,
            ["cat", f"/app/node_modules/{package}/package.json"],
            capture=True,
        )
        if pkg_json_result and pkg_json_result.returncode == 0:
            try:
                import json
                pkg_json = json.loads(pkg_json_result.stdout)
                for hook in ("preinstall", "install", "postinstall"):
                    if hook in pkg_json.get("scripts", {}):
                        install_scripts[hook] = pkg_json["scripts"][hook]
            except Exception:
                pass

        duration_ms = int(time.time() * 1000) - start_ms
        print(f"[sandbox] Analysis complete ({duration_ms}ms)")
        return TelemetryBlob(
            package=package, version=version,
            network_attempts=network_attempts,
            file_accesses=file_accesses,
            install_scripts=install_scripts,
            canary_leaked=canary_leaked,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )

    except Exception as exc:
        return TelemetryBlob(
            package=package, version=version,
            network_attempts=[], file_accesses=[],
            install_scripts={"error": str(exc)},
            canary_leaked=False, exit_code=-1,
            duration_ms=int(time.time() * 1000) - start_ms,
        )
    finally:
        if container_id:
            _silent(["docker", "rm", "-f", container_id])


def _silent(cmd: list[str], capture: bool = False):
    """Run a command with all output suppressed. Raises on non-zero exit."""
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        check=True,
    )


def _exec(container_id: str, cmd: list[str], capture: bool = False, check: bool = False):
    return subprocess.run(
        ["docker", "exec", container_id] + cmd,
        capture_output=capture, text=True, check=check,
    )


def _parse_connects(log: str, canary: str) -> list[NetworkAttempt]:
    seen: set[tuple] = set()
    results: list[NetworkAttempt] = []
    for m in _CONNECT_RE.finditer(log):
        port, ip = int(m.group(1)), m.group(2)
        # Port 53 = DNS — normal for every npm install, not an exfil signal
        if port == 53:
            continue
        if (ip, port) in seen:
            continue
        seen.add((ip, port))
        # Check 2KB window around the connect() for canary
        start = max(0, m.start() - 1024)
        window = log[start: m.end() + 1024]
        results.append(NetworkAttempt(
            dest_host=None, dest_ip=ip, port=port,
            payload_contains_canary=canary in window,
            raw_snippet=m.group(0)[:200],
        ))
    return results


def _parse_opens(log: str) -> list[FileAccess]:
    seen: set[str] = set()
    results: list[FileAccess] = []
    for m in _OPEN_RE.finditer(log):
        path = m.group(1)
        if path in seen:
            continue
        seen.add(path)
        is_sensitive = path in _SENSITIVE_PATHS or any(
            path.startswith(s.rstrip("*")) for s in _SENSITIVE_PATHS
        )
        if is_sensitive:
            results.append(FileAccess(path=path, operation="open", is_sensitive=True))
    return results


def _detect_canary_leak(log: str, canary: str, network_attempts: list[NetworkAttempt]) -> bool:
    if canary not in log:
        return False
    canary_pos = log.find(canary)
    nearby = log[max(0, canary_pos - 512): canary_pos + 512]
    return "connect(" in nearby or bool(network_attempts)
