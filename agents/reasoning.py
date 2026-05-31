"""
reasoning.py — REASONING AGENT (LLM agent, W&B Inference / DeepSeek).

Job: turn a raw TelemetryBlob (+ IntelResult) into a Verdict with
human-readable evidence. The LLM reasons over what the package actually DID in
the sandbox (file reads, network attempts, install-script text) and explains
why it's malicious or benign.

Owner: Person C (intelligence).

Falls back to deterministic rules if the LLM is unavailable, so the chain
never breaks during the demo.
"""
from __future__ import annotations

import json

import weave_shim as W
import llm
from contracts import TelemetryBlob, IntelResult, Verdict

_SYSTEM = (
    "You are a security analyst agent in an npm supply-chain defense system. "
    "A suspicious package was detonated in an isolated sandbox seeded with FAKE "
    "honeytoken credentials (a fake ~/.aws/credentials, .env, and ~/.ssh/id_rsa). "
    "You are given the telemetry of what the package did during install. "
    "A benign package reads none of those files and makes no outbound network "
    "connections during install. Decide if the package is malicious.\n"
    'Respond with ONLY a JSON object: {"decision":"allow|block",'
    '"risk":"low|medium|critical","score":<float 0-1>,"evidence":[<short strings>],'
    '"summary":"<one sentence>"}'
)


def _telemetry_text(t: TelemetryBlob, intel: IntelResult | None) -> str:
    lines = [f"Package: {t.package}@{t.version}"]
    if intel:
        lines.append(f"Intel: {intel.notes} (recently_transferred={intel.recently_transferred})")
    lines.append("Sensitive files the package opened during install:")
    lines += [f"  - {f.path}" for f in t.file_accesses] or ["  (none)"]
    lines.append("Outbound network connection attempts during install:")
    lines += [f"  - {n.dest_host or n.dest_ip}:{n.port}" for n in t.network_attempts] or ["  (none)"]
    lines.append(f"Honeytoken canary observed leaving the box: {t.canary_leaked}")
    if t.install_scripts.get("postinstall"):
        lines.append("postinstall script:\n" + t.install_scripts["postinstall"][:1500])
    return "\n".join(lines)


@W.op
def reasoning_agent(telemetry: TelemetryBlob, intel: IntelResult | None = None) -> Verdict:
    if llm.available():
        try:
            content = llm.chat(
                [
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": _telemetry_text(telemetry, intel)},
                ],
                response_format={"type": "json_object"},
                temperature=0,
            )
            data = json.loads(content)
            return Verdict(
                package=telemetry.package, version=telemetry.version,
                decision=data.get("decision", "block"),
                risk=data.get("risk", "medium"),
                score=float(data.get("score", 0.5)),
                evidence=list(data.get("evidence", [])),
                summary=data.get("summary", ""),
            )
        except Exception as e:
            # fall through to rules below; record why for debugging
            fallback_note = f"(LLM unavailable: {e})"
    else:
        fallback_note = "(LLM key not set; used rules)"

    # ---- deterministic fallback ----
    evidence, malicious = [], False
    if telemetry.canary_leaked:
        malicious = True
        evidence.append("Honeytoken canary was exfiltrated over the network.")
    for n in telemetry.network_attempts:
        evidence.append(f"Outbound connection attempt to {n.dest_host or n.dest_ip}:{n.port}.")
    for f in telemetry.file_accesses:
        if f.is_sensitive:
            malicious = True
            evidence.append(f"Read sensitive file: {f.path}.")
    evidence.append(fallback_note)
    if malicious:
        return Verdict(telemetry.package, telemetry.version, "block", "critical", 0.96,
                       evidence, "Package accessed seeded credentials during install — blocked.")
    return Verdict(telemetry.package, telemetry.version, "allow", "low", 0.04,
                   evidence or ["No suspicious activity."], "Clean install — allowed.")