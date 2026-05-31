"""
reasoning.py — REASONING AGENT (LLM agent, Claude).

Job: turn a raw TelemetryBlob (+ IntelResult) into a Verdict with
human-readable evidence. This is where the LLM adds value: explaining WHY
"connect to 203.0.113.7 carrying CANARY_AWS_KEY" means credential exfiltration.

Owner: Person C (intelligence).

STATUS: STUB with simple rule-based logic so the chain runs. Replace with a
Claude call that reasons over the telemetry and returns the same Verdict shape.
"""
from __future__ import annotations

import weave_shim as W
from contracts import TelemetryBlob, IntelResult, Verdict


@W.op
def reasoning_agent(telemetry: TelemetryBlob, intel: IntelResult | None = None) -> Verdict:
    # ---- MOCK rule-based logic (replace with Claude) ----
    evidence: list[str] = []
    malicious = False

    if telemetry.canary_leaked:
        malicious = True
        evidence.append("Honeytoken canary was exfiltrated over the network.")
    for n in telemetry.network_attempts:
        evidence.append(f"Outbound connection attempt to {n.dest_host or n.dest_ip}:{n.port}.")
    for f in telemetry.file_accesses:
        if f.is_sensitive:
            malicious = True
            evidence.append(f"Read sensitive file: {f.path}.")

    if malicious:
        return Verdict(
            package=telemetry.package, version=telemetry.version,
            decision="block", risk="critical", score=0.96,
            evidence=evidence,
            summary="Package exfiltrated seeded credentials during install — blocked.",
        )
    return Verdict(
        package=telemetry.package, version=telemetry.version,
        decision="allow", risk="low", score=0.04,
        evidence=evidence or ["No suspicious network or file activity during install."],
        summary="Clean install — allowed.",
    )
    # ---- TODO: Claude API call. Feed telemetry + intel as context, ask for
    #            {decision, risk, score, evidence, summary}. Use latest model.