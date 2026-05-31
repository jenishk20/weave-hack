"""
orchestrator.py — THE SPINE.

Receives a package name, routes through the agents with DYNAMIC escalation
(not a fixed pipeline), and returns a Verdict (+ Remediation if blocked).

This is what earns the "Agent Orchestration" score: the routing decisions here
must be meaningful and visible in the Weave trace.

Owner: Person B (spine).
Run it directly to see the whole chain work with mocks:  python orchestrator.py
"""
from __future__ import annotations

import weave_shim as W
from contracts import Verdict, Remediation
from agents.intel import intel_agent
from agents.sandbox import sandbox_agent
from agents.reasoning import reasoning_agent
from agents.fix import fix_agent


@W.op
def orchestrate(package: str, version: str = "latest") -> dict:
    # 1) Fast, cheap intel first.
    intel = intel_agent(package, version)

    # 2) Short-circuit: if intel already proves it's malicious, don't bother detonating.
    if intel.clearly_malicious:
        verdict = Verdict(
            package=package, version=version, decision="block",
            risk="critical", score=0.99,
            evidence=[f"Intel: {intel.notes}"],
            summary="Blocked on intel alone (known-malicious / typosquat).",
        )
        return _finalize(verdict)

    # 3) Escalate to detonation only when warranted (this is the routing story).
    if intel.recommend_escalate or intel.recently_transferred:
        telemetry = sandbox_agent(package, version)
        verdict = reasoning_agent(telemetry, intel)
    else:
        verdict = Verdict(
            package=package, version=version, decision="allow",
            risk="low", score=0.05,
            evidence=["Intel: well-established package, no signals; skipped detonation."],
            summary="Allowed without detonation.",
        )

    return _finalize(verdict)


@W.op
def quarantine_install_trace(package: str, version: str = "latest") -> dict:
    return orchestrate(package, version)


@W.op
def _finalize(verdict: Verdict) -> dict:
    out = {"verdict": verdict, "remediation": None}
    if verdict.decision == "block":
        out["remediation"] = fix_agent(verdict)
    return out


if __name__ == "__main__":
    W.init("quarantine")
    for pkg in ["evil-demo-pkg", "lodash"]:
        print("\n" + "=" * 60)
        print(f"npm install {pkg}")
        result = quarantine_install_trace(pkg)
        v: Verdict = result["verdict"]
        print(f"  decision = {v.decision.upper()}  risk = {v.risk}  score = {v.score}")
        print(f"  summary  = {v.summary}")
        for e in v.evidence:
            print(f"   - {e}")
        rem: Remediation | None = result["remediation"]
        if rem:
            print(f"  FIX → use '{rem.safe_alternative}': {rem.message_to_agent}")
