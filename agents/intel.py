"""
intel.py — INTEL AGENT (tool agent, no LLM needed).

Job: fast/cheap risk signals BEFORE we spend time detonating.
  - OSV.dev / known CVE lookup
  - npm registry metadata (package age, version velocity, maintainer change)
  - typosquat distance vs. popular package names

Owner: Person C (intelligence).

STATUS: STUB. Returns mock data matching the contract so the rest of the
team is unblocked. Replace the body with real OSV/npm calls.
"""
from __future__ import annotations

import weave_shim as W
from contracts import IntelResult


@W.op
def intel_agent(package: str, version: str = "latest") -> IntelResult:
    # ---- MOCK (delete once real logic lands) ----
    if package == "evil-demo-pkg":
        return IntelResult(
            package=package, version=version,
            clearly_malicious=False,           # inconclusive on purpose -> forces detonation
            recently_transferred=True,
            package_age_days=2,
            recommend_escalate=True,
            notes="Brand-new package, ownership recently transferred. Escalate to sandbox.",
        )
    return IntelResult(
        package=package, version=version,
        clearly_malicious=False,
        package_age_days=3000,
        recommend_escalate=False,
        notes="Well-established package, no signals.",
    )
    # ---- TODO real implementation ----
    # 1. GET https://api.osv.dev/v1/query  with {package, ecosystem: "npm"}
    # 2. GET https://registry.npmjs.org/<package>  -> created date, maintainers, versions
    # 3. typosquat: edit-distance vs. a local list of top-N npm package names