"""
fix.py — FIX AGENT (LLM agent, Claude).

Job: on a "block" verdict, propose a safe alternative + a remediation message
the AI coder / dev can act on. (We do NOT silently rewrite code today — that's
a future-work slide. We return a structured suggestion.)

Owner: Person C (intelligence).

STATUS: STUB. Replace with a Claude call that picks a real safe alternative.
"""
from __future__ import annotations

import weave_shim as W
from contracts import Verdict, Remediation

# tiny demo lookup; real version asks Claude for the best-known alternative
_KNOWN_ALTERNATIVES = {
    "evil-demo-pkg": "lodash",
}


@W.op
def fix_agent(verdict: Verdict) -> Remediation:
    alt = _KNOWN_ALTERNATIVES.get(verdict.package, None)
    return Remediation(
        blocked_package=verdict.package,
        safe_alternative=alt,
        reason=verdict.summary,
        import_change=f"replace '{verdict.package}' with '{alt}'" if alt else "",
        message_to_agent=(
            f"'{verdict.package}' was blocked: {verdict.summary} "
            + (f"Use '{alt}' instead and update your imports." if alt else
               "No safe drop-in found; remove this dependency.")
        ),
    )
    # ---- TODO: Claude call to find the best safe alternative for `verdict.package`.