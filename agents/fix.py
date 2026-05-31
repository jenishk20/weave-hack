"""
fix.py — FIX AGENT (LLM agent, W&B Inference / DeepSeek).

Job: on a "block" verdict, ask the model for a safe, well-maintained alternative
npm package and a concrete remediation the AI coder / dev can act on. Works for
ANY package now (not a hardcoded list).

Owner: Person C (intelligence).

Falls back to a tiny lookup if the LLM is unavailable.
"""
from __future__ import annotations

import json

import weave_shim as W
import llm
from contracts import Verdict, Remediation

_SYSTEM = (
    "You are a remediation agent in an npm supply-chain defense system. "
    "A package was blocked as malicious. Suggest a single safe, popular, "
    "well-maintained npm package that serves the same purpose, and how to swap it.\n"
    'Respond with ONLY a JSON object: {"safe_alternative":"<npm package name>",'
    '"reason":"<why it is safe>","import_change":"<concrete change>",'
    '"message_to_agent":"<one short instruction to the developer>"}'
)

_FALLBACK = {"evil-demo-pkg": "lodash"}


@W.op
def fix_agent(verdict: Verdict) -> Remediation:
    if llm.available():
        try:
            content = llm.chat(
                [
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content":
                        f"Blocked package: {verdict.package}\nReason: {verdict.summary}\n"
                        f"Evidence: {'; '.join(verdict.evidence)}"},
                ],
                response_format={"type": "json_object"},
                temperature=0,
            )
            data = json.loads(content)
            return Remediation(
                blocked_package=verdict.package,
                safe_alternative=data.get("safe_alternative"),
                reason=data.get("reason", verdict.summary),
                import_change=data.get("import_change", ""),
                message_to_agent=data.get("message_to_agent", ""),
            )
        except Exception:
            pass

    # ---- fallback ----
    alt = _FALLBACK.get(verdict.package)
    return Remediation(
        blocked_package=verdict.package,
        safe_alternative=alt,
        reason=verdict.summary,
        import_change=f"replace '{verdict.package}' with '{alt}'" if alt else "",
        message_to_agent=(
            f"'{verdict.package}' was blocked: {verdict.summary} "
            + (f"Use '{alt}' instead." if alt else "Remove this dependency.")
        ),
    )