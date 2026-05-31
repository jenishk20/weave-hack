"""
fix.py — FIX AGENT (LLM agent via W&B Inference).

Job: on a "block" verdict, propose the best safe alternative from the npm
ecosystem and return a Remediation the developer or AI agent can act on.
"""
from __future__ import annotations

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

import weave_shim as W
from contracts import Remediation, Verdict

load_dotenv()

_MODEL = os.getenv("WANDB_MODEL", "meta-llama/Llama-3.1-70B-Instruct")
_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.getenv("WANDB_API_KEY", "")
        if not api_key:
            raise RuntimeError("WANDB_API_KEY not set — add it to your .env file")
        _client = OpenAI(base_url="https://api.inference.wandb.ai/v1", api_key=api_key)
    return _client

_SYSTEM = """\
You are a Node.js/npm security expert.
A package was blocked because it contains a supply-chain attack.
Suggest the best safe, well-maintained alternative from the npm ecosystem.

Respond with JSON ONLY — no markdown, no extra text.

Schema:
{
  "safe_alternative": "package-name" or null,
  "reason": "why this alternative is safer and suitable",
  "import_change": "e.g. replace 'evil-pkg' with 'lodash'",
  "message_to_agent": "concise actionable message for the developer or AI coding agent"
}

If there is no safe drop-in, set safe_alternative to null and explain in message_to_agent.
"""


@W.op
def fix_agent(verdict: Verdict) -> Remediation:
    prompt = (
        f"Blocked package: {verdict.package}\n"
        f"Risk level: {verdict.risk}\n"
        f"Reason: {verdict.summary}\n"
        f"Evidence:\n" + "\n".join(f"  - {e}" for e in verdict.evidence)
    )

    raw = _call_llm(prompt)
    parsed = _safe_parse(raw)

    return Remediation(
        blocked_package=verdict.package,
        safe_alternative=parsed.get("safe_alternative"),
        reason=parsed.get("reason", verdict.summary),
        import_change=parsed.get("import_change", ""),
        message_to_agent=parsed.get(
            "message_to_agent",
            f"'{verdict.package}' was blocked ({verdict.risk}): {verdict.summary}",
        ),
    )


def _call_llm(prompt: str) -> str:
    resp = _get_client().chat.completions.create(
        model=_MODEL,
        messages=[
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=256,
    )
    return resp.choices[0].message.content or ""


def _safe_parse(raw: str) -> dict:
    text = raw.strip()
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) > 1 else text
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}
