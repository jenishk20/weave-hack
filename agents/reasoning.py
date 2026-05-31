"""
reasoning.py — REASONING AGENT (LLM agent via W&B Inference).

Job: turn a raw TelemetryBlob (+ IntelResult) into a Verdict with
human-readable evidence explaining WHY the behavior is malicious.
Calls models through W&B's OpenAI-compatible inference endpoint.
"""
from __future__ import annotations

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

import weave_shim as W
from contracts import IntelResult, TelemetryBlob, Verdict

load_dotenv()

_MODEL = os.getenv("WANDB_MODEL", "openai/gpt-oss-120b")
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
You are a security analyst specializing in npm supply-chain attacks.
Given sandbox telemetry from an isolated npm install, determine if the package is malicious.

Respond with a JSON object ONLY — no markdown fences, no extra text.

Schema:
{
  "decision": "allow" | "block",
  "risk": "low" | "medium" | "critical",
  "score": 0.0-1.0,
  "evidence": ["one finding per item", ...],
  "summary": "one-sentence human verdict"
}

Scoring guide:
- canary_leaked=true (honeytoken exfiltrated over network) → score ≥ 0.95, decision=block, risk=critical
- sensitive file read (~/.aws/credentials, ~/.ssh/id_rsa, .env) + outbound connection → score 0.70-0.90, block, medium/critical
- sensitive file read only, no network → score 0.50-0.70, block, medium
- no suspicious activity → score ≤ 0.10, allow, low

IMPORTANT — these are NORMAL during any npm install, do NOT flag them:
- Reading /root/.npmrc (npm config file, not credentials)
- DNS queries (port 53) to any host (required for package registry)
- Reading node_modules/** files
- npm exit code 1 alone is not a security signal
"""


@W.op
def reasoning_agent(telemetry: TelemetryBlob, intel: IntelResult | None = None) -> Verdict:
    prompt = _build_prompt(telemetry, intel)
    raw = _call_llm(prompt)
    parsed = _safe_parse(raw)

    return Verdict(
        package=telemetry.package,
        version=telemetry.version,
        decision=parsed.get("decision", "block"),
        risk=parsed.get("risk", "critical"),
        score=float(parsed.get("score", 0.95)),
        evidence=parsed.get("evidence", ["LLM response unparseable; defaulting to block."]),
        summary=parsed.get("summary", raw[:300]),
    )


def _build_prompt(telemetry: TelemetryBlob, intel: IntelResult | None) -> str:
    lines = [f"Package: {telemetry.package}@{telemetry.version}"]

    if intel:
        lines.append(f"Intel: {intel.notes}")
        if intel.typosquat_of:
            lines.append(f"Typosquat of: {intel.typosquat_of}")
        if intel.known_cves:
            lines.append(f"Known CVEs: {', '.join(intel.known_cves)}")

    lines.append(f"Honeytoken canary exfiltrated: {telemetry.canary_leaked}")
    lines.append(f"npm exit code: {telemetry.exit_code}")

    if telemetry.file_accesses:
        lines.append("File accesses:")
        for fa in telemetry.file_accesses:
            tag = " [SENSITIVE]" if fa.is_sensitive else ""
            lines.append(f"  {fa.operation}({fa.path}){tag}")

    if telemetry.network_attempts:
        lines.append("Network connection attempts:")
        for na in telemetry.network_attempts:
            host = na.dest_host or na.dest_ip
            canary_tag = " [CANARY IN PAYLOAD]" if na.payload_contains_canary else ""
            lines.append(f"  connect → {host}:{na.port}{canary_tag}")
            if na.raw_snippet:
                lines.append(f"    strace: {na.raw_snippet[:200]}")

    if telemetry.install_scripts:
        lines.append("Install scripts:")
        for hook, cmd in telemetry.install_scripts.items():
            lines.append(f"  {hook}: {cmd[:200]}")

    return "\n".join(lines)


def _call_llm(prompt: str) -> str:
    resp = _get_client().chat.completions.create(
        model=_MODEL,
        messages=[
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        max_tokens=512,
    )
    return resp.choices[0].message.content or ""


def _safe_parse(raw: str) -> dict:
    text = raw.strip()
    # Strip markdown code fences if model wraps its output
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) > 1 else text
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}
