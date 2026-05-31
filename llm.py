"""
llm.py — shared W&B Inference client (a SPONSOR tool).

All LLM agents call through here. Because weave.init() is active, Weave
autopatches the OpenAI client, so every call here is traced into Weave
automatically and nests under the calling agent.

Owner: Person C (intelligence) / shared.

Set your W&B API key in the environment before running:
    export WANDB_API_KEY="...your key from https://wandb.ai/authorize..."
"""
from __future__ import annotations

import os
import openai

# Load .env here too, so this module works even when imported standalone
# (not just via weave_shim). Safe no-op if python-dotenv isn't installed.
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

# Your W&B team/project (used by Inference for usage tracking).
WANDB_PROJECT = "jenishk1800-student/quarantine"

# Model id from the W&B Inference catalog. Swap if a better one is available.
MODEL = "deepseek-ai/DeepSeek-V4-Pro"


def _api_key() -> str | None:
    return os.environ.get("WANDB_API_KEY") or os.environ.get("OPENAI_API_KEY")


def get_client() -> openai.OpenAI:
    return openai.OpenAI(
        base_url="https://api.inference.wandb.ai/v1",
        api_key=_api_key(),
        project=WANDB_PROJECT,
    )


def chat(messages: list[dict], **kwargs) -> str:
    """Send a chat completion and return the text content."""
    client = get_client()
    resp = client.chat.completions.create(model=MODEL, messages=messages, **kwargs)
    return resp.choices[0].message.content


def available() -> bool:
    """True if we have a key to call the API (lets agents fall back gracefully)."""
    return _api_key() is not None