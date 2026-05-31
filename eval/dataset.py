"""
dataset.py — curated, HONEST eval set for the Weave evaluation harness.

Owner: Person D (proof & demo).

The set is small and reliable on purpose — it exercises all three detection
layers so the precision/recall dashboard is meaningful and reproducible on stage:

  1. BEHAVIORAL (detonation)  — evil-demo-pkg runs in the sandbox; strace catches
                                the honeytoken reads + exfil. (Add real Datadog
                                samples here as local dirs for a richer run.)
  2. REPUTATION (intel)       — typosquats are caught deterministically by the
                                local Levenshtein check (no network needed),
                                so intel flags clearly_malicious and we block.
  3. BENIGN (no false positive)— popular packages, incl. ones WITH legit install
                                scripts (esbuild/sharp), must come back ALLOW.

Honest note for judges: dynamic detection only catches behavior that executes in
our sandbox. We report detection on the behaviorally-observable + reputation set,
not a claim of 100% recall over all malware categories (wipers, import-only
payloads, target-gated logic can evade dynamic analysis).

To add a REAL malicious sample from the Datadog dataset:
  1. extract it (password "infected") into a local dir, e.g. ./samples/<name>/
     containing its package.json + entry/postinstall.
  2. point sandbox_agent at it (it detonates REPO_ROOT/<package>), set
     SEAL_NETWORK=True in agents/sandbox.py first.
  3. add {"package": "<name>", "label": "malicious", "kind": "behavioral"} below.
"""

# 1) Behavioral — actually detonated in the sandbox.
BEHAVIORAL_MALICIOUS = [
    {"package": "evil-demo-pkg", "label": "malicious", "kind": "behavioral"},
]

# 2) Reputation — typosquats of popular packages (caught by intel, deterministic).
TYPOSQUAT_MALICIOUS = [
    {"package": "expresss", "label": "malicious", "kind": "typosquat"},
    {"package": "reactt", "label": "malicious", "kind": "typosquat"},
    {"package": "axioss", "label": "malicious", "kind": "typosquat"},
]

# 3a) Benign popular packages (no install scripts).
BENIGN = [
    {"package": "lodash", "label": "benign", "kind": "benign"},
    {"package": "express", "label": "benign", "kind": "benign"},
    {"package": "react", "label": "benign", "kind": "benign"},
    {"package": "axios", "label": "benign", "kind": "benign"},
    {"package": "chalk", "label": "benign", "kind": "benign"},
    {"package": "dotenv", "label": "benign", "kind": "benign"},
    {"package": "uuid", "label": "benign", "kind": "benign"},
    {"package": "zod", "label": "benign", "kind": "benign"},
]

# 3b) Benign packages WITH legit install scripts — false-positive stress test.
BENIGN_WITH_SCRIPTS = [
    {"package": "esbuild", "label": "benign", "kind": "benign_with_scripts"},
    {"package": "sharp", "label": "benign", "kind": "benign_with_scripts"},
]

DATASET = BEHAVIORAL_MALICIOUS + TYPOSQUAT_MALICIOUS + BENIGN + BENIGN_WITH_SCRIPTS
