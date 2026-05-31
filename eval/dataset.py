"""
dataset.py — labeled eval set for the Weave evaluation harness.

Owner: Person D (proof & demo).

~5 malicious + ~10 benign. Used by run_eval.py to score precision/recall.
Start with names; expand as the real agents come online.
"""

MALICIOUS = [
    {"package": "evil-demo-pkg", "label": "malicious"},
    # TODO add a few crafted variants (different exfil vectors) so the demo
    # shows more than one positive.
]

BENIGN = [
    {"package": "lodash", "label": "benign"},
    {"package": "express", "label": "benign"},
    {"package": "react", "label": "benign"},
    {"package": "axios", "label": "benign"},
    {"package": "chalk", "label": "benign"},
    {"package": "dotenv", "label": "benign"},
    {"package": "uuid", "label": "benign"},
    {"package": "zod", "label": "benign"},
    {"package": "commander", "label": "benign"},
    {"package": "dayjs", "label": "benign"},
]

DATASET = MALICIOUS + BENIGN