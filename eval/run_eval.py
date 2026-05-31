"""
run_eval.py — Weave evaluation harness (the "Best Use of Weave" differentiator).

Owner: Person D (proof & demo).

Runs the labeled dataset through the orchestrator and scores it. When weave is
installed + configured, prefer `weave.Evaluation` so the dashboard renders
precision/recall. This file ships a plain-Python fallback so it runs today.

Run from repo root:  python -m eval.run_eval
"""
from __future__ import annotations

import weave_shim as W
from eval.dataset import DATASET
from orchestrator import orchestrate


def predict(package: str) -> str:
    result = orchestrate(package)
    return result["verdict"].decision  # "block" -> malicious, "allow" -> benign


def main() -> None:
    W.init("quarantine")
    tp = fp = tn = fn = 0
    for row in DATASET:
        pred = predict(row["package"])
        predicted_malicious = pred == "block"
        actually_malicious = row["label"] == "malicious"
        if predicted_malicious and actually_malicious:
            tp += 1
        elif predicted_malicious and not actually_malicious:
            fp += 1
        elif not predicted_malicious and not actually_malicious:
            tn += 1
        else:
            fn += 1
        print(f"  {row['package']:<16} label={row['label']:<9} pred={pred}")

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    print("\n  ---- scores ----")
    print(f"  precision={precision:.2f}  recall={recall:.2f}  f1={f1:.2f}")
    print(f"  tp={tp} fp={fp} tn={tn} fn={fn}")

    # TODO: swap this for weave.Evaluation(dataset=..., scorers=[...]).evaluate(model)
    #       so the precision/recall dashboard renders in the Weave UI.


if __name__ == "__main__":
    main()