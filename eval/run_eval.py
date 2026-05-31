"""
run_eval.py — Weave Evaluation harness (the "Best Use of Weave" differentiator).

Owner: Person D (proof & demo).

Runs the labeled dataset through the orchestrator using weave.Evaluation, which
renders a real Evaluation dashboard in Weave (per-example results table, the full
agent trace for each package, and aggregate precision/recall/F1 at the top).

Falls back to a plain-Python tally if weave isn't installed, so it always runs.

Run from repo root (venv active):  python -m eval.run_eval
"""
from __future__ import annotations

import asyncio

import weave_shim as W
from eval.dataset import DATASET
from orchestrator import orchestrate

try:
    import weave

    _HAS_WEAVE = True
except Exception:
    _HAS_WEAVE = False


@W.op
def predict(package: str) -> dict:
    """The 'model' under evaluation: run the full orchestrator, return its call."""
    try:
        result = orchestrate(package)
        decision = result["verdict"].decision
    except Exception as e:  # never let one package crash the whole eval
        decision = f"error:{type(e).__name__}"
    return {"decision": decision, "predicted_malicious": decision == "block"}


@W.op
def correctness(label: str, output: dict) -> dict:
    """Scorer: compare the prediction to the ground-truth label."""
    pred = bool(output.get("predicted_malicious"))
    actual = label == "malicious"
    return {
        "correct": pred == actual,
        "true_positive": pred and actual,
        "false_positive": pred and not actual,
        "false_negative": (not pred) and actual,
        "true_negative": (not pred) and not actual,
    }


def _count(summary: dict, key: str) -> int | None:
    """Pull a boolean scorer's true_count out of the weave summary, defensively."""
    node = summary.get("correctness", {}) if isinstance(summary, dict) else {}
    cell = node.get(key, {}) if isinstance(node, dict) else {}
    if isinstance(cell, dict):
        return cell.get("true_count")
    return None


def run_weave_eval() -> None:
    evaluation = weave.Evaluation(
        name="quarantine-supplychain",
        dataset=DATASET,
        scorers=[correctness],
    )
    summary = asyncio.run(evaluation.evaluate(predict))
    print("\n--- weave.Evaluation summary ---")
    print(summary)

    tp = _count(summary, "true_positive")
    fp = _count(summary, "false_positive")
    fn = _count(summary, "false_negative")
    if None not in (tp, fp, fn):
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        print(f"\n  precision={precision:.2f}  recall={recall:.2f}  f1={f1:.2f}")
        print(f"  tp={tp} fp={fp} fn={fn}")
    print("\nOpen the Weave dashboard link above to see the Evaluation table.")


def run_manual() -> None:
    tp = fp = tn = fn = 0
    for row in DATASET:
        out = predict(row["package"])
        pred = out["predicted_malicious"]
        actual = row["label"] == "malicious"
        tp += pred and actual
        fp += pred and not actual
        tn += (not pred) and not actual
        fn += (not pred) and actual
        print(f"  {row['package']:<16} label={row['label']:<9} -> {out['decision']}")
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    print(f"\n  precision={precision:.2f}  recall={recall:.2f}  f1={f1:.2f}  (tp={tp} fp={fp} tn={tn} fn={fn})")


def main() -> None:
    W.init("quarantine")
    if _HAS_WEAVE:
        run_weave_eval()
    else:
        run_manual()


if __name__ == "__main__":
    main()
