#!/usr/bin/env python3
"""Score a reconstruction against ground truth.

Primary metric is link-level precision / recall / F1 over the attack chain.
Decision correctness compares the reconstructed IR decision to the
ground-truth-correct decision.
"""

import argparse
import json
import sys


def pair_set(links):
    return {(min(a, b), max(a, b)) for a, b, _t in links}


def score_recon(recon, gt):
    pred = pair_set(recon.get("incident_links", recon["links"]))
    truth = pair_set(gt["links"])
    tp = len(pred & truth)
    fp = len(pred - truth)
    fn = len(truth - pred)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "n_predicted": len(pred),
        "n_truth": len(truth),
        "decision": recon["decision"],
        "correct_decision": gt["correct_decision"],
        "decision_correct": int(recon["decision"] == gt["correct_decision"]),
        "confidence": recon["confidence"],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("recon")
    ap.add_argument("groundtruth")
    args = ap.parse_args()

    with open(args.recon) as f:
        recon = json.load(f)
    with open(args.groundtruth) as f:
        gt = json.load(f)

    r = score_recon(recon, gt)
    print("precision %.3f  recall %.3f  f1 %.3f  (tp=%d fp=%d fn=%d)"
          % (r["precision"], r["recall"], r["f1"], r["tp"], r["fp"], r["fn"]))
    print("decision: %s (correct: %s -> %s)"
          % (r["decision"], r["correct_decision"], "yes" if r["decision_correct"] else "no"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
