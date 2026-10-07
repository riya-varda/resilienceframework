#!/usr/bin/env python3
"""Experiment runner: seed x degradation condition sweep.

For each (vector, seed):
    generate the full log (if missing) -> degrade per condition ->
    reconstruct -> score -> results.csv

Ground truth is only read here (the evaluator), never by reconstruct.py.
"""

import argparse
import csv
import json
import os
import sys

import degrade
import genlog
import reconstruct
from score import score_recon
from vectors import all_vectors

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CSV_FIELDS = [
    "vector", "seed", "condition", "n_total", "n_kept", "evidence_pct",
    "precision", "recall", "f1", "tp", "fp", "fn",
    "confidence", "decision", "correct_decision", "decision_correct",
]


def run(seeds, vectors, n, conditions, base_dir=BASE_DIR):
    rows = []
    for vector in vectors:
        for seed in seeds:
            log_path, gt_path, gt = genlog.generate(seed, n, vector, base_dir)
            with open(gt_path) as f:
                gt = json.load(f)
            run_dir = os.path.dirname(log_path)
            for cond in conditions:
                if cond == "full":
                    degraded = log_path
                else:
                    degraded = os.path.join(run_dir, "degraded", cond + ".log")
                    degrade.degrade(log_path, degraded, cond, seed)
                recon = reconstruct.reconstruct(degraded)
                r = score_recon(recon, gt)
                total, kept = degrade.read_stats(log_path, degraded)
                rows.append({
                    "vector": vector,
                    "seed": seed,
                    "condition": cond,
                    "n_total": total,
                    "n_kept": kept,
                    "evidence_pct": round(100.0 * kept / total, 1) if total else 0.0,
                    "precision": r["precision"],
                    "recall": r["recall"],
                    "f1": r["f1"],
                    "tp": r["tp"],
                    "fp": r["fp"],
                    "fn": r["fn"],
                    "confidence": r["confidence"],
                    "decision": r["decision"],
                    "correct_decision": r["correct_decision"],
                    "decision_correct": r["decision_correct"],
                })
    return rows


def write_csv(rows, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)


def summarize(rows):
    groups = {}
    for r in rows:
        groups.setdefault((r["vector"], r["condition"]), []).append(r)

    def mean(rs, k):
        return sum(r[k] for r in rs) / len(rs)

    order = sorted(groups.items(),
                   key=lambda kv: (kv[0][0], -mean(kv[1], "evidence_pct")))
    print("%-22s %-12s %6s %6s %6s %6s %5s" %
          ("vector", "condition", "ev%", "P", "R", "F1", "dec"))
    for (vector, cond), rs in order:
        print("%-22s %-12s %6.1f %6.3f %6.3f %6.3f %5.2f" %
              (vector, cond, mean(rs, "evidence_pct"), mean(rs, "precision"),
               mean(rs, "recall"), mean(rs, "f1"), mean(rs, "decision_correct")))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    ap.add_argument("--vectors", nargs="+", default=None)
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--conditions", nargs="+", default=degrade.ALL_CONDITIONS)
    ap.add_argument("--random-losses", type=int, nargs="*", default=[],
                    help="additional random-record-loss percentages, e.g. 10 25 50 75 90")
    ap.add_argument("--out", default=os.path.join(BASE_DIR, "results", "results.csv"))
    args = ap.parse_args()

    conditions = list(args.conditions)
    for pct in args.random_losses:
        cond = "random_%d" % pct
        if cond not in conditions:
            conditions.append(cond)

    vectors = args.vectors or sorted(all_vectors())
    rows = run(args.seeds, vectors, args.n, conditions)
    write_csv(rows, args.out)
    print("wrote %s (%d rows)\n" % (os.path.relpath(args.out, BASE_DIR), len(rows)))
    summarize(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
