#!/usr/bin/env python3
"""Interactive demo: one incident end-to-end.

Shows generation, reconstruction, scoring, and degradation
for a single seed+vector combination.

Usage:
    python demo.py
    python demo.py --vector exploit_webshell --seed 1
"""

import argparse
import json
import os
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import degrade
import genlog
import reconstruct
from score import score_recon


def banner(title):
    print("\n" + "=" * 64)
    print("  %s" % title)
    print("=" * 64)


def section(title):
    print("\n--- %s %s" % (title, "-" * max(0, 56 - len(title))))


def show_lines(path, head=8, tail=4):
    with open(path) as f:
        lines = f.read().splitlines()
    print("  Total events: %d" % len(lines))
    print()
    for ln in lines[:head]:
        print("  %s" % ln)
    if len(lines) > head + tail:
        print("  ... (%d lines omitted) ..." % (len(lines) - head - tail))
    for ln in lines[-tail:]:
        print("  %s" % ln)


def show_gt(gt):
    print("  Vector:          %s" % gt["vector"])
    print("  Description:     %s" % gt["description"])
    print("  Correct decision: %s" % gt["correct_decision"])
    print("  Attack events:   %d events at IDs %s" % (
        len(gt["attack_events"]),
        ", ".join(str(e) for e in gt["attack_events"])))
    print("  Chain links:     %d" % len(gt["links"]))
    for a, b, t in gt["links"]:
        print("    %3d -> %3d  [%s]" % (a, b, t))


def show_recon(recon, label=""):
    if label:
        print("  [%s]" % label)
    print("  Suspicious seeds:  %d" % len(recon["suspicious_events"]))
    print("  Predicted links:   %d (incident chain: %d)" % (
        recon["n_predicted_links"], len(recon.get("incident_links", recon["links"]))))
    print("  Chain events:      %d" % len(recon["chain_events"]))
    print("  Features:          %s" % recon["features"])
    print("  Decision:          %s  (confidence %.3f)" % (
        recon["decision"], recon["confidence"]))


def show_score(r, label=""):
    if label:
        print("  [%s]" % label)
    print("  Precision: %.3f  Recall: %.3f  F1: %.3f" % (
        r["precision"], r["recall"], r["f1"]))
    print("  TP: %d  FP: %d  FN: %d" % (r["tp"], r["fp"], r["fn"]))
    print("  Decision: %s  (correct: %s -> %s)" % (
        r["decision"], r["correct_decision"],
        "YES" if r["decision_correct"] else "NO"))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vector", default="phishing_powershell")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--n", type=int, default=500)
    args = ap.parse_args()

    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="irti_demo_")

    banner("IRTI Demo: %s (seed=%d, n=%d)" % (args.vector, args.seed, args.n))

    # 1. Generate
    section("1. Generating synthetic event log")
    log_path, gt_path, gt = genlog.generate(args.seed, args.n, args.vector, tmpdir)
    with open(gt_path) as f:
        gt = json.load(f)
    print("  Log:    %s" % log_path)
    print("  GT:     %s" % gt_path)
    show_lines(log_path)

    # 2. Ground truth
    section("2. Ground truth attack chain")
    show_gt(gt)

    # 3. Full reconstruction
    section("3. Reconstruction on FULL evidence")
    recon_full = reconstruct.reconstruct(log_path)
    show_recon(recon_full, "full evidence")
    r_full = score_recon(recon_full, gt)
    show_score(r_full, "full evidence")

    # 4. Degradation: no_process
    section("4. Degradation: no_process (remove all process events)")
    deg_path = os.path.join(tmpdir, "degraded_no_process.log")
    total, kept = degrade.degrade(log_path, deg_path, "no_process")
    print("  Records: %d -> %d (%.1f%% kept)" % (total, kept, 100.0 * kept / total))
    recon_np = reconstruct.reconstruct(deg_path)
    show_recon(recon_np, "no_process")
    r_np = score_recon(recon_np, gt)
    show_score(r_np, "no_process")

    # 5. Degradation: random_50
    section("5. Degradation: random_50 (drop 50%% of records randomly)")
    deg_path2 = os.path.join(tmpdir, "degraded_random_50.log")
    total2, kept2 = degrade.degrade(log_path, deg_path2, "random_50", args.seed)
    print("  Records: %d -> %d (%.1f%% kept)" % (total2, kept2, 100.0 * kept2 / total2))
    recon_r50 = reconstruct.reconstruct(deg_path2)
    show_recon(recon_r50, "random_50")
    r_r50 = score_recon(recon_r50, gt)
    show_score(r_r50, "random_50")

    # 6. Summary table
    banner("Summary")
    print("  %-16s  %6s  %6s  %6s  %-12s  %s" % (
        "Condition", "P", "R", "F1", "Decision", "Correct?"))
    print("  " + "-" * 62)
    for label, r in [("full", r_full), ("no_process", r_np), ("random_50", r_r50)]:
        print("  %-16s  %6.3f  %6.3f  %6.3f  %-12s  %s" % (
            label, r["precision"], r["recall"], r["f1"],
            r["decision"], "YES" if r["decision_correct"] else "NO"))
    print()
    print("  Key insight: process evidence is the keystone — removing it")
    print("  severs every chain link, while random 50%% loss may preserve")
    print("  some structure depending on which records survive.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
