#!/usr/bin/env python3
"""One-command reproduction of all IRTI results.

Usage:
    python reproduce.py                    # default: 5 seeds, 500 events
    python reproduce.py --seeds 0 1 2      # fewer seeds for quick check
    python reproduce.py --skip-plots       # skip matplotlib-dependent plots
"""
import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--skip-plots", action="store_true")
    ap.add_argument("--skip-tests", action="store_true")
    args = ap.parse_args()
    
    python = sys.executable
    start = time.time()
    
    # Step 1: Run self-tests
    if not args.skip_tests:
        print("=" * 60)
        print("STEP 1: Running self-tests")
        print("=" * 60)
        rc = subprocess.call([python, os.path.join(HERE, "selftest.py"), "-v"], cwd=HERE)
        if rc != 0:
            print("\nSelf-tests FAILED (exit %d). Fix before reproducing." % rc)
            return rc
        print()
    
    # Step 2: Full experiment sweep
    print("=" * 60)
    print("STEP 2: Full experiment sweep")
    print("=" * 60)
    seeds_arg = [str(s) for s in args.seeds]
    cmd = [python, os.path.join(HERE, "run.py"),
           "--seeds"] + seeds_arg + [
           "--n", str(args.n),
           "--random-losses", "10", "25", "50", "75", "90"]
    rc = subprocess.call(cmd, cwd=HERE)
    if rc != 0:
        print("\nExperiment sweep FAILED (exit %d)." % rc)
        return rc
    print()
    
    # Step 3: Generate plots
    if not args.skip_plots:
        print("=" * 60)
        print("STEP 3: Generating figures")
        print("=" * 60)
        rc = subprocess.call([python, os.path.join(HERE, "plots.py")], cwd=HERE)
        if rc != 0:
            print("\nPlot generation failed (matplotlib missing?). Skipping.")
        print()
    
    elapsed = time.time() - start
    print("=" * 60)
    print("REPRODUCTION COMPLETE in %.1f seconds" % elapsed)
    print("=" * 60)
    results_path = os.path.join(HERE, "results", "results.csv")
    figures_dir = os.path.join(HERE, "results", "figures")
    print("Results: %s" % os.path.relpath(results_path, HERE))
    if os.path.isdir(figures_dir):
        figs = [f for f in os.listdir(figures_dir) if f.endswith(".png")]
        print("Figures: %d plots in %s" % (len(figs), os.path.relpath(figures_dir, HERE)))
    return 0

if __name__ == "__main__":
    sys.exit(main())
