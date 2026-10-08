#!/usr/bin/env python3
"""Evidence degradation: drop whole sources or a random fraction of records.

Degraded logs keep original event ids (persistent record ids) so that
reconstruction output can still be matched against ground truth.

Conditions:
    full, no_process, no_network (network+dns), no_dns, no_file, no_logon,
    random_50, or random_<pct>
"""

import argparse
import os
import random
import sys

SOURCE_DROPS = {
    "no_process": {"process"},
    "no_network": {"network", "dns"},
    "no_dns": {"dns"},
    "no_file": {"file"},
    "no_logon": {"logon"},
}

ALL_CONDITIONS = ["full", "no_process", "no_network", "no_dns", "no_file", "no_logon"]

# Combined conditions (stretch goal): remove multiple sources at once.
COMBINED_CONDITIONS = [
    "no_process+no_dns",
    "no_process+no_file",
    "no_process+no_logon",
    "no_network+no_file",
    "no_network+no_logon",
    "no_dns+no_file",
    "no_dns+no_logon",
    "no_file+no_logon",
]


def _parse_combined(condition):
    """Parse a combined condition like 'no_process+no_dns' into a set of sources to drop."""
    drops = set()
    for part in condition.split("+"):
        part = part.strip()
        if part in SOURCE_DROPS:
            drops |= SOURCE_DROPS[part]
        else:
            return None
    return drops


def read_lines(path):
    with open(path) as f:
        return [ln for ln in f.read().splitlines() if ln.strip()]


def read_stats(full_path, degraded_path):
    return len(read_lines(full_path)), len(read_lines(degraded_path))


def degrade(in_path, out_path, condition, seed=0):
    lines = read_lines(in_path)
    if condition == "full":
        kept = lines
    elif condition in SOURCE_DROPS:
        drops = SOURCE_DROPS[condition]
        kept = []
        for ln in lines:
            parts = [p.strip() for p in ln.split("|")]
            if len(parts) >= 8 and parts[2] in drops:
                continue
            kept.append(ln)
    elif "+" in condition:
        drops = _parse_combined(condition)
        if drops is None:
            raise ValueError("unknown combined condition %r" % condition)
        kept = []
        for ln in lines:
            parts = [p.strip() for p in ln.split("|")]
            if len(parts) >= 8 and parts[2] in drops:
                continue
            kept.append(ln)
    elif condition.startswith("random_"):
        pct = int(condition.split("_", 1)[1])
        rng = random.Random(seed)
        kept = [ln for ln in lines if rng.random() >= pct / 100.0]
    else:
        raise ValueError("unknown condition %r" % condition)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as f:
        f.write("\n".join(kept))
        if kept:
            f.write("\n")
    return len(lines), len(kept)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile")
    ap.add_argument("--condition", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    total, kept = degrade(args.logfile, args.out, args.condition, args.seed)
    print("%s: kept %d/%d records (%.1f%%)"
          % (args.condition, kept, total, 100.0 * kept / total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
