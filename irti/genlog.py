#!/usr/bin/env python3
"""Synthetic event-log generator with a known attack chain (ground truth).

Writes:
    runs/<vector>/<seed>/events.log
    gt/<vector>_<seed>.json

The ground-truth graph is generated once and never modified. The reconstruction
engine only ever sees events.log.
"""

import argparse
import json
import os
import random
from datetime import datetime, timedelta

import benign
from vectors import get_vector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_TIME = datetime(2026, 3, 2, 8, 0, 0)

ATTACK_IPS = ["203.0.113.77", "198.51.100.23", "203.0.113.90", "192.0.2.55"]
ATTACK_DOMAINS = ["cdn-sync-update.net", "update-check.cdn-relay.net", "exfil-cdn.net"]


def _make_pid_allocator(rng):
    used = set()

    def next_pid():
        while True:
            p = rng.randint(1000, 9000)
            if p not in used:
                used.add(p)
                return p

    return next_pid


def _fmt_details(d):
    parts = []
    for k in sorted(d):
        v = str(d[k])
        if v == "" or any(c in v for c in " \t"):
            v = '"%s"' % v
        parts.append("%s=%s" % (k, v))
    return " ".join(parts)


def _fmt_time(t):
    return (BASE_TIME + timedelta(seconds=float(t))).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _fmt_line(i, s):
    pid = "-" if s["pid"] is None else str(s["pid"])
    img = s["image"] or "-"
    return "%03d | %s | %-7s | %-10s | %-8s | %5s | %-16s | %s" % (
        i, _fmt_time(s["t"]), s["source"], s["host"], s["user"],
        pid, img, _fmt_details(s["details"]))


def generate(seed, n=500, vector_name="phishing_powershell", base_dir=BASE_DIR):
    rng = random.Random(seed)
    vec = get_vector(vector_name)
    pid = _make_pid_allocator(rng)
    env = benign.make_env(rng)

    victim_user = rng.choice(sorted(env["users"]))
    victim_ws = env["users"][victim_user]
    t0 = rng.uniform(2.0 * 3600, 7.0 * 3600)  # attack starts 10:00-15:00

    ctx = {
        "rng": rng,
        "user": victim_user,
        "ws": victim_ws,
        "fs": benign.FS,
        "web": benign.WEB,
        "db": benign.DB,
        "attack_ips": list(ATTACK_IPS),
        "attack_domains": list(ATTACK_DOMAINS),
        "t0": t0,
        "next_pid": pid,
    }

    attack_specs, attack_links = vec.build(ctx)
    benign_specs = benign.build(rng, max(0, n - len(attack_specs)), env, pid)
    for i, s in enumerate(benign_specs):
        s["key"] = "b%04d" % i

    all_specs = benign_specs + attack_specs
    all_specs.sort(key=lambda s: (s["t"], s["key"]))

    spec_by_key = {s["key"]: s for s in all_specs}
    ids = {s["key"]: i for i, s in enumerate(all_specs)}

    for a, b, _ltype in attack_links:
        if a not in ids or b not in ids:
            raise ValueError("attack link references unknown key: %s -> %s" % (a, b))
        if spec_by_key[b]["t"] < spec_by_key[a]["t"]:
            raise ValueError("attack link goes backwards in time: %s -> %s" % (a, b))

    run_dir = os.path.join(base_dir, "runs", vector_name, str(seed))
    gt_dir = os.path.join(base_dir, "gt")
    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(gt_dir, exist_ok=True)

    log_path = os.path.join(run_dir, "events.log")
    with open(log_path, "w") as f:
        for i, s in enumerate(all_specs):
            f.write(_fmt_line(i, s) + "\n")

    gt = {
        "seed": seed,
        "n": len(all_specs),
        "vector": vector_name,
        "description": vec.DESCRIPTION,
        "correct_decision": vec.CORRECT_DECISION,
        "attack_events": sorted(ids[s["key"]] for s in attack_specs),
        "links": sorted([ids[a], ids[b], t] for a, b, t in attack_links),
    }
    gt_path = os.path.join(gt_dir, "%s_%d.json" % (vector_name, seed))
    with open(gt_path, "w") as f:
        json.dump(gt, f, indent=2, sort_keys=True)
        f.write("\n")

    return log_path, gt_path, gt


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--n", type=int, default=500, help="total events per log")
    ap.add_argument("--vector", default="phishing_powershell")
    ap.add_argument("--list-vectors", action="store_true")
    args = ap.parse_args()

    if args.list_vectors:
        from vectors import all_vectors
        for name, mod in sorted(all_vectors().items()):
            print("%-24s %s" % (name, mod.DESCRIPTION))
        return

    log_path, gt_path, gt = generate(args.seed, args.n, args.vector)
    print("vector:      %s" % gt["vector"])
    print("seed:        %d" % gt["seed"])
    print("events:      %d" % gt["n"])
    print("attack:      %d events, %d links" % (len(gt["attack_events"]), len(gt["links"])))
    print("log:         %s" % os.path.relpath(log_path, BASE_DIR))
    print("groundtruth: %s" % os.path.relpath(gt_path, BASE_DIR))


if __name__ == "__main__":
    main()
