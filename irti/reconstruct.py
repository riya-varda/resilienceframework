#!/usr/bin/env python3
"""Rule-based attack-chain reconstruction from a single events.log file.

This engine is deliberately blind: it only knows the log path it is given and
never imports or reads anything from gt/ or the generator modules.

Pipeline:
    1. parse observations
    2. score events for suspicion (behavioral heuristics)
    3. grow candidate chains from suspicious seeds via shared
       host/pid, parent-child, logon and document-read links
    4. map the best chain to a 3-tier IR decision with a confidence score
"""

import argparse
import ipaddress
import json
import os
import re
import sys
from datetime import datetime

DETAIL_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')
TS_FMT = "%Y-%m-%d %H:%M:%S.%f"

OFFICE = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "acrobat.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe"}
SHELLS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
          "mshta.exe", "rundll32.exe", "curl.exe", "certutil.exe"}
BAD_PARENTS = OFFICE | BROWSERS | {"w3wp.exe", "httpd.exe"}
WEBROOT_MARKERS = ("\\inetpub\\wwwroot",)
SEED_THRESHOLD = 1.5

SRC_LINK = {"network": "connected", "dns": "resolved", "file": "created"}


def parse_log(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 8:
                continue
            eid, ts, source, host, user, pid, image, details = parts
            d = {}
            for m in DETAIL_RE.finditer(details):
                v = m.group(2)
                if v.startswith('"') and v.endswith('"'):
                    v = v[1:-1]
                d[m.group(1)] = v
            events.append({
                "id": int(eid),
                "t": datetime.strptime(ts, TS_FMT),
                "source": source,
                "host": host,
                "user": user,
                "pid": None if pid in ("-", "") else int(pid),
                "image": "" if image in ("-", "") else image,
                "details": d,
            })
    events.sort(key=lambda e: e["id"])
    return events


def is_external(ip):
    """External = not RFC1918 / loopback / link-local.

    Python's ipaddress.is_private also flags documentation ranges
    (TEST-NET), which our synthetic attack IPs use, so ranges are checked
    explicitly here.
    """
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 4:
        for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                    "127.0.0.0/8", "169.254.0.0/16"):
            if a in ipaddress.ip_network(net):
                return False
        return True
    return not (a.is_loopback or a.is_link_local)


def suspicion(e):
    s = 0.0
    why = []
    img = e["image"].lower()
    d = e["details"]
    if e["source"] == "process":
        parent = d.get("parent", "").lower()
        if parent in BAD_PARENTS and img in SHELLS:
            s += 3.0
            why.append("shell-spawned-by-%s" % parent)
        if img in ("schtasks.exe", "regsvr32.exe"):
            s += 1.5
            why.append("task-or-reg")
        cmd = d.get("cmd", "").lower()
        if img == "rundll32.exe" and ("comsvcs" in cmd or "minidump" in cmd):
            s += 3.0
            why.append("credential-dump-indicator")
        if parent == "services.exe" and img in SHELLS and e["host"].startswith("SRV"):
            s += 1.0
            why.append("server-service-shell")
    elif e["source"] == "network":
        dst = d.get("dst", "")
        if dst and is_external(dst) and img in SHELLS:
            s += 2.0
            why.append("external-from-shell")
    elif e["source"] == "dns":
        q = d.get("query", "")
        first = q.split(".")[0] if q else ""
        if len(first) >= 18:
            s += 1.5
            why.append("tunnel-like-domain")
    elif e["source"] == "file":
        path = d.get("path", "").lower()
        if "\\inetpub\\wwwroot" in path or path.endswith((".aspx", ".jsp", ".php")):
            s += 2.0
            why.append("webroot-write")
        if "\\programdata" in path and img in SHELLS:
            s += 1.0
            why.append("programdata-write")
        if path.endswith(".zip") and img in SHELLS:
            s += 1.0
            why.append("archive-by-shell")
    elif e["source"] == "logon":
        if d.get("type", "") == "network" and e["host"].startswith("SRV"):
            s += 1.0
            why.append("remote-logon-to-server")
    return s, why


def _seconds(a, b):
    return abs((a - b).total_seconds())


def reconstruct(path):
    events = parse_log(path)
    by_id = {e["id"]: e for e in events}

    procs = [e for e in events if e["source"] == "process"]
    proc_by_pid = {}
    for p in procs:
        proc_by_pid[(p["host"], p["pid"])] = p

    children = {}
    for p in procs:
        ppid = p["details"].get("ppid")
        if ppid:
            children.setdefault((p["host"], int(ppid)), []).append(p)

    sats = {}
    for e in events:
        if e["source"] in SRC_LINK and e["pid"] is not None:
            sats.setdefault((e["host"], e["pid"]), []).append(e)

    logons = [e for e in events if e["source"] == "logon"]
    process_available = any(e["source"] == "process" for e in events)

    scores = {}
    for e in events:
        s, why = suspicion(e)
        if s >= SEED_THRESHOLD:
            scores[e["id"]] = (s, why)

    links = set()
    visited = set()
    frontier = list(scores)

    def add(a, b, ltype):
        if a == b:
            return
        ea, eb = by_id[a], by_id[b]
        if eb["t"] < ea["t"]:
            a, b = b, a
        links.add((a, b, ltype))

    while frontier:
        eid = frontier.pop()
        if eid in visited:
            continue
        visited.add(eid)
        e = by_id[eid]
        partners = []

        if e["source"] == "process":
            ppid = e["details"].get("ppid")
            if ppid:
                par = proc_by_pid.get((e["host"], int(ppid)))
                if par:
                    partners.append((par, "spawned"))
            for ch in children.get((e["host"], e["pid"]), []):
                partners.append((ch, "spawned"))
            for sat in sats.get((e["host"], e["pid"]), []):
                partners.append((sat, SRC_LINK[sat["source"]]))
            for lg in logons:
                if lg["details"].get("type") != "network" or lg["user"] != e["user"]:
                    continue
                # Lateral movement: a process on host A followed by a
                # network logon arriving from A onto host B.  Originally
                # restricted to seed events; relaxed to any event already
                # in the candidate chain so credential-theft vectors
                # where the lateral-movement initiator is reachable from
                # (but not itself) a high-suspicion event are traceable.
                if eid in visited and lg["details"].get("src") == e["host"] \
                        and 0 <= (lg["t"] - e["t"]).total_seconds() <= 900:
                    partners.append((lg, "authenticated"))
                if lg["host"] == e["host"] and 0 <= (e["t"] - lg["t"]).total_seconds() <= 900:
                    partners.append((lg, "authenticated"))
            # A server worker with no process record in the log that spawned a
            # shell: connect the shell back to the inbound connection that
            # carried the exploit.
            if ppid and not proc_by_pid.get((e["host"], int(ppid))) \
                    and e["details"].get("parent", "").lower() in ("w3wp.exe", "httpd.exe"):
                for cand in events:
                    if (cand["source"] == "network" and cand["host"] == e["host"]
                            and cand["pid"] == int(ppid)
                            and cand["details"].get("dir") == "in"):
                        partners.append((cand, "spawned"))
            if e["image"].lower() in ("winword.exe", "excel.exe"):
                candidates = []
                for f in events:
                    if (f["source"] == "file" and f["host"] == e["host"]
                            and f["user"] == e["user"]
                            and f["image"].lower() == "outlook.exe"
                            and _seconds(f["t"], e["t"]) <= 120
                            and f["details"].get("path", "").lower().endswith(
                                (".docm", ".doc", ".docx", ".xlsm", ".xls", ".pdf"))):
                        candidates.append(f)
                if candidates:
                    nearest = min(candidates, key=lambda f: _seconds(f["t"], e["t"]))
                    partners.append((nearest, "read"))

        elif e["source"] in SRC_LINK:
            p = proc_by_pid.get((e["host"], e["pid"])) if e["pid"] is not None else None
            if p:
                partners.append((p, SRC_LINK[e["source"]]))
            elif not process_available:
                # The process source is absent from this log entirely: fall
                # back to host/user/time correlation against other suspicious
                # events. Weaker, hence "correlated".
                for f in events:
                    if f["id"] == e["id"] or f["id"] not in scores:
                        continue
                    if (f["host"] == e["host"] and f["user"] == e["user"]
                            and _seconds(f["t"], e["t"]) <= 300):
                        partners.append((f, "correlated"))
            if (e["source"] == "network" and e["details"].get("dir") == "in"
                    and e["pid"] is not None):
                for ch in children.get((e["host"], e["pid"]), []):
                    partners.append((ch, "spawned"))

        elif e["source"] == "logon":
            for p in procs:
                if p["host"] == e["host"] and p["user"] == e["user"]:
                    dt = (p["t"] - e["t"]).total_seconds()
                    if 0 <= dt <= 900:
                        partners.append((p, "authenticated"))

        for partner, ltype in partners:
            add(e["id"], partner["id"], ltype)
            if partner["id"] not in visited:
                frontier.append(partner["id"])

    # connected components over predicted links
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for a, b, _ in links:
        union(a, b)

    comps = {}
    for eid in visited:
        if eid in parent:
            comps.setdefault(find(eid), set()).add(eid)

    best = set()
    best_score = -1.0
    for comp in comps.values():
        sc = max((scores.get(i, (0.0, []))[0] for i in comp), default=0.0)
        if sc > best_score or (sc == best_score and len(comp) > len(best)):
            best, best_score = comp, sc

    evs = [by_id[i] for i in best]
    has_lineage = any(
        e["source"] == "process"
        and e["image"].lower() in SHELLS
        and e["details"].get("parent", "").lower() in BAD_PARENTS
        for e in evs)
    # Credential-dump indicators also demonstrate execution lineage
    if not has_lineage:
        has_lineage = any(
            e["source"] == "process"
            and e["image"].lower() == "rundll32.exe"
            and ("comsvcs" in e["details"].get("cmd", "").lower()
                 or "minidump" in e["details"].get("cmd", "").lower())
            for e in evs)
    has_external = any(
        e["source"] == "network"
        and (is_external(e["details"].get("dst", ""))
             or (e["details"].get("dir") == "in" and is_external(e["details"].get("src", ""))))
        for e in evs)

    has_impact = False
    dns_by_proc = {}
    ext_by_proc = {}
    for e in evs:
        if e["source"] == "file":
            path = e["details"].get("path", "").lower()
            if (any(m in path for m in WEBROOT_MARKERS)
                    or path.endswith((".aspx", ".jsp", ".php"))
                    or (path.endswith(".zip") and e["image"].lower() in SHELLS)):
                has_impact = True
        if e["source"] == "process" and e["image"].lower() == "schtasks.exe":
            has_impact = True
        if e["source"] == "dns":
            dns_by_proc[(e["host"], e["pid"])] = dns_by_proc.get((e["host"], e["pid"]), 0) + 1
        if e["source"] == "network" and is_external(e["details"].get("dst", "")):
            key = (e["host"], e["pid"], e["image"].lower())
            ext_by_proc[key] = ext_by_proc.get(key, 0) + 1
    if any(c >= 3 for c in dns_by_proc.values()):
        has_impact = True
    if any(c >= 2 for c in ext_by_proc.values()):
        has_impact = True

    if has_lineage and has_external and has_impact:
        decision = "isolate"
    elif has_lineage or has_external:
        decision = "investigate"
    else:
        decision = "monitor"

    confidence = round(0.40 * has_lineage + 0.35 * has_external + 0.25 * has_impact, 3)

    incident_links = sorted([a, b, t] for a, b, t in links if a in best and b in best)

    return {
        "logfile": os.path.basename(path),
        "n_events": len(events),
        "n_predicted_links": len(links),
        "links": sorted([a, b, t] for a, b, t in links),
        "incident_links": incident_links,
        "chain_events": sorted(best),
        "decision": decision,
        "confidence": confidence,
        "features": {
            "lineage": has_lineage,
            "external": has_external,
            "impact": has_impact,
        },
        "suspicious_events": {
            str(eid): {"score": sc, "reasons": why}
            for eid, (sc, why) in sorted(scores.items())
        },
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    result = reconstruct(args.logfile)
    print("log:          %s" % args.logfile)
    print("events:       %d" % result["n_events"])
    print("seeds:        %d suspicious events" % len(result["suspicious_events"]))
    print("predicted:    %d links, chain of %d events"
          % (result["n_predicted_links"], len(result["chain_events"])))
    print("features:     %s" % result["features"])
    print("decision:     %s (confidence %.3f)" % (result["decision"], result["confidence"]))

    if args.out:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
        print("wrote:        %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
