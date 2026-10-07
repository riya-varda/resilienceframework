"""Event-spec constructors shared by the benign simulator and the attack vectors.

A spec is a plain dict:
    key, source, host, user, pid, image, t (seconds since sim start), details

genlog.py time-sorts all specs, assigns global event ids, and renders the log.
"""


def proc(key, host, user, pid, image, t, parent=None, ppid=None, cmd=None):
    d = {}
    if ppid is not None:
        d["ppid"] = ppid
    if parent is not None:
        d["parent"] = parent
    if cmd is not None:
        d["cmd"] = cmd
    return {"key": key, "source": "process", "host": host, "user": user,
            "pid": pid, "image": image, "t": float(t), "details": d}


def net(key, host, user, pid, image, t, dst=None, src=None, dport=443,
        proto="tcp", direction=None):
    d = {"proto": proto}
    if direction:
        d["dir"] = direction
    if src:
        d["src"] = src
    if dst:
        d["dst"] = dst
        d["dport"] = dport
    return {"key": key, "source": "network", "host": host, "user": user,
            "pid": pid, "image": image, "t": float(t), "details": d}


def dns(key, host, user, pid, image, t, query):
    return {"key": key, "source": "dns", "host": host, "user": user,
            "pid": pid, "image": image, "t": float(t),
            "details": {"query": query}}


def file_ev(key, host, user, pid, image, t, op, path):
    return {"key": key, "source": "file", "host": host, "user": user,
            "pid": pid, "image": image, "t": float(t),
            "details": {"op": op, "path": path}}


def logon(key, host, user, t, type_="interactive", src=None):
    return {"key": key, "source": "logon", "host": host, "user": user,
            "pid": None, "image": "", "t": float(t),
            "details": {"type": type_, "src": src or host}}
