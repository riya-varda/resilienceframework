"""Benign background activity for the synthetic event log.

Generates routine user and server activity (logons, browsers, Office, dev
tools, backups, web traffic) plus deliberate "look-alike" events that resemble
attack patterns without being part of the attack chain. These look-alikes are
what make reconstruction precision non-trivial.

No ground-truth links are produced here: benign activity is distractor noise.
"""

from specs import dns, file_ev, logon, net, proc

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
         "ivan", "judy", "karl", "linda", "mallory", "niaj", "olivia", "itadmin"]
WORKSTATIONS = ["WS-%02d" % i for i in range(1, 13)]
WEB, DB, FS, DC = "SRV-WEB01", "SRV-DB01", "SRV-FS01", "DC-01"

BENIGN_DOMAINS = [
    "outlook.office365.com", "teams.microsoft.com", "www.google.com",
    "github.com", "cdn.jsdelivr.net", "registry.npmjs.org", "pypi.org",
    "api.slack.com", "serverfault.com", "onedrive.live.com",
    "sharepoint.com", "intranet.corp.local", "srv-db01.corp.local",
    "srv-fs01.corp.local",
]

BENIGN_IPS = [
    "13.107.42.12", "52.113.194.132", "142.250.190.14", "140.82.112.3",
    "104.16.132.229", "151.101.1.140", "204.79.197.200", "20.190.160.20",
    "40.126.32.130", "52.96.0.16",
]

BENIGN_CLIENT_IPS = ["45.33.32.156", "185.199.108.153", "51.15.0.10", "88.99.0.5"]

INTERNAL_DB_IP = "10.0.3.11"


def make_env(rng):
    """Assign users to workstations; returns {user: host} plus host list."""
    wss = list(WORKSTATIONS)
    rng.shuffle(wss)
    users = {}
    for i, user in enumerate(sorted(USERS)):
        users[user] = wss[i % len(wss)]
    return {"users": users}


def build(rng, target, env, pid):
    """Return exactly `target` benign event specs."""
    specs = _sessions(rng, env, pid)
    specs.sort(key=lambda s: s["t"])
    if len(specs) > target:
        specs = specs[:target]
    elif len(specs) < target:
        specs.extend(_noise(rng, target - len(specs), env, pid))
    return specs


def _sessions(rng, env, pid):
    specs = []
    for user in sorted(env["users"]):
        host = env["users"][user]
        if user == "itadmin":
            kinds = ["it"]
            if rng.random() < 0.7:
                kinds.append("morning")
        else:
            kinds = [_pick_kind(rng)]
            if rng.random() < 0.6:
                kinds.append(_pick_kind(rng))
        for kind in kinds:
            start = rng.uniform(0.0, 8.5 * 3600)
            specs.extend(_SESSIONS[kind](rng, user, host, start, pid))
    specs.extend(_sess_web(rng, pid))
    specs.extend(_sess_db(rng, pid))
    specs.extend(_sess_fs(rng, pid, env))
    specs.extend(_sess_dc(rng, pid, env))
    return specs


def _pick_kind(rng):
    r = rng.random()
    if r < 0.52:
        return "morning"
    if r < 0.73:
        return "finance"
    if r < 0.95:
        return "dev"
    return "macro"


def _sess_morning(rng, user, host, t0, pid):
    po, pe, pt, pc = pid(), pid(), pid(), pid()
    ev = [
        logon(None, host, user, t0, "interactive"),
        proc(None, host, user, pe, "explorer.exe", t0 + 2, parent="userinit.exe", ppid=pid()),
        proc(None, host, user, po, "outlook.exe", t0 + 6, parent="explorer.exe", ppid=pe,
             cmd="\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""),
        net(None, host, user, po, "outlook.exe", t0 + 9, dst="13.107.42.12"),
        dns(None, host, user, po, "outlook.exe", t0 + 9.5, "outlook.office365.com"),
        proc(None, host, user, pt, "teams.exe", t0 + 15, parent="explorer.exe", ppid=pe),
        net(None, host, user, pt, "teams.exe", t0 + 18, dst="52.113.194.132"),
        dns(None, host, user, pt, "teams.exe", t0 + 18.4, "teams.microsoft.com"),
        proc(None, host, user, pc, "chrome.exe", t0 + 30, parent="explorer.exe", ppid=pe),
        dns(None, host, user, pc, "chrome.exe", t0 + 33, "www.google.com"),
        net(None, host, user, pc, "chrome.exe", t0 + 33.3, dst="142.250.190.14"),
        dns(None, host, user, pc, "chrome.exe", t0 + 60, "github.com"),
        net(None, host, user, pc, "chrome.exe", t0 + 60.5, dst="140.82.112.3"),
        file_ev(None, host, user, pc, "chrome.exe", t0 + 62, "create",
                "C:\\Users\\%s\\Downloads\\report.pdf" % user),
    ]
    # Benign attachment flow: a word document saved by Outlook, then opened.
    if rng.random() < 0.4:
        doc = "C:\\Users\\%s\\Documents\\notes_%d.docx" % (user, rng.randint(100, 999))
        pw = pid()
        ev.append(file_ev(None, host, user, po, "outlook.exe", t0 + 80, "create", doc))
        ev.append(proc(None, host, user, pw, "winword.exe", t0 + 84,
                       parent="outlook.exe", ppid=po, cmd="WINWORD.EXE"))
    return ev


def _sess_finance(rng, user, host, t0, pid):
    pe, px, pw = pid(), pid(), pid()
    book = "C:\\Users\\%s\\Documents\\budget_2026.xlsx" % user
    return [
        logon(None, host, user, t0, "interactive"),
        proc(None, host, user, pe, "explorer.exe", t0 + 2, parent="userinit.exe", ppid=pid()),
        proc(None, host, user, px, "excel.exe", t0 + 8, parent="explorer.exe", ppid=pe, cmd="EXCEL.EXE"),
        file_ev(None, host, user, px, "excel.exe", t0 + 11, "modify", book),
        dns(None, host, user, px, "excel.exe", t0 + 14, "sharepoint.com"),
        net(None, host, user, px, "excel.exe", t0 + 14.5, dst="40.126.32.130"),
        proc(None, host, user, pw, "winword.exe", t0 + 40, parent="explorer.exe", ppid=pe, cmd="WINWORD.EXE"),
        file_ev(None, host, user, pw, "winword.exe", t0 + 46, "create",
                "C:\\Users\\%s\\Documents\\quarterly_review.docx" % user),
    ]


def _sess_dev(rng, user, host, t0, pid):
    pe, pc, pn = pid(), pid(), pid()
    return [
        logon(None, host, user, t0, "interactive"),
        proc(None, host, user, pe, "explorer.exe", t0 + 2, parent="userinit.exe", ppid=pid()),
        proc(None, host, user, pc, "code.exe", t0 + 10, parent="explorer.exe", ppid=pe, cmd="code.exe"),
        proc(None, host, user, pn, "node.exe", t0 + 14, parent="code.exe", ppid=pc, cmd="node index.js"),
        dns(None, host, user, pn, "node.exe", t0 + 17, "registry.npmjs.org"),
        net(None, host, user, pn, "node.exe", t0 + 17.4, dst="104.16.132.229"),
        dns(None, host, user, pn, "node.exe", t0 + 25, "pypi.org"),
        net(None, host, user, pn, "node.exe", t0 + 25.4, dst="151.101.1.140"),
        file_ev(None, host, user, pc, "code.exe", t0 + 30, "modify",
                "C:\\Users\\%s\\dev\\app\\index.js" % user),
    ]


def _sess_it(rng, user, host, t0, pid):
    """IT admin routine. Sometimes PowerShell reaches an external host."""
    pe, pp = pid(), pid()
    ev = [
        logon(None, host, user, t0, "interactive"),
        proc(None, host, user, pe, "explorer.exe", t0 + 2, parent="userinit.exe", ppid=pid()),
        proc(None, host, user, pp, "powershell.exe", t0 + 10, parent="explorer.exe", ppid=pe,
             cmd="powershell -File C:\\scripts\\deploy.ps1"),
        file_ev(None, host, user, pp, "powershell.exe", t0 + 12, "create",
                "C:\\scripts\\deploy.ps1"),
        net(None, host, user, pp, "powershell.exe", t0 + 20, dst=INTERNAL_DB_IP, dport=1433),
        dns(None, host, user, pp, "powershell.exe", t0 + 20.5, "srv-db01.corp.local"),
    ]
    if rng.random() < 0.25:
        ev.append(net(None, host, user, pp, "powershell.exe", t0 + 40,
                      dst="140.82.112.3", dport=443))
    return ev


def _sess_macro(rng, user, host, t0, pid):
    """Benign macro workbook that spawns a shell. A near-miss pattern."""
    pe, pc, px, pp = pid(), pid(), pid(), pid()
    macro = "C:\\Users\\%s\\Downloads\\macro_tool_%d.xlsm" % (user, rng.randint(10, 99))
    return [
        logon(None, host, user, t0, "interactive"),
        proc(None, host, user, pe, "explorer.exe", t0 + 2, parent="userinit.exe", ppid=pid()),
        proc(None, host, user, pc, "chrome.exe", t0 + 8, parent="explorer.exe", ppid=pe),
        file_ev(None, host, user, pc, "chrome.exe", t0 + 12, "create", macro),
        proc(None, host, user, px, "excel.exe", t0 + 16, parent="explorer.exe", ppid=pe, cmd="EXCEL.EXE"),
        proc(None, host, user, pp, "powershell.exe", t0 + 20, parent="excel.exe", ppid=px,
             cmd="powershell -c \"Write-Host refresh\""),
        file_ev(None, host, user, pp, "powershell.exe", t0 + 22, "create",
                "C:\\Users\\%s\\AppData\\Local\\Temp\\refresh.log" % user),
    ]


def _sess_web(rng, pid):
    """Web server handling benign traffic; occasionally a deployment write."""
    pw = pid()
    t0 = rng.uniform(0.0, 2.0 * 3600)
    ev = [proc(None, WEB, "SYSTEM", pw, "w3wp.exe", t0, parent="services.exe", ppid=pid())]
    for _ in range(rng.randint(2, 4)):
        t = t0 + rng.uniform(600, 7.5 * 3600)
        ev.append(net(None, WEB, "SYSTEM", pw, "w3wp.exe", t, dst=INTERNAL_DB_IP, dport=1433))
        ev.append(dns(None, WEB, "SYSTEM", pw, "w3wp.exe", t + 0.2, "intranet.corp.local"))
    if rng.random() < 0.4:
        ev.append(net(None, WEB, "SYSTEM", pw, "w3wp.exe",
                      t0 + rng.uniform(600, 7.5 * 3600),
                      src=rng.choice(BENIGN_CLIENT_IPS), direction="in"))
    if rng.random() < 0.35:
        pr = pid()
        t = t0 + rng.uniform(600, 7.5 * 3600)
        ev.append(proc(None, WEB, "SYSTEM", pr, "robocopy.exe", t,
                       parent="cmd.exe", ppid=pid()))
        ev.append(file_ev(None, WEB, "SYSTEM", pr, "robocopy.exe", t + 5, "create",
                          "C:\\inetpub\\wwwroot\\app\\release.js"))
    return ev


def _sess_db(rng, pid):
    ps = pid()
    t0 = rng.uniform(0.0, 2.0 * 3600)
    return [
        proc(None, DB, "SYSTEM", ps, "sqlservr.exe", t0, parent="services.exe", ppid=pid()),
        net(None, DB, "SYSTEM", ps, "sqlservr.exe", t0 + rng.uniform(600, 7 * 3600),
            src="10.0.1.%d" % rng.randint(20, 40), direction="in", dport=1433),
        file_ev(None, DB, "SYSTEM", ps, "sqlservr.exe", t0 + rng.uniform(600, 7 * 3600),
                "create", "D:\\backups\\model_%03d.bak" % rng.randint(1, 999)),
    ]


def _sess_fs(rng, pid, env):
    pb = pid()
    t0 = rng.uniform(0.0, 4.0 * 3600)
    ev = [
        proc(None, FS, "SYSTEM", pb, "backup.exe", t0, parent="services.exe", ppid=pid()),
        file_ev(None, FS, "SYSTEM", pb, "backup.exe", t0 + 30, "create",
                "C:\\Shares\\backups\\daily_backup_%03d.zip" % rng.randint(1, 999)),
    ]
    for user in rng.sample(sorted(env["users"]), 2):
        ev.append(logon(None, FS, user, rng.uniform(1.0 * 3600, 8.0 * 3600),
                        "network", src=env["users"][user]))
    return ev


def _sess_dc(rng, pid, env):
    ev = []
    for _ in range(rng.randint(2, 3)):
        user = rng.choice(sorted(env["users"]))
        ev.append(logon(None, DC, user, rng.uniform(0.0, 8.0 * 3600),
                        "network", src=env["users"][user]))
    return ev


def _noise(rng, count, env, pid):
    """Lonely DNS/network heartbeats spread across the day."""
    users = sorted(env["users"])
    specs = []
    for i in range(count):
        user = rng.choice(users)
        host = env["users"][user]
        t = rng.uniform(0.0, 10.0 * 3600)
        image = rng.choice(["svchost.exe", "OneDrive.exe", "teams.exe", "SearchIndexer.exe"])
        p = pid()
        if rng.random() < 0.5:
            specs.append(dns(None, host, user, p, image, t, rng.choice(BENIGN_DOMAINS)))
        else:
            specs.append(net(None, host, user, p, image, t, dst=rng.choice(BENIGN_IPS)))
    return specs


_SESSIONS = {
    "morning": _sess_morning,
    "finance": _sess_finance,
    "dev": _sess_dev,
    "it": _sess_it,
    "macro": _sess_macro,
}
