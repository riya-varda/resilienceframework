"""Family 1: phishing attachment -> WinWord -> encoded PowerShell.

Chain: Outlook saves a macro attachment, WinWord opens it and spawns an
encoded PowerShell, which beacons to C2, runs discovery, archives documents,
moves laterally to the file server, collects, and exfiltrates.
"""

from specs import dns, file_ev, logon, net, proc

NAME = "phishing_powershell"
DESCRIPTION = ("Phishing attachment -> WinWord -> encoded PowerShell -> C2 -> "
               "discovery/collection -> lateral movement to file server -> exfiltration")
CORRECT_DECISION = "isolate"


def build(ctx):
    rng = ctx["rng"]
    user = ctx["user"]
    ws = ctx["ws"]
    fs = ctx["fs"]
    c2_ip = ctx["attack_ips"][0]
    exfil_ip = ctx["attack_ips"][1]
    c2_domain = ctx["attack_domains"][0]
    np = ctx["next_pid"]
    t = ctx["t0"]

    p_outlook = np()
    p_winword = np()
    p_ps = np()
    p_cmd = np()
    p_ps_fs = np()

    doc = "C:\\Users\\%s\\AppData\\Local\\Temp\\invoice_%d.docm" % (user, rng.randint(100, 999))
    zip_ws = "C:\\Users\\%s\\Documents\\fin_docs_2026.zip" % user
    zip_fs = "C:\\Shares\\finance\\2026_archive.zip"
    enc = ("powershell -NoP -W Hidden -Enc "
           "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==")

    specs = [
        proc("s0", ws, user, p_outlook, "outlook.exe", t,
             parent="explorer.exe", ppid=np(),
             cmd="\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\""),
        file_ev("s1", ws, user, p_outlook, "outlook.exe", t + 3, "create", doc),
        proc("s2", ws, user, p_winword, "winword.exe", t + 6,
             parent="outlook.exe", ppid=p_outlook, cmd="WINWORD.EXE"),
        proc("s3", ws, user, p_ps, "powershell.exe", t + 9,
             parent="winword.exe", ppid=p_winword, cmd=enc),
        net("s4", ws, user, p_ps, "powershell.exe", t + 12, dst=c2_ip, dport=443),
        dns("s5", ws, user, p_ps, "powershell.exe", t + 13, c2_domain),
        proc("s6", ws, user, p_cmd, "cmd.exe", t + 90,
             parent="powershell.exe", ppid=p_ps, cmd="whoami /all & net user"),
        file_ev("s7", ws, user, p_cmd, "cmd.exe", t + 150, "create", zip_ws),
        logon("s8", fs, user, t + 300, "network", src=ws),
        proc("s9", fs, user, p_ps_fs, "powershell.exe", t + 305,
             parent="services.exe", ppid=np(),
             cmd="-Enc QwBvAGwAbABlAGMAdAAgAFMAaABhAHIAZQBzAA=="),
        file_ev("s10", fs, user, p_ps_fs, "powershell.exe", t + 420, "create", zip_fs),
        net("s11", fs, user, p_ps_fs, "powershell.exe", t + 470, dst=exfil_ip, dport=443),
    ]

    links = [
        ("s0", "s1", "created"),
        ("s0", "s2", "spawned"),
        ("s1", "s2", "read"),
        ("s2", "s3", "spawned"),
        ("s3", "s4", "connected"),
        ("s3", "s5", "resolved"),
        ("s3", "s6", "spawned"),
        ("s6", "s7", "created"),
        ("s3", "s8", "authenticated"),
        ("s8", "s9", "authenticated"),
        ("s9", "s10", "created"),
        ("s9", "s11", "connected"),
    ]
    return specs, links
