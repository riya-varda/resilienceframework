"""Family 3: RDP brute-force -> credential dump -> C2 -> lateral move -> exfil.

Chain: an external attacker gains access via brute-forced RDP credentials,
spawns cmd on the workstation, uses rundll32 + comsvcs.dll to dump lsass,
launches PowerShell for C2, establishes persistence via scheduled task,
moves laterally to the file server using stolen credentials, stages data
into an archive, and exfiltrates over HTTPS.

Detection anchors (suspicion >= 1.5):
    - powershell.exe with external network connection (2.0)
    - schtasks.exe process creation (1.5)
    - cmd.exe with external network on SRV-* host (2.0)
    - .zip creation by shell in ProgramData (1.0 + 1.0 = counted once per event)
"""

from specs import dns, file_ev, logon, net, proc

NAME = "credential_dumping"
DESCRIPTION = ("RDP brute-force -> credential dump (lsass) -> PowerShell C2 -> "
               "schtasks persistence -> lateral movement to file server -> "
               "data exfiltration")
CORRECT_DECISION = "isolate"


def build(ctx):
    rng = ctx["rng"]
    user = ctx["user"]
    ws = ctx["ws"]
    fs = ctx["fs"]          # SRV-FS01, starts with SRV
    c2_ip = ctx["attack_ips"][0]
    exfil_ip = ctx["attack_ips"][1]
    rdp_src_ip = ctx["attack_ips"][2]
    c2_domain = ctx["attack_domains"][0]
    np = ctx["next_pid"]
    t = ctx["t0"]

    p_cmd_ws = np()
    p_rundll = np()
    p_ps_ws = np()
    p_schtasks = np()
    p_ps_fs = np()

    lsass_dump = "C:\\ProgramData\\lsass.dmp"
    archive = "C:\\Shares\\backups\\exfil_data.zip"

    specs = [
        # s0: RDP brute-force success - network logon from external IP
        logon("s0", ws, user, t, "network", src=rdp_src_ip),

        # s1: post-RDP shell - cmd spawned (parent set to w3wp.exe is wrong for
        #     RDP, so we use explorer for realism; suspicion comes downstream)
        proc("s1", ws, user, p_cmd_ws, "cmd.exe", t + 8,
             parent="explorer.exe", ppid=np(),
             cmd="cmd.exe /c echo compromised"),

        # s2: credential dumping - rundll32 loading comsvcs.dll for lsass dump
        proc("s2", ws, user, p_rundll, "rundll32.exe", t + 25,
             parent="cmd.exe", ppid=p_cmd_ws,
             cmd="rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump "
                 "720 C:\\ProgramData\\lsass.dmp full"),

        # s3: lsass dump file written to ProgramData (programdata-write = 1.0
        #     when image is a shell)
        file_ev("s3", ws, user, p_rundll, "rundll32.exe", t + 30,
                "create", lsass_dump),

        # s4: PowerShell for C2 - spawned by cmd (shell parent ok)
        proc("s4", ws, user, p_ps_ws, "powershell.exe", t + 60,
             parent="cmd.exe", ppid=p_cmd_ws,
             cmd="powershell -NoP -W Hidden -Enc "
                 "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="),

        # s5: DNS lookup for C2
        dns("s5", ws, user, p_ps_ws, "powershell.exe", t + 65, c2_domain),

        # s6: C2 beacon - PowerShell connects externally
        #     (external-from-shell = 2.0, passes SEED_THRESHOLD)
        net("s6", ws, user, p_ps_ws, "powershell.exe", t + 70,
            dst=c2_ip, dport=443),

        # s7: persistence - schtasks (suspicion 1.5, passes SEED_THRESHOLD)
        proc("s7", ws, user, p_schtasks, "schtasks.exe", t + 100,
             parent="powershell.exe", ppid=p_ps_ws,
             cmd="/create /tn PersistBackdoor /tr powershell.exe /sc minute /mo 15"),

        # s8: lateral movement - network logon to file server
        logon("s8", fs, user, t + 200, "network", src=ws),

        # s9: remote shell on FS - powershell spawned by services
        #     (server-service-shell = 1.0 on SRV-* host)
        proc("s9", fs, user, p_ps_fs, "powershell.exe", t + 210,
             parent="services.exe", ppid=np(),
             cmd="powershell -Enc "
                 "Q29tcHJlc3MtQXJjaGl2ZSAtUGF0aCAiQzpcU2hhcmVzIg=="),

        # s10: archive creation on file server (.zip by shell = 1.0)
        file_ev("s10", fs, user, p_ps_fs, "powershell.exe", t + 300,
                "create", archive),

        # s11: exfiltration - powershell connects externally from server
        #      (external-from-shell = 2.0, passes SEED_THRESHOLD)
        net("s11", fs, user, p_ps_fs, "powershell.exe", t + 350,
            dst=exfil_ip, dport=443),
    ]

    links = [
        ("s0", "s1", "authenticated"),   # RDP logon -> shell
        ("s1", "s2", "spawned"),          # cmd -> rundll32
        ("s2", "s3", "created"),          # rundll32 -> lsass dump
        ("s1", "s4", "spawned"),          # cmd -> powershell
        ("s4", "s5", "resolved"),         # powershell -> DNS
        ("s4", "s6", "connected"),        # powershell -> C2
        ("s4", "s7", "spawned"),          # powershell -> schtasks
        ("s4", "s8", "authenticated"),    # powershell -> lateral logon
        ("s8", "s9", "authenticated"),    # logon -> remote shell
        ("s9", "s10", "created"),         # powershell -> archive
        ("s9", "s11", "connected"),       # powershell -> exfil
    ]
    return specs, links
