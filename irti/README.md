# IRTI — Incident Reconstruction under Telemetry Incompleteness

A small, honest, reproducible study platform: synthetic event logs with a known
attack chain, a blind rule-based reconstruction engine, and a measurement of how
missing evidence degrades reconstruction accuracy and — separately — the incident
response decision derived from it.

Everything is synthetic, stdlib-only, and seeded. No real telemetry, malware, or
exploit code is involved. Only plotting needs a third-party package.

## The idea in one paragraph

A generator produces a time-sorted text log of ~500 events (process, network,
DNS, file, logon) for a `WS`/`SRV` environment. Most events are benign routine
activity; 9–12 events form a causal attack chain whose ground truth is known.
The reconstruction engine reads only the log, heuristically grows a candidate
chain, and maps it to a 3-tier decision (`isolate` / `investigate` / `monitor`).
The degradation engine deletes evidence sources or random records; we then
measure link-level precision/recall/F1 and decision correctness against ground
truth.

The headline is not the accuracy curve — it is the **gap between the two**: the
evidence level where the reconstruction still looks mostly right but the
recommended response is already wrong.

## Layout

```
genlog.py       generator CLI -> runs/<vector>/<seed>/events.log + gt/
vectors/        attack chain templates; auto-registered, add a file to add one
benign.py       routine user/server activity + deliberate look-alikes
specs.py        shared event-spec constructors
reconstruct.py  blind rule-based reconstruction (never sees gt/)
degrade.py      source removal / random record loss
score.py        link P/R/F1 + decision correctness
run.py          seed x condition sweep -> results/results.csv
plots.py        figures from the CSV -> results/figures/ (needs matplotlib)
selftest.py     7 high-value checks (determinism, ground truth, recovery, ...)
```

## Quickstart

```bash
# core loop (stdlib only)
python3 genlog.py --seed 0 --n 500 --vector phishing_powershell
python3 reconstruct.py runs/phishing_powershell/0/events.log
python3 selftest.py

# full sweep: source removal + random record loss
python3 run.py --seeds 0 1 2 3 4 --n 500 --random-losses 10 25 50 75 90

# figures (one-time venv setup; core scripts remain stdlib-only)
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python plots.py
```

`genlog.py --list-vectors` shows the available attack templates.

## Attack vectors

| vector | chain |
|---|---|
| `phishing_powershell` | attachment delivered by Outlook → WinWord opens it → encoded PowerShell → C2 → discovery → zip collection → lateral network logon to file server → exfil |
| `exploit_webshell` | inbound exploit against w3wp → cmd → `shell.aspx` webroot drop → PowerShell → scheduled-task persistence → C2 → DNS-tunnel exfil |

## Degradation conditions

`full`, `no_process`, `no_network` (network+dns), `no_dns`, `no_file`,
`no_logon`, plus `random_<pct>` (e.g. `random_25`). Degraded logs keep original
event ids so predictions stay matchable to ground truth.

## Metrics

- **Link P/R/F1** over the attack chain. The engine reports one incident (its
  best-connected component); a link is matched as an unordered event-id pair.
- **Decision correctness**: `isolate` requires reconstructable execution
  lineage, external communications, and an impact indicator (webroot/archive/
  scheduled task/multi-DNS/exfil). Weaker evidence downgrades the decision.
- **Confidence**: 0.40·lineage + 0.35·external + 0.25·impact.

## Figures (`results/figures/`)

- `resilience_source_removal.png` — F1 and decision correctness per removed
  source (bars, mean ± std), with the pre-declared bars (F1 ≥ 0.8, decision ≥ 0.9)
- `resilience_random_loss.png` — the primary completeness curve: scores vs % of
  records randomly removed, with the interpolated decision threshold
- `source_importance.png` — accuracy drop caused by removing each source
- `confidence_calibration.png` — engine confidence vs actual F1 (all runs)

## Current v0 results (5 seeds, 500 events)

Source removal:

| vector | condition | F1 | decision |
|---|---|---|---|
| phishing_powershell | full | 1.000 | 1.00 |
| phishing_powershell | no_dns | 0.957 | 1.00 |
| phishing_powershell | no_file | 0.800 | 0.00 |
| phishing_powershell | no_logon | 0.800 | 1.00 |
| phishing_powershell | no_network | 0.857 | 0.00 |
| phishing_powershell | no_process | 0.000 | 0.00 |
| exploit_webshell | full | 1.000 | 1.00 |
| exploit_webshell | no_dns | 0.800 | 1.00 |
| exploit_webshell | no_file | 0.875 | 1.00 |
| exploit_webshell | no_logon | 1.000 | 1.00 |
| exploit_webshell | no_network | 0.492 | 0.00 |
| exploit_webshell | no_process | 0.000 | 0.00 |

Random record loss (mean over seeds): F1 falls to 0.63/0.71 at 25% removed and
0.26/0.39 at 50%. Interpolated decision threshold: **18% removed for webshell,
14% for phishing** — at or just before the F1 ≥ 0.8 crossing (19%/15%).

Observations to defend (not yet claims): process evidence is the keystone for
this log model (its removal severs every chain link); structured source removal
is far more survivable than random loss at equal record counts, because the
attack chain is sparse; the decision can fail while F1 still clears its bar
(`no_file` phishing, `no_network` both); source importance is vector-dependent
(webshell does not use logon at all); and engine confidence is overconfident —
runs at confidence 1.0 span F1 0.35–1.0.

## Adding an attack vector

Create `vectors/my_vector.py` with `NAME`, `DESCRIPTION`,
`CORRECT_DECISION`, and `build(ctx) -> (specs, links)`. It is auto-registered.
`ctx` provides `rng`, `user`, `ws`, `fs`, `web`, `attack_ips`,
`attack_domains`, `t0`, and `next_pid`.

## Scope notes

- All probabilities and thresholds are hand-set, not calibrated.
- The event-pair link metric makes process events the natural hubs; this is
  honest for this log model but is a modeling choice, not a universal result.
- Two degradation types (source removal, uniform random loss); no timestamp
  jitter or conflicting evidence yet.
- Small samples (5 seeds); report intervals, avoid significance claims.
