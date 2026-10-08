# Incident Reconstruction under Telemetry Incompleteness (IRTI)
### DFIR Prototype & Forensic Resilience Framework

A reproducible study platform designed to answer a fundamental practitioner question:
> **How much evidence is enough? At what level of missing evidence does forensic incident reconstruction degrade, and at what threshold does the downstream incident response decision fail?**

This framework couples a synthetic generator of enterprise telemetry with known causal ground truth, a generator-blind rule-based reconstruction engine, and a degradation engine that systematically induces telemetry loss (whole-source drops, combined drops, and uniform random record loss).

---

## 🎯 Key Findings & The "Resilience Gap"

1. **The Accuracy–Decision Gap (RQ3 / H3):**
   - The downstream IR response decision (`isolate`) degrades and flips to incorrect at **~14% random record loss for phishing** and **~18% for webshell attacks**.
   - These decision failure points occur **at or just before** the raw graph reconstruction accuracy ($F_1$) crosses below its pre-declared acceptability bar ($F_1 \ge 0.80$).
   - **Takeaway:** An investigator inspecting a reconstructed graph might judge it mostly accurate ($F_1 \approx 0.80$), yet the containment recommendation derived from it is already flawed.

2. **Source Importance Hierarchy (RQ2 / H2):**
   - **Process evidence is the keystone:** Removing process logs drops incident $F_1$ to `0.000` across all vectors because process events serve as structural hubs.
   - **Retention priority:** $\text{Process} > \text{Network} > \text{File} > \text{Logon} > \text{DNS}$.
   - **DNS is the most survivable:** Even with all DNS records omitted, the engine maintains $F_1 = 0.80 - 0.96$ and 100% decision correctness.

3. **Structured vs. Random Loss:**
   - Removing 60–80% of records via whole-source removal is often far more survivable than 25–50% uniform random record loss. The attack chain is sparse; random loss rapidly severs critical single points of failure.

---

## 📁 Repository Layout

```text
├── DFIR_Prototype_Implementation_Plan.pdf  # 3-week prototype engineering plan
├── DFIR_Research_Plan.pdf                  # Core research questions, hypotheses & metrics
├── Makefile                                # Top-level automation (test, demo, sweep, reproduce)
├── README.md                               # Project overview and quickstart (this file)
├── report/
│   └── report.md                           # Short technical research report
└── irti/                                   # Core implementation package
    ├── benign.py                           # Enterprise background noise & look-alike distractor generator
    ├── degrade.py                          # Evidence degradation engine (source drops + random loss)
    ├── demo.py                             # 5-minute interactive end-to-end CLI walkthrough
    ├── genlog.py                           # Event log generator & ground truth writer
    ├── gt/                                 # Ground-truth incident definitions (JSON)
    ├── plots.py                            # Matplotlib figure generation (4 study figures)
    ├── reconstruct.py                      # Blind rule-based reconstruction & IR decision engine
    ├── reproduce.py                        # One-command full reproduction runner
    ├── requirements.txt                    # Minimal dependencies (matplotlib)
    ├── results/
    │   ├── figures/                        # Generated publication plots (.png)
    │   └── results.csv                     # 165+ row multi-seed experiment sweep dataset
    ├── run.py                              # Parameterized experiment matrix runner
    ├── score.py                            # Link P/R/F1, stage recall, and decision evaluator
    ├── selftest.py                         # 9 high-value regression & leak-detection tests
    ├── specs.py                            # Common telemetry schema & constructor helpers
    └── vectors/                            # Auto-registered attack chain templates
        ├── credential_dumping.py           # Family 3: RDP -> lsass dump -> lateral -> exfil
        ├── exploit_webshell.py             # Family 2: w3wp exploit -> webshell -> C2 -> DNS tunnel
        └── phishing_powershell.py          # Family 1: Phishing -> WinWord -> PowerShell -> C2 -> exfil
```

---

## ⚡ Quickstart

### 1. Requirements
The core pipeline (generation, degradation, reconstruction, scoring, self-tests) uses the **Python standard library only** (Python 3.10+). Generating visualization figures requires `matplotlib`:

```bash
cd irti
pip install -r requirements.txt
```

### 2. Run the 5-Minute Interactive Demo
See one incident end-to-end (generation $\rightarrow$ ground truth $\rightarrow$ full reconstruction $\rightarrow$ degradation):

```bash
python irti/demo.py --vector phishing_powershell --seed 0
```
Or for another attack family:
```bash
python irti/demo.py --vector exploit_webshell --seed 1
```

### 3. Run Self-Tests
Verify ground truth integrity, determinism, full-evidence recovery, and strict generator-blindness:

```bash
python irti/selftest.py -v
```

### 4. One-Command Full Reproduction
Run all tests, execute the complete seed $\times$ condition matrix across all 3 attack families, and re-plot all figures:

```bash
python irti/reproduce.py
```
*(Or via Makefile: `make reproduce`)*

---

## 🔬 Attack Families

| Vector | Attack Chain |
|---|---|
| `phishing_powershell` | Phishing email attachment $\rightarrow$ WinWord $\rightarrow$ encoded PowerShell $\rightarrow$ C2 $\rightarrow$ discovery $\rightarrow$ zip collection $\rightarrow$ lateral network logon $\rightarrow$ exfiltration |
| `exploit_webshell` | External exploit against `w3wp.exe` $\rightarrow$ `cmd.exe` $\rightarrow$ `shell.aspx` drop $\rightarrow$ PowerShell $\rightarrow$ `schtasks` persistence $\rightarrow$ C2 $\rightarrow$ DNS tunneling exfil |
| `credential_dumping` | External RDP brute force $\rightarrow$ `rundll32.exe` LSASS dump (`comsvcs.dll`) $\rightarrow$ PowerShell C2 $\rightarrow$ `schtasks` $\rightarrow$ lateral logon to file server $\rightarrow$ archive $\rightarrow$ HTTPS exfil |

---

## 📈 Evaluation & Figures

All generated figures are saved under [`irti/results/figures/`](file:///C:/Users/riyav/.gemini/antigravity/scratch/resilienceframework/irti/results/figures/):

- **`resilience_source_removal.png`**: $F_1$ score and decision correctness across missing log sources.
- **`resilience_random_loss.png`**: Primary completeness curve illustrating the resilience threshold gap.
- **`source_importance.png`**: Accuracy degradation caused by removing each telemetry source.
- **`confidence_calibration.png`**: Reconstructed confidence score vs. empirical $F_1$.

For detailed analysis, methodologies, threats to validity, and discussion, consult the [**Technical Report (`report/report.md`)**](file:///C:/Users/riyav/.gemini/antigravity/scratch/resilienceframework/report/report.md).
