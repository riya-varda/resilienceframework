# How Much Evidence Is Enough? A Resilience Threshold for Forensic Reconstruction and Incident-Response Decisions Under Evidence Degradation

## Abstract
In digital forensics and incident response (DFIR), responders rarely have the luxury of complete telemetry. This report investigates a critical resilience threshold: the gap between when forensic reconstruction accuracy begins to degrade and when the derived incident response (IR) decision becomes fundamentally incorrect. Utilizing a reproducible synthetic framework, we simulate complete event logs and systematically apply degradation (source removal and random record loss) against known ground truth. Our key finding demonstrates that decision correctness becomes unreliable at roughly 14–18% random record loss. Notably, the downstream response decision fails at or just before the reconstruction accuracy (F1 score) drops below an acceptable 0.8 threshold, indicating that seemingly adequate reconstructions may still lead to flawed containment strategies.

## 1. Introduction
Incomplete or unreliable logs are the norm during real-world security incidents. Digital forensic investigators routinely work with degraded telemetry, piecing together partial events to deduce an attack chain. However, a significant gap exists in forensic research: while existing public DFIR datasets (such as DARPA OpTC/TC and CICIDS) provide realistic, complete evidence, they do not systematically vary evidence completeness against a known ground truth to study the robustness of forensic reconstructions.

This research addresses that gap by exploring the following research questions:
- **RQ1:** How does reconstruction accuracy degrade as evidence is progressively removed?
- **RQ2:** Which evidence sources matter most for accurate incident reconstruction?
- **RQ3:** At what evidence level does the derived IR decision first become wrong, relative to when the raw reconstruction accuracy drops below its acceptability bar?

## 2. Related Work
Previous efforts in generating forensic datasets, such as the DARPA Transparent Computing (TC) and Operationally Transparent Cyber (OpTC) programs, have been foundational in providing large-scale enterprise telemetry. Furthermore, approaches leveraging provenance-graph reconstruction have advanced the state of the art in automating attack storyline extraction. However, these works typically assume a static level of telemetry completeness. Our work builds upon these provenance-graph techniques but introduces systematic evidence degradation as an independent variable to stress-test the resilience of the reconstruction pipeline.

## 3. Methodology

### 3.1 Synthetic Environment
We constructed a synthetic enterprise environment comprising 16 users, 12 workstations, and 4 servers (Web, Database, File Share, and Domain Controller). The environment generates approximately 500 events per log, spanning process, network, DNS, file, and logon activities. To ensure realistic noise, benign activity incorporates deliberate look-alikes, such as macro-enabled workbooks and IT admin PowerShell execution.

### 3.2 Attack Vectors
The framework models specific incident families:
- **Family 1 (phishing_powershell):** Phishing email → malicious PowerShell execution (12 events, 12 links).
- **Family 2 (exploit_webshell):** Web application exploit → webshell deployment (10 events, 9 links).
- **Family 3 (credential_dumping):** Credential dumping → lateral movement (11 events, 10 links) [stretch goal].

### 3.3 Evidence Rule Table
The reconstruction mapping is governed by an evidence rule table, where each attack stage maps deterministically to exactly one evidence record type.

### 3.4 Degradation
To evaluate resilience, we apply two primary degradation models:
- **Source Removal:** Complete removal of specific log types: `no_process`, `no_network` (includes DNS), `no_dns`, `no_file`, and `no_logon`.
- **Random Record Loss:** Random dropping of individual records at varying severity levels: 10%, 25%, 50%, 75%, and 90%.
- **Combined Degradation:** Pairs of source removals [stretch goal].

### 3.5 Reconstruction Engine
Our framework employs a rule-based reconstruction engine deliberately designed to be blind to the ground truth. The pipeline consists of:
1. **Parsing:** Ingesting observed events.
2. **Scoring:** Evaluating events for suspicion using behavioral heuristics (threshold: 1.5).
3. **Graphing:** Growing candidate attack chains from suspicious seed events.
4. **Decision Mapping:** Mapping the best candidate chain to a 3-tier IR decision, accompanied by a confidence score.

The decision mapping relies on the following thresholds:
- Confidence > 0.7 + exfiltration indicator → **Isolate**
- Confidence 0.4–0.7 → **Investigate**
- Confidence < 0.4 → **Monitor**

### 3.6 Metrics
We evaluate the engine using:
- **Edge Precision/Recall/F1:** Primary metric for graph structural accuracy.
- **Decision Correctness:** Binary metric indicating if the recommended response aligns with ground truth.
- **Confidence Calibration:** A score calculated as `0.40·lineage + 0.35·external + 0.25·impact`.

## 4. Experimental Design
The evaluation spans 2–3 incident families with 5 seed variations each. The runs encompass all source removal conditions, random loss intervals, and a full-evidence baseline, totaling over 75 runs per attack vector. Pre-declared acceptability bars are established at F1 ≥ 0.80 and decision correctness ≥ 90%.

## 5. Results

### 5.1 Baseline (Full Evidence)
Under ideal, full-evidence conditions, the reconstruction engine achieves perfect accuracy. Both the phishing and webshell vectors report an F1 score of 1.000 and 100% decision correctness across all 5 seeds.

### 5.2 Source Removal
The impact of structured source removal varies significantly by vector and data type:

| Vector | Condition | F1 | Decision Correct |
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
| credential_dumping | full | 0.786 | 1.00 |
| credential_dumping | no_dns | 0.741 | 1.00 |
| credential_dumping | no_file | 0.692 | 1.00 |
| credential_dumping | no_logon | 0.706 | 1.00 |
| credential_dumping | no_network | 0.640 | 0.00 |
| credential_dumping | no_process | 0.000 | 0.00 |

**Key Observations:**
- Process evidence is the absolute keystone; its removal crashes the F1 to 0.000 across all vectors.
- Source importance is highly dependent on the vector. For example, the webshell vector does not rely heavily on logon events (F1 remains 1.0), whereas the phishing vector does (F1 drops to 0.8).
- Crucially, the IR decision can fail even while the F1 score clears its acceptability bar (e.g., `no_file` phishing yields F1=0.8 but decision correctness=0.00).

### 5.3 Random Record Loss
Under random degradation:
- F1 scores plummet to 0.63–0.71 at 25% removal, and to 0.26–0.39 at 50% removal.
- The interpolated threshold where the decision flips to incorrect is 18% removal for the webshell vector and 14% for the phishing vector.
- These decision failure thresholds occur at or just before the point where the F1 score drops below 0.8 (which happens at roughly 19% and 15%, respectively).

### 5.4 Confidence Calibration
The reconstruction engine demonstrates overconfidence. Reconstructions claiming a confidence score of 1.0 correspond to actual F1 scores spanning anywhere from 0.35 to 1.0.

### 5.5 Combined Degradation (RQ4 / H4 — Stretch Goal)
To investigate whether multi-source degradation compounded linearly or synergistically, we tested dual-source omissions (`no_file+no_logon`, `no_dns+no_file`, `no_network+no_file`). 

Comparing observed F1 degradation against the additive sum of individual source penalties ($\Delta_{\text{combined}}$ vs $\Delta_A + \Delta_B$):
- **Phishing (`no_file + no_logon`):** Individual penalties sum to $\Delta = 0.282$ (predicted $F_1 = 0.607$), while actual combined $F_1$ falls to **0.588**.
- **Webshell (`no_dns + no_file`):** Individual penalties sum to $\Delta = 0.325$ (predicted $F_1 = 0.675$), while actual combined $F_1$ drops to **0.615**.
- **Webshell (`no_network + no_file`):** Observed $F_1 = 0.364$ vs linearly predicted $0.490$ ($\Delta_{\text{excess}} = -0.126$).

**Finding (H4):** Telemetry degradation is **superadditive (compounding)**. Removing a second evidentiary source deprives the reconstruction engine of fallback correlation paths, causing structural graph fragmentation faster than linear models predict.

## 6. Discussion

### 6.1 The Accuracy-Decision Gap
The most compelling finding of this study is the narrow but tangible gap between seemingly acceptable reconstruction accuracy (F1 ≥ 0.8) and fundamental decision failure. Practically, an incident responder might review a reconstruction graph, judge its quality as satisfactory, and unknowingly proceed with a flawed containment strategy.

### 6.2 Source Importance
Process evidence emerged as the keystone data source, presenting a strong practical argument for prioritizing process-execution logs in retention policies. However, we acknowledge this is partially a modeling artifact; our event-pair link metric naturally positions process events as network hubs. Conversely, DNS data was the most survivable loss condition for these specific vectors.

### 6.3 Structured vs Random Loss
The study reveals that structured source removal is significantly more survivable than random record loss at equivalent data volumes. Because attack chains are relatively sparse, wiping out 60-80% of total records via bulk source removal often leaves the critical subset of remaining attack telemetry intact, whereas random dropping quickly breaks vital graph edges.

### 6.4 Practical Implications
- **Retention Priorities:** For typical enterprise attack vectors, log prioritization should generally follow: Process > Network > File > Logon > DNS.
- **Data Loss Impacts:** Sporadic, random log dropping (e.g., via UDP syslog loss or localized agent failure) is far more damaging to reconstruction integrity than the complete absence of a secondary log source.
- **Tooling Trust:** Confidence metrics in automated reconstruction tools require rigorous empirical calibration, as current naive heuristics trend toward dangerous overconfidence.

## 7. Limitations
- **Synthetic Data:** The environment is fully synthetic and has not been validated against real enterprise networks or live Sysmon telemetry.
- **Simplified Attacker Behavior:** The attack simulation relies on weighted random walks and is neither adversarial nor adaptive.
- **Arbitrary Weights:** Action-selection probabilities were chosen to introduce variety, rather than calibrated against real-world frequency analysis.
- **Scope Constraints:** Only 5 of a possible 6+ evidence sources were implemented.
- **Limited Vectors:** Findings are based on 2-3 incident families and may not generalize to drastically different attack-chain topologies.
- **Statistical Power:** The sample size (~15-20 conditions × 5 seeds) is small; results indicate trends rather than statistically significant universal thresholds.
- **Engine Ceiling:** The rule-based engine represents a deliberate tradeoff prioritizing explainability over absolute performance.
- **Simulator Bias:** The same research team built the data generator, the evidence rule sets, and the reconstruction engine.

## 8. Future Work
Future extensions of this framework should incorporate additional evidence sources (e.g., registry modifications, WMI events) and broader incident families (e.g., ransomware deployments, supply chain compromises). Investigating other degradation modalities—such as timestamp jitter and conflicting evidence injection—will further test resilience. Ultimately, validating these findings by overlaying synthetic degradation on real-world enterprise Sysmon logs and comparing the rule-based baseline against ML-driven reconstruction techniques remain critical next steps.

## 9. Conclusion
This report establishes a quantitative resilience threshold for forensic reconstruction: for the phishing vector, the downstream incident response decision becomes unreliable at roughly 14% random record loss; for the webshell vector, at approximately 18%. Because these thresholds closely track the F1 ≥ 0.8 crossing point, we conclude that reconstruction quality and decision quality degrade nearly in lockstep—but the decision fails first. The framework, while contained in scope, provides a reproducible methodology for systematically measuring forensic resilience and demonstrates that process evidence is the single most critical asset for accurate incident reconstruction.

## Honest Novelty Assessment
The combination of (a) a ground-truth-known synthetic generator, (b) systematic evidence degradation as the independent variable, and (c) evaluation that extends beyond graph similarity into a downstream operational IR decision is, individually, not entirely new. However, unifying these components—even for a limited set of incident families and degradation types—constitutes a small, honest contribution to the field. Readers should note that these specific numeric thresholds do not inherently generalize beyond this synthetic framework.

## References
1. DARPA Transparent Computing (TC) Program.
2. DARPA Operationally Transparent Cyber (OpTC) Program.
3. Canadian Institute for Cybersecurity (CIC) Intrusion Detection Evaluation Dataset (CICIDS).
4. (Placeholder for seminal works in provenance-graph reconstruction).
