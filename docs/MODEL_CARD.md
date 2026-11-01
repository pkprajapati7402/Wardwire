# Wardwire — Detection Engine Model Card

## 1. Model Details

- **Model Name:** Wardwire Hybrid Ensemble & Benign Discriminator
- **Architecture:** Hybrid ensemble combining robust statistics (EWMA + MAD with diurnal curves), behavioural heuristics, online machine learning (River `HalfSpaceTrees`), and a multi-hypothesis benign look-alike discriminator.
- **Task:** Real-time API abuse detection, incident correlation, and mitigation recommendation mapped to the OWASP API Security Top 10 (2023).

---

## 2. Detectors & Algorithms

| Detector | Underlying Technique | OWASP API (2023) | Primary Input Signals | Failure Modes |
|---|---|---|---|---|
| **Volumetric Flood** | Robust Z-Score over EWMA + MAD baseline | **API4** | Global & route request rates, diurnal curve multiplier | Extreme sudden flash crowds exceeding 50x baseline |
| **Credential Stuffing** | Cross-Entity Multi-Signal Aggregation | **API2** | Target account failure rates, distinct accounts per fingerprint, subnet diversity | Ultra-slow distributed brute-force (< 1 attempt/day/account) |
| **Password Spraying** | Failure Distribution Uniformity | **API2** | Distinct accounts, attempts-per-account ratio, failure proportion | Extremely dispersed spraying across months |
| **BOLA Enumeration** | Monotonic Step & Cardinality Analysis | **API1** | Monotonic step ratio, object cardinality, 403/404 mix | Random non-sequential UUID exploration |
| **Scraping** | Inter-Arrival CV + Resource Coverage | **API6** | Coefficient of variation (CV = std/mean), unique resource count | Sophisticated bots applying human-like Poisson jitter |
| **Probing & Fuzzing** | Error Ratio + Undocumented Route Matching | **API9 / API8** | 404/400 ratios, OpenAPI specification match flag | Low-volume reconnaissance interleaved with normal requests |
| **Data Exfiltration** | Payload Volume Z-Score | **API3 / API4** | Mean response bytes, total exfiltrated byte volume | Multi-day trickle exfiltration |
| **Online ML Scorer** | River `HalfSpaceTrees` (Streaming Isolation) | **Supporting** | Multi-dimensional entity feature vector | Initial cold start before tree window warms up |

---

## 3. Benign Look-Alike Discriminator

When volume spikes occur, Wardwire avoids false alarms by evaluating 6 explicit hypotheses:
1. **Endpoint-Mix Divergence (Jensen-Shannon):** Legitimate flash sales retain balanced catalog distributions ($JS < 0.38$); attacks hyper-focus ($JS > 0.60$).
2. **Auth Success Ratio:** Flash sales maintain high authentication success ($>85\%$); credential attacks fail ($<10\%$).
3. **Source & Subnet Diversity:** Legitimate crowds exhibit wide IP-to-subnet spread ratios; botnets cluster.
4. **Session Consistency:** Human traffic exhibits browse $\to$ cart $\to$ checkout progression.
5. **Error-Driven Retries:** Volume correlating with preceding backend 5xx spikes is attributed to client retries.
6. **Known Stable Automation:** Whitelisted partner API credentials with historic low error rates.

---

## 4. Evaluation Performance & Held-Out Results

*Results measured on chronological test split (`reports/eval.json`, seed 42):*
- **Precision:** **94.1%**
- **Recall:** **91.4%**
- **F1 Score:** **0.927**
- **False Alarms per Day:** **0.0** (0 false alerts across flash-sale B1 and retry-storm B2 scenarios)
- **Time to Detect (p50):** **12.0 s**

