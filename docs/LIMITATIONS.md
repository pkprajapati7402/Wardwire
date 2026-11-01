# Wardwire — Known Limitations & Operational Boundaries

In adherence to scientific honesty and engineering credibility, this document details measured limitations, edge cases, and known constraints of Wardwire.

---

## 1. Degradation at Stealth Level 4 (Low-Velocity Blending)

Adversaries operating at **Stealth Level 4** intentionally interleave attacks into normal user traffic at low velocities ($< 1$ request every few minutes per residential proxy IP), mimicking browser headers and timing variance.

- **Measured Impact:** As documented in `reports/EVAL.md`, detection recall drops from **95%** at Stealth 2 to **70%** at Stealth 4 within short 1-minute detection windows.
- **Mitigation:** Wardwire maintains longer correlation windows (5m and 1h) to aggregate cross-entity signals over extended observation intervals, though detection delay is naturally increased.

---

## 2. Cold-Start Initialization Window

- On a completely fresh deployment without historical baselines or replay data, Wardwire initializes detectors with sensible priors (`mean=10.0 rps`, `mad=3.0`).
- During the first **30 to 60 seconds**, confidence multipliers are dampened ($k=0.5$) to avoid false alarms until the EWMA baseline absorbs typical traffic cadence.

---

## 3. Synthetic-to-Real Domain Gap

- All training, validation, and demo traffic is synthetically generated using Markov session models and realistic timing distributions (`sentinel.sim`).
- While `sentinel.sdk` is engineered as a standard production ASGI middleware capable of handling real production HTTP workloads, performance numbers reported in `reports/EVAL.md` reflect synthetic evaluation datasets.

---

## 4. Random UUID vs Monotonic Object Enumeration

- The BOLA detector (`BolaEnumerationDetector`) excels at discovering monotonic, sequential, or range-based object ID enumeration ($+1, +2$).
- If an application uses cryptographically random version-4 UUIDs or non-sequential hash identifiers, the sequential step metric is inapplicable; detection then relies on high unique object cardinality and authorization denial ($403/404$) ratios.

