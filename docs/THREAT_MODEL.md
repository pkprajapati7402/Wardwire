# Wardwire — Threat Model (STRIDE Methodology)

This document formalizes the threat model for the Wardwire API abuse detection platform, following STRIDE principles with explicit mitigations and automated test references.

---

## 1. STRIDE Analysis Matrix

| Threat Category | Threat Description | Severity | Mitigation Architecture | Verification Test |
|---|---|---|---|---|
| **Spoofing** | Attacker spoofs source IP or rotates User-Agents to evade per-IP tracking | High | Cross-entity aggregation: tracks target accounts, header hash fingerprints, and /24 subnet blocks rather than single IPs | `tests/test_detectors.py::test_credential_stuffing_detector` |
| **Tampering** | Attacker slowly ramps volume to poison dynamic baselines (A9 attack) | High | Robust statistics (median/MAD), slow frozen reference baseline, drift alarm, and anomaly exclusion during bursts | `tests/test_baselines.py::test_drift_and_poisoning_resistance` |
| **Repudiation** | Operator or analyst actions lack accountability | Medium | Tamper-evident SQLite `audit_log` records every configuration change, threshold adjustment, and scenario launch | `tests/test_api_integration.py` |
| **Information Disclosure** | Leakage of raw client IP addresses or user PII in databases, logs, or API responses | Critical | HMAC-SHA256 pseudonymisation with secret salt at the ingestion boundary; raw IPs discarded in memory | `tests/test_pseudonym.py`, `tests/test_security.py::test_privacy_no_raw_ips_in_db` |
| **Denial of Service** | High-cardinality IP flooding designed to exhaust worker RAM (memory explosion DoS) | High | Hard cardinality caps (`CARDINALITY_MAX_KEYS=10000`) with LRU eviction and memory bounds | `tests/test_security.py::test_cardinality_flood_memory_bounds` |
| **Elevation of Privilege** | Attacker manipulates simulator to target external infrastructure or corporate systems | Critical | Strict destination allow-listing (`SIM_ALLOWED_TARGETS`); non-local hosts rejected with `SimulatorSecurityError` | `tests/test_security.py::test_hard_safety_target_allowlist` |
| **Indirect Injection** | Adversarial prompt injection embedded in User-Agents, paths, or headers targeting LLM | High | LLM inputs restricted strictly to numeric/categorical evidence JSON; raw untrusted strings are stripped | `tests/test_security.py::test_prompt_injection_safety` |

---

## 2. Supply-Chain & Dependency Hardening

1. **Vulnerability Auditing:** Continuous dependency scanning via `pip-audit` and `npm audit` integrated into CI.
2. **SAST Analysis:** Bandit AST inspection gating security pull requests (`bandit -r src/ -ll`).
3. **Software Bill of Materials (SBOM):** Standardized CycloneDX JSON SBOM generated during build (`reports/sbom.json`).
4. **Secret Scanning:** Gitleaks automated repository scanning preventing credential or API key leakage.

