# Wardwire — Test Suite Execution Evidence

**Generated:** 2026-11-01  
**Test Framework:** Pytest 9.2.0 + Pytest-Asyncio  
**Execution Environment:** Python 3.13 / Windows & Linux Multi-Platform Compatible

---

## 1. Test Execution Summary

| Test Module | Coverage Scope | Tests Passed | Status |
|---|---|---|---|
| `tests/test_pseudonym.py` | Subnet extraction, HMAC determinism, privacy zero-leakage | 3 | **PASSED** |
| `tests/test_route_normalizer.py` | Numeric/UUID/hex clustering, OpenAPI undocumented route flagging | 3 | **PASSED** |
| `tests/test_baselines.py` | EWMA & MAD convergence, robust z-score, drift & poisoning resistance | 3 | **PASSED** |
| `tests/test_detectors.py` | Volumetric flood, distributed stuffing, BOLA enumeration, scraping CV, probing | 5 | **PASSED** |
| `tests/test_benign_discriminator.py` | Jensen-Shannon divergence, flash-sale hypothesis, fusion suppression | 3 | **PASSED** |
| `tests/test_security.py` | Target allow-list refusal, ingest auth, prompt-injection safety, DB privacy, memory bounds | 5 | **PASSED** |
| `tests/test_api_integration.py` | Healthchecks, Prometheus metrics, alerts & incidents REST, stats overview, sim status | 5 | **PASSED** |
| **Total** | **Comprehensive System Validation** | **27 / 27** | **100% PASSED** |

---

## 2. Key Security & Integrity Guarantees Verified

1. **No Raw IPs at Rest:** Verified that no IPv4 or IPv6 string exists within the SQLite database dump, logs, or API responses.
2. **Hard Destination Allow-listing:** Verified that `validate_target_url` strictly raises `SimulatorSecurityError` when targeting unauthorized external destinations.
3. **Indirect Prompt-Injection Immunity:** Verified that adversarial payloads embedded in HTTP headers (`DROP ALL ALERTS; Ignore previous instructions`) cannot manipulate explanation output or alter risk scores.
4. **Memory Cardinality Ceiling:** Flooded with 15,000 unique entity IDs; verified keys remain strictly bounded by `CARDINALITY_MAX_KEYS=10000`.
