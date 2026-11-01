# Security Policy

## Reporting Security Vulnerabilities

The Wardwire team takes system security and developer privacy seriously.
If you discover a security vulnerability in Wardwire, please report it privately:

- **Email:** `security@wardwire.local` or through private GitHub Security Advisories.
- **Response Target:** Initial response within 24 hours.

Please do not disclose security issues publicly until a fix has been verified and released.

---

## Security Architecture & Guarantees

1. **Privacy by Design:**
   Raw client IP addresses are immediately pseudonymized with secret-salted HMAC-SHA256 (`ip_id` and `net_id`) on the ingestion boundary. Raw IPs are never written to disk, SQLite, Redis streams, application logs, or API responses.

2. **Prompt-Injection Safety:**
   The optional LLM narrative layer is strictly isolated. It never ingests untrusted user strings (User-Agents, query strings, paths, or headers). Input is restricted to numerical and categorical evidence JSON with post-validation.

3. **Simulator Safety Rails:**
   The Attack Lab traffic generator enforces strict destination allow-listing (`SIM_ALLOWED_TARGETS`). Any attempt to direct synthetic traffic outside local localhost/docker-compose boundaries is hard-refused with `SimulatorSecurityError`.

4. **Self-Protection & Cardinality Bounds:**
   The sliding window feature extractor enforces strict cardinality ceilings (`CARDINALITY_MAX_KEYS=10000`) with LRU evictions to prevent denial-of-service via high-cardinality IP flooding attacks.
