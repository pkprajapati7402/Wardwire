# Wardwire — Demonstration Scripts

This document provides scripts for the 2-minute video submission and the 5-minute live judging demonstration.

---

## 1. Two-Minute Submission Video Script (Round 1)

| Time | Visual / Screen Action | Voiceover Audio Script |
|---|---|---|
| **0:00–0:12** | Title slide: Wardwire logo, tagline, OWASP API Security Top 10 badges | *"Most API abuse detectors simply flag volume spikes. Wardwire tells real attacks apart from busy days, catches distributed abuse that per-IP limits miss, explains every alert with verifiable evidence, and provides safe shadow-mode responses."* |
| **0:12–0:28** | Terminal running `make demo`; browser opens to `http://localhost:3000` showing live dashboard | *"With one command, Wardwire spins up locally with zero paid API keys. We are looking at live telemetry from ShopAPI, our demo e-commerce application instrumented with Wardwire's drop-in ASGI middleware."* |
| **0:28–0:58** | Navigate to Attack Lab; trigger **A1 Distributed Credential Stuffing** at Stealth 2; alert pops up on dashboard | *"Let's test an attack. Traditional rate limiters look at requests per IP, meaning attacks rotated across hundreds of IPs go completely undetected. In the Attack Lab, we fire scenario A1 at stealth level 2. Within seconds, Wardwire aggregates across user accounts and subnets, and fires an alert."* |
| **0:58–1:18** | Open alert drawer: highlight Evidence, **"Why Not Benign?"** panel, Action ladder | *"Opening the alert, we see complete evidence: 83x failure elevation, OWASP API2 mapping, and our 'Why Not Benign' panel proving this is an attack rather than a user surge. Notice our action ladder recommends safe friction challenges in shadow mode with zero legitimate user impact."* |
| **1:18–1:35** | Trigger **B1 Flash-Sale Surge** (10x volume); dashboard stays quiet / logs benign | *"Now the true test: busy days. We launch scenario B1—a 10x flash-sale surge. Notice the threat gauge remains calm. Our Jensen-Shannon divergence and auth-success checks recognize normal catalog exploration and suppress false alarms."* |
| **1:35–1:48** | Trigger **A3 BOLA / Object Enumeration**; sequential ID score displays in drawer | *"Wardwire also detects API-specific logic flaws, such as BOLA enumeration under OWASP API1, spotting sequential step patterns across order identifiers."* |
| **1:48–2:00** | Evaluation page showing Precision/Recall table, Evasion curve, and GitHub CI badges | *"Every metric is measured honestly on chronological splits with zero data leakage. Clean, explainable, and privacy-preserving by design. That's Wardwire."* |

---

## 2. Five-Minute Live Demonstration Flow (Round 2)

1. **0:00–0:40 | Architecture & Problem Statement:**
   - Display system architecture diagram (`docs/ARCHITECTURE.md`).
   - Explain why per-IP rate limits and unsupervised Isolation Forests fail in production.

2. **0:40–1:40 | Distributed Credential Stuffing (A1) Live:**
   - Launch A1 at Stealth 2 from the Attack Lab.
   - Show telemetry reaction within 10 seconds.
   - Open alert drawer, walk through evidence, blast radius, and shadow mitigation counters.

3. **1:40–2:30 | Hard Negatives (B1 Flash Sale & B2 Retry Storm):**
   - Launch B1 Flash Sale (10x volume) and B2 Retry Storm.
   - Show how the Benign Discriminator checks (Jensen-Shannon divergence, auth ratio, preceding 5xx retries) suppress false positives.

4. **2:30–3:15 | BOLA Object Enumeration (A3):**
   - Launch A3 BOLA enumeration.
   - Highlight sequential-ID monotonic step analysis ($92\%$ score) and OWASP API1 tagging.

5. **3:15–4:00 | Stealth Slider & Evasion Curves:**
   - Increase stealth slider to Stealth 3 and 4.
   - Discuss measured evasion curve honestly and reference `docs/LIMITATIONS.md`.

6. **4:00–4:30 | Prompt-Injection & Security Posture:**
   - Demonstrate that adversarial prompt injection payloads embedded in HTTP headers do not alter explanation outputs or risk scores.
   - Show HMAC pseudonymisation (zero raw IPs stored).

7. **4:30–5:00 | Technical Q&A:**
   - Refer to Technical Q&A cheat sheet (`Appendix A` in build spec).
