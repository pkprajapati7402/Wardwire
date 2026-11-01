"""Evidence generation and deterministic natural-language explanations."""

from __future__ import annotations

from typing import Any, Dict, List

from sentinel.core.schemas import ActionRecommendation, EvidenceObject, WhyNotBenignCheck


def generate_template_narrative(
    category: str,
    owasp: str,
    risk: int,
    observed: Dict[str, Any],
    baseline: Dict[str, Any],
    deviation: Dict[str, Any],
    entities: Dict[str, Any],
) -> str:
    """Produces explainable deterministic text explaining the alert and reasoning."""
    if category == "credential_stuffing":
        fails = observed.get("failed_logins", 0)
        accounts = observed.get("distinct_accounts", 1)
        ips = observed.get("distinct_ips", 1)
        return (
            f"Detected distributed credential stuffing campaign targeting {accounts} distinct accounts "
            f"across {ips} client endpoints with {fails} failed attempts. "
            f"Pattern exhibits low-and-slow velocity designed to bypass traditional per-IP rate limits. "
            f"Mapped to OWASP {owasp} (Broken Authentication)."
        )
    elif category == "bola_enumeration":
        objs = observed.get("distinct_objects_accessed", 0)
        seq = round(float(observed.get("sequential_id_score", 0.0)) * 100, 1)
        return (
            f"Detected BOLA / Object-ID enumeration activity. Single principal iterated across {objs} distinct objects "
            f"with a {seq}% sequential monotonic step progression. "
            f"Mapped to OWASP {owasp} (Broken Object Level Authorization)."
        )
    elif category == "volumetric_flood":
        rate = observed.get("request_rate_rps", 0)
        mult = deviation.get("rate_multiplier", "N/A")
        return (
            f"Detected volumetric flood anomaly. Ingestion rate surged to {rate} rps ({mult} baseline). "
            f"Benign look-alike discriminator evaluated endpoint-mix and authentication consistency. "
            f"Mapped to OWASP {owasp} (Unrestricted Resource Consumption)."
        )
    elif category == "scraping":
        res = observed.get("distinct_resources_harvested", 0)
        cv = observed.get("timing_coefficient_of_variation", 0)
        return (
            f"Detected automated catalog scraping. Client harvested {res} distinct catalog resources "
            f"with low inter-arrival variance (CV = {cv}), indicating headless loop iteration. "
            f"Mapped to OWASP {owasp} (Unrestricted Access to Sensitive Business Flows)."
        )
    elif category == "password_spraying":
        accs = observed.get("distinct_accounts_targeted", 0)
        return (
            f"Detected horizontal password spraying campaign across {accs} user accounts. "
            f"Characterized by minimal attempts per target account to avoid account lockout triggers. "
            f"Mapped to OWASP {owasp} (Broken Authentication)."
        )
    elif category == "probing":
        errors = observed.get("404_not_found_count", 0)
        return (
            f"Detected reconnaissance scanning and endpoint probing resulting in {errors} 404/400 errors. "
            f"Mapped to OWASP {owasp} (Improper Inventory Management)."
        )
    elif category == "data_exfiltration":
        total_kb = round(observed.get("total_payload_bytes", 0) / 1024, 1)
        return (
            f"Detected bulk data exfiltration anomaly totaling {total_kb} KB. "
            f"Payload volume significantly deviates from expected single-resource responses. "
            f"Mapped to OWASP {owasp} (Broken Object Property Level Authorization)."
        )
    else:
        return (
            f"Anomalous API activity detected in category {category} ({owasp}) "
            f"with fused risk score {risk}/100."
        )


def build_evidence_object(
    alert_id: str,
    category: str,
    owasp: str,
    risk: int,
    confidence: float,
    window: str,
    observed: Dict[str, Any],
    baseline: Dict[str, Any],
    deviation: Dict[str, Any],
    top_features: List[Dict[str, Any]],
    why_not_benign: List[WhyNotBenignCheck],
    entities: Dict[str, Any],
    sample_requests: List[Dict[str, Any]],
    recommendations: List[ActionRecommendation],
) -> EvidenceObject:
    """Assembles complete structured evidence object."""
    explanation = generate_template_narrative(
        category=category,
        owasp=owasp,
        risk=risk,
        observed=observed,
        baseline=baseline,
        deviation=deviation,
        entities=entities,
    )

    return EvidenceObject(
        alert_id=alert_id,
        category=category,
        owasp=owasp,
        risk=risk,
        confidence=confidence,
        window=window,
        observed=observed,
        baseline=baseline,
        deviation=deviation,
        top_features=top_features,
        why_not_benign=why_not_benign,
        entities=entities,
        sample_requests=sample_requests,
        recommendations=recommendations,
        explanation=explanation,
        llm_narrative=None,
    )

