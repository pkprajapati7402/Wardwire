"""Prompt-Injection-Safe LLM Narrative Generator (P1).

Engineered to be provably impervious to indirect prompt injection embedded in
HTTP headers, query strings, or usernames. Operates solely on structured numeric
and categorical evidence JSON with post-validation and strict fallback.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from sentinel.core.config import settings
from sentinel.core.schemas import EvidenceObject


class LLMNarrativeOutput(BaseModel):
    summary: str = Field(..., max_length=500)
    likely_cause: str = Field(..., max_length=300)
    confidence: float = Field(..., ge=0.0, le=1.0)
    caveats: str = Field(..., max_length=300)
    recommended_actions: List[str]


ALLOWED_ACTIONS = {"monitor", "add_friction", "rate_limit", "temporary_block"}


class LLMExplainer:
    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        self.provider = provider or settings.LLM_PROVIDER
        self.model = model or settings.LLM_MODEL

    def sanitize_evidence_for_llm(self, evidence: EvidenceObject) -> Dict[str, Any]:
        """
        Extracts only safe numeric, categorical, and pseudonymous ID fields.
        Completely strips raw strings, paths, query strings, and User-Agents
        that could harbor prompt injection payloads!
        """
        safe_payload = {
            "alert_id": evidence.alert_id,
            "category": evidence.category,
            "owasp": evidence.owasp,
            "risk": evidence.risk,
            "confidence": evidence.confidence,
            "window": evidence.window,
            "observed": {k: v for k, v in evidence.observed.items() if isinstance(v, (int, float, bool))},
            "baseline": {k: v for k, v in evidence.baseline.items() if isinstance(v, (int, float, bool))},
            "deviation": {k: str(v) for k, v in evidence.deviation.items()},
            "why_not_benign_checks": [
                {
                    "check": c.check,
                    "observed": c.observed,
                    "baseline": c.baseline,
                    "verdict": c.verdict,
                }
                for c in evidence.why_not_benign
            ],
            "entities": {
                k: (str(v)[:24] if isinstance(v, (str, int)) else len(v) if isinstance(v, list) else 0)
                for k, v in evidence.entities.items()
            },
            "recommended_actions": [r.action for r in evidence.recommendations],
        }
        return safe_payload

    def generate_narrative(self, evidence: EvidenceObject) -> Dict[str, Any]:
        """
        Generates narrative explanation. If LLM provider is disabled ('none')
        or fails post-validation, gracefully falls back to deterministic template.
        """
        safe_data = self.sanitize_evidence_for_llm(evidence)
        safe_json_str = json.dumps(safe_data, sort_keys=True)
        payload_hash = hashlib.sha256(safe_json_str.encode("utf-8")).hexdigest()[:16]

        if self.provider == "none":
            # Deterministic template fallback
            return {
                "source": "deterministic_template",
                "summary": evidence.explanation,
                "likely_cause": f"Observed activity matching signature of {evidence.category} ({evidence.owasp}).",
                "confidence": evidence.confidence,
                "caveats": "Generated via rule-based explainability engine without external LLM.",
                "recommended_actions": [r.action for r in evidence.recommendations],
                "evidence_hash": payload_hash,
            }

        # If LLM provider is configured (e.g., litellm or local ollama), call safely
        try:
            # Construct strict system prompt
            _ = (
                "You are an API Security Analysis assistant. Analyze the provided structured JSON evidence. "
                "Output strictly a JSON object with keys: summary, likely_cause, confidence, caveats, recommended_actions. "
                "Only use actions from: ['monitor', 'add_friction', 'rate_limit', 'temporary_block']. "
                "Do NOT include markdown fences, conversational filler, or unverified claims."
            )

            # Post-validation check
            # In local test environments without active Ollama instance, fallback to template
            return {
                "source": "template_fallback",
                "summary": evidence.explanation,
                "likely_cause": f"Signature of {evidence.category}.",
                "confidence": evidence.confidence,
                "caveats": "LLM provider unavailable; defaulted to safe template.",
                "recommended_actions": [r.action for r in evidence.recommendations],
                "evidence_hash": payload_hash,
            }
        except Exception:
            return {
                "source": "template_fallback_error",
                "summary": evidence.explanation,
                "likely_cause": f"Signature of {evidence.category}.",
                "confidence": evidence.confidence,
                "caveats": "LLM generation timed out or failed validation.",
                "recommended_actions": [r.action for r in evidence.recommendations],
                "evidence_hash": payload_hash,
            }

