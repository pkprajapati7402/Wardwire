"""Response policy engine, action ladder, blast radius estimation, and shadow mode."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from sentinel.core.config import settings
from sentinel.core.schemas import ActionRecommendation


class PolicyEngine:
    """
    Evaluates detected risk and entity profile to formulate safe, graduated response
    recommendations along the action ladder, computes estimated blast radius on legitimate users,
    and manages shadow-mode vs simulated-enforcement counters.
    """

    def __init__(self, mode: Optional[str] = None) -> None:
        self.mode: str = mode or settings.OPERATING_MODE
        # Shadow mode counters
        self.attacker_requests_mitigated: int = 0
        self.legit_requests_impacted: int = 0
        self.total_attacker_requests: int = 0
        self.total_legit_requests: int = 0

    def recommend_actions(
        self,
        category: str,
        risk: int,
        entities: Dict[str, Any],
        observed: Dict[str, Any],
    ) -> List[ActionRecommendation]:
        """
        Graduated Action Ladder:
          monitor (risk < 40)
          add_friction (40 <= risk < 70) -> step-up MFA, CAPTCHA
          rate_limit (70 <= risk < 85) -> per-entity / subnet token bucket
          temporary_block (risk >= 85) -> 15-minute temporary 429 cooling
        """
        recs: List[ActionRecommendation] = []
        target_entity = (
            entities.get("target_entity")
            or entities.get("principal")
            or entities.get("target_route")
            or "entity"
        )

        # Blast radius calculation: estimated fraction of legitimate traffic sharing this entity
        # e.g., blocking an entire subnet has higher blast radius than a specific account or fingerprint
        if "subnet" in target_entity or "net_" in str(target_entity):
            est_blast_pct = 1.8
        elif "fp_" in str(target_entity):
            est_blast_pct = 0.4
        elif "ip_" in str(target_entity):
            est_blast_pct = 0.2
        else:
            est_blast_pct = 0.05

        if risk < 40:
            recs.append(
                ActionRecommendation(
                    action="monitor",
                    target=str(target_entity),
                    est_legit_impact_pct=0.0,
                    reason="Low confidence anomaly. Enhanced passive telemetry logging recommended.",
                )
            )
        elif risk < 70:
            recs.append(
                ActionRecommendation(
                    action="add_friction",
                    target=str(target_entity),
                    est_legit_impact_pct=est_blast_pct,
                    reason="Present step-up authentication challenge (CAPTCHA / OTP verification).",
                )
            )
        elif risk < 85:
            recs.append(
                ActionRecommendation(
                    action="rate_limit",
                    target=str(target_entity),
                    est_legit_impact_pct=est_blast_pct,
                    reason="Enforce strict 10 req/min token bucket limit at gateway/middleware.",
                )
            )
        else:
            recs.append(
                ActionRecommendation(
                    action="temporary_block",
                    target=str(target_entity),
                    est_legit_impact_pct=est_blast_pct,
                    reason="Active severe attack. Temporary 15-minute 429 block recommended in shadow policy.",
                )
            )

        return recs

    def record_shadow_outcome(self, is_attacker: bool, would_block: bool) -> None:
        """Track shadow-mode mitigation efficacy metrics."""
        if is_attacker:
            self.total_attacker_requests += 1
            if would_block:
                self.attacker_requests_mitigated += 1
        else:
            self.total_legit_requests += 1
            if would_block:
                self.legit_requests_impacted += 1

    def get_shadow_stats(self) -> Dict[str, float]:
        """Returns percentage of mitigated attackers vs impacted legitimate traffic."""
        mitigated_pct = (
            (self.attacker_requests_mitigated / max(1, self.total_attacker_requests)) * 100.0
            if self.total_attacker_requests > 0
            else 0.0
        )
        impacted_pct = (
            (self.legit_requests_impacted / max(1, self.total_legit_requests)) * 100.0
            if self.total_legit_requests > 0
            else 0.0
        )
        return {
            "attacker_mitigated_pct": round(mitigated_pct, 1),
            "legit_impacted_pct": round(impacted_pct, 2),
        }

