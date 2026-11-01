"""Calibrated fusion, risk scoring, alert budget enforcement, and lifecycle deduplication."""

from __future__ import annotations

import collections
import datetime
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from sentinel.core.config import settings
from sentinel.core.detectors.base import DetectionResult


class FusionEngine:
    """
    Fuses multiple detector signals into a calibrated 0-100 risk score,
    applies benign likelihood suppression, enforces alert budget ceilings,
    and deduplicates alerts across time buckets.
    """

    def __init__(
        self,
        suppression_k: Optional[float] = None,
        hourly_budget: Optional[int] = None,
    ) -> None:
        self.suppression_k = suppression_k or settings.BENIGN_SUPPRESSION_K
        self.hourly_budget = hourly_budget or settings.ALERT_BUDGET_HOURLY

        # Deduplication memory: dedupe_key -> active_alert_id
        self.active_alert_keys: Dict[str, str] = {}
        # Hourly budget tracker: (hour_timestamp) -> opened_count
        self.hourly_alert_counts: Dict[int, int] = collections.defaultdict(int)
        self.suppressed_alerts_count: int = 0

    def compute_fused_risk(
        self,
        detection_results: List[DetectionResult],
        benign_likelihood: float,
    ) -> Tuple[int, float]:
        """
        Combines detector scores using weighted noisy-OR:
          P(Abuse) = 1 - PROD(1 - w_i * s_i)
        Suppressed by (1 - benign_likelihood * k).
        Returns:
          (risk_score_0_to_100, confidence_0_to_1)
        """
        if not detection_results:
            return 0, 0.0

        # Weights per detector category
        weights = {
            "credential_stuffing": 0.90,
            "bola_enumeration": 0.85,
            "volumetric_flood": 0.70,
            "scraping": 0.65,
            "password_spraying": 0.75,
            "probing": 0.60,
            "data_exfiltration": 0.80,
            "online_ml_anomaly": 0.50,
        }

        prob_not_abuse = 1.0
        confidences = []

        for res in detection_results:
            w = weights.get(res.category, 0.60)
            score = max(0.0, min(1.0, res.score))
            prob_not_abuse *= 1.0 - (w * score)
            confidences.append(res.confidence)

        raw_abuse_prob = 1.0 - prob_not_abuse

        # Apply benign suppression
        suppression_factor = max(0.0, 1.0 - (benign_likelihood * self.suppression_k))
        calibrated_prob = raw_abuse_prob * suppression_factor

        risk_score = int(round(calibrated_prob * 100))
        mean_confidence = float(sum(confidences) / len(confidences)) if confidences else 0.5

        return risk_score, round(mean_confidence, 2)

    def generate_dedupe_key(self, category: str, entities: Dict[str, Any], time_bucket_10m: int) -> str:
        """Constructs stable dedupe key (category, entity-set hash, time bucket)."""
        entity_repr = ":".join(f"{k}={v}" for k, v in sorted(entities.items()))
        ent_hash = hashlib.sha256(entity_repr.encode("utf-8")).hexdigest()[:12]
        return f"{category}:{ent_hash}:{time_bucket_10m}"

    def can_open_alert(self, risk_score: int) -> bool:
        """Enforces hourly alert budget to prevent alert fatigue."""
        now_hour = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) // 3600
        count = self.hourly_alert_counts[now_hour]

        if count >= self.hourly_budget:
            # Under budget exhaustion, only critical severity alerts (risk >= 85) are allowed
            if risk_score < 85:
                self.suppressed_alerts_count += 1
                return False

        self.hourly_alert_counts[now_hour] += 1
        return True

