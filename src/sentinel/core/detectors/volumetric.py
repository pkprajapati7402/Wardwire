"""Volumetric flood detector (OWASP API4: Unrestricted Resource Consumption)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from sentinel.core.config import settings
from sentinel.core.detectors.base import BaseDetector, DetectionResult


class VolumetricFloodDetector(BaseDetector):
    def __init__(self, z_threshold: Optional[float] = None) -> None:
        self.z_threshold = z_threshold or settings.VOLUMETRIC_Z_THRESHOLD

    def detect(self, features: Dict[str, Any], **kwargs: Any) -> Optional[DetectionResult]:
        """
        Detects request volume floods across global or route-specific windows.
        Features passed from window slice: request_rate, baseline_mean, baseline_mad, z_score.
        """
        rate = float(features.get("request_rate", 0.0))
        baseline_mean = float(features.get("baseline_mean", 10.0))
        baseline_mad = float(features.get("baseline_mad", 3.0))
        z_score = float(features.get("z_score", 0.0))
        route = features.get("route", "global")

        if z_score < self.z_threshold:
            return None

        # Scale score between 0.5 (at threshold) and 1.0 (at threshold + 5.0)
        score = min(1.0, 0.5 + (z_score - self.z_threshold) / 10.0)
        confidence = min(1.0, 0.6 + (z_score / 15.0))
        dev_mult = round(rate / max(0.1, baseline_mean), 1)

        return DetectionResult(
            detector_name="VolumetricFloodDetector",
            category="volumetric_flood",
            owasp="API4:2023",
            score=round(score, 3),
            confidence=round(confidence, 2),
            entities={"target_route": route, "scope": "global" if route == "global" else "route"},
            observed={"request_rate_rps": round(rate, 1), "robust_z_score": round(z_score, 2)},
            baseline={"expected_rate_rps": round(baseline_mean, 1), "mad": round(baseline_mad, 2)},
            deviation={"rate_multiplier": f"{dev_mult}x", "z_score": f"+{round(z_score, 1)}σ"},
            top_features=[
                {"name": "request_rate", "value": round(rate, 1), "baseline": round(baseline_mean, 1), "weight": 0.6},
                {"name": "robust_z_score", "value": round(z_score, 2), "baseline": 0.0, "weight": 0.4},
            ],
        )

