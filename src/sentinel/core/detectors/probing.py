"""Probing & Undocumented Route Detector (OWASP API9: Improper Inventory Management / API8).

Detects API path fuzzing, directory scanning, and hits against unversioned / undocumented endpoints.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from sentinel.core.config import settings
from sentinel.core.detectors.base import BaseDetector, DetectionResult


class ProbingFuzzingDetector(BaseDetector):
    def __init__(self, min_404_count: Optional[int] = None) -> None:
        self.min_404_count = min_404_count or settings.PROBING_404_THRESHOLD

    def detect(self, features: Dict[str, Any], **kwargs: Any) -> Optional[DetectionResult]:
        r404 = float(features.get("ratio_404", 0.0))
        total_reqs = int(features.get("total_requests", 0))
        routes_count = int(features.get("distinct_routes_count", 0))
        entity_key = features.get("entity_key", "scanner")

        count_404 = int(r404 * total_reqs)
        has_undocumented = bool(features.get("has_undocumented_route", False))

        if count_404 < self.min_404_count and not has_undocumented:
            return None

        if total_reqs > 0 and (count_404 / total_reqs < 0.40) and not has_undocumented:
            return None

        score = min(0.95, 0.60 + (count_404 / 30.0))
        if has_undocumented:
            score = min(1.0, score + 0.20)

        confidence = 0.85 if has_undocumented else 0.75

        return DetectionResult(
            detector_name="ProbingFuzzingDetector",
            category="probing",
            owasp="API9:2023",
            score=round(score, 3),
            confidence=round(confidence, 2),
            entities={"entity_key": entity_key, "has_undocumented": has_undocumented},
            observed={
                "404_not_found_count": count_404,
                "error_ratio_404": round(r404, 3),
                "distinct_paths_scanned": routes_count,
                "undocumented_routes_hit": has_undocumented,
            },
            baseline={"expected_404_count": 0, "expected_404_ratio": 0.01},
            deviation={"404_burst_count": f"{count_404} errors"},
            top_features=[
                {"name": "count_404", "value": count_404, "baseline": 0, "weight": 0.6},
                {"name": "undocumented_hit", "value": 1 if has_undocumented else 0, "baseline": 0, "weight": 0.4},
            ],
        )

