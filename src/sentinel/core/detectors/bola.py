"""BOLA / ID-Enumeration Detector (OWASP API1: Broken Object Level Authorization).

Detects sequential / monotonic ID enumeration and wide resource footprint probing
where a single principal iterates over object identifiers.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from sentinel.core.config import settings
from sentinel.core.detectors.base import BaseDetector, DetectionResult


class BolaEnumerationDetector(BaseDetector):
    def __init__(
        self,
        monotonic_ratio_threshold: Optional[float] = None,
        min_objects: Optional[int] = None,
    ) -> None:
        self.monotonic_ratio_threshold = monotonic_ratio_threshold or settings.BOLA_MONOTONIC_RATIO
        self.min_objects = min_objects or settings.BOLA_MIN_OBJECTS

    def detect(self, features: Dict[str, Any], **kwargs: Any) -> Optional[DetectionResult]:
        distinct_objs = int(features.get("distinct_objects_count", 0))
        seq_score = float(features.get("sequential_id_score", 0.0))
        r403 = float(features.get("ratio_403", 0.0))
        r404 = float(features.get("ratio_404", 0.0))
        entity_key = features.get("entity_key", "principal")

        # Must touch multiple objects to qualify
        if distinct_objs < self.min_objects:
            return None

        # Two primary enumeration paths:
        # 1. Clear monotonic progression (e.g., id+1, id+2)
        # 2. Wide object sweep with authorization denial / not-found mix
        is_sequential = seq_score >= self.monotonic_ratio_threshold
        is_wide_probing = distinct_objs >= 15 and (r403 > 0.15 or r404 > 0.20)

        if not (is_sequential or is_wide_probing):
            return None

        # Calculate severity and confidence
        score = 0.65
        if is_sequential:
            score += min(0.30, seq_score * 0.30)
        if is_wide_probing:
            score = min(1.0, score + 0.15)

        confidence = min(0.96, 0.70 + (seq_score * 0.25))

        return DetectionResult(
            detector_name="BolaEnumerationDetector",
            category="bola_enumeration",
            owasp="API1:2023",
            score=round(score, 3),
            confidence=round(confidence, 2),
            entities={"principal": entity_key, "distinct_objects": distinct_objs},
            observed={
                "distinct_objects_accessed": distinct_objs,
                "sequential_id_score": round(seq_score, 3),
                "ratio_403_forbidden": round(r403, 3),
                "ratio_404_not_found": round(r404, 3),
            },
            baseline={
                "expected_distinct_objects": 2,
                "expected_sequential_score": 0.05,
            },
            deviation={
                "object_access_expansion": f"{round(distinct_objs / 2.0, 1)}x",
                "monotonic_step_ratio": f"{round(seq_score * 100, 1)}%",
            },
            top_features=[
                {"name": "distinct_objects", "value": distinct_objs, "baseline": 2, "weight": 0.45},
                {"name": "sequential_score", "value": round(seq_score, 2), "baseline": 0.05, "weight": 0.40},
                {"name": "ratio_403_404", "value": round(r403 + r404, 2), "baseline": 0.02, "weight": 0.15},
            ],
        )

