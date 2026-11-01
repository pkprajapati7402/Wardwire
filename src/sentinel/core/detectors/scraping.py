"""Scraping & Business Flow Abuse Detector (OWASP API6: Unrestricted Access to Sensitive Business Flows).

Detects automated catalog scraping and business flow abuse via broad resource coverage
and unnatural robotic timing regularity (low coefficient of variation).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from sentinel.core.config import settings
from sentinel.core.detectors.base import BaseDetector, DetectionResult


class ScrapingDetector(BaseDetector):
    def __init__(
        self,
        min_resources: Optional[int] = None,
        cv_threshold: Optional[float] = None,
    ) -> None:
        self.min_resources = min_resources or settings.SCRAPING_MIN_RESOURCES
        self.cv_threshold = cv_threshold or settings.SCRAPING_CV_THRESHOLD

    def detect(self, features: Dict[str, Any], **kwargs: Any) -> Optional[DetectionResult]:
        distinct_objs = int(features.get("distinct_objects_count", 0))
        cv = float(features.get("timing_cv", 1.0))
        total_reqs = int(features.get("total_requests", 0))
        entity_key = features.get("entity_key", "scraper")

        if distinct_objs < self.min_resources or total_reqs < 20:
            return None

        # Low CV (std_dev / mean < 0.25) signifies robotic loop pacing
        is_robotic_timing = cv <= self.cv_threshold

        if not is_robotic_timing and distinct_objs < (self.min_resources * 2):
            return None

        score = 0.65 + min(0.30, (distinct_objs - self.min_resources) / 50.0)
        if is_robotic_timing:
            score = min(1.0, score + 0.10)

        confidence = 0.80 if is_robotic_timing else 0.65

        return DetectionResult(
            detector_name="ScrapingDetector",
            category="scraping",
            owasp="API6:2023",
            score=round(score, 3),
            confidence=round(confidence, 2),
            entities={"entity_key": entity_key, "resources_scraped": distinct_objs},
            observed={
                "distinct_resources_harvested": distinct_objs,
                "timing_coefficient_of_variation": round(cv, 3),
                "total_requests": total_reqs,
            },
            baseline={"expected_resources": 4, "expected_timing_cv": 0.75},
            deviation={
                "resource_coverage_multiplier": f"{round(distinct_objs / 4.0, 1)}x",
                "timing_regularity": "unnatural_robotic" if is_robotic_timing else "elevated",
            },
            top_features=[
                {"name": "distinct_resources", "value": distinct_objs, "baseline": 4, "weight": 0.55},
                {"name": "timing_cv", "value": round(cv, 2), "baseline": 0.75, "weight": 0.45},
            ],
        )

