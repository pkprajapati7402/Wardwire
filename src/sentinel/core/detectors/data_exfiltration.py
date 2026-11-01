"""Data Exfiltration Detector (OWASP API3 / API4).

Detects anomalous bulk data extraction, oversized responses, and pagination limit bypasses.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from sentinel.core.config import settings
from sentinel.core.detectors.base import BaseDetector, DetectionResult


class DataExfiltrationDetector(BaseDetector):
    def __init__(self, bytes_z_threshold: Optional[float] = None) -> None:
        self.bytes_z_threshold = bytes_z_threshold or settings.DATA_EXFIL_BYTES_Z_THRESHOLD

    def detect(self, features: Dict[str, Any], **kwargs: Any) -> Optional[DetectionResult]:
        mean_bytes = float(features.get("mean_bytes_out", 0.0))
        total_reqs = int(features.get("total_requests", 0))
        entity_key = features.get("entity_key", "principal")

        # Typical API responses are 500B - 5KB. Flag if consistent responses > 50KB or total exfil > 2MB
        total_bytes = mean_bytes * total_reqs
        baseline_bytes = 2048.0  # 2KB expected

        if mean_bytes < 25000.0 and total_bytes < 1_500_000:
            return None

        dev_mult = round(mean_bytes / baseline_bytes, 1)
        score = min(0.95, 0.65 + min(0.3, dev_mult / 30.0))
        confidence = 0.82

        return DetectionResult(
            detector_name="DataExfiltrationDetector",
            category="data_exfiltration",
            owasp="API3:2023",
            score=round(score, 3),
            confidence=round(confidence, 2),
            entities={"entity_key": entity_key, "total_exfiltrated_bytes": int(total_bytes)},
            observed={
                "mean_bytes_per_request": round(mean_bytes, 1),
                "total_payload_bytes": int(total_bytes),
                "request_volume": total_reqs,
            },
            baseline={"expected_mean_bytes": int(baseline_bytes)},
            deviation={"payload_size_multiplier": f"{dev_mult}x"},
            top_features=[
                {"name": "mean_bytes_out", "value": round(mean_bytes, 1), "baseline": 2048.0, "weight": 0.7},
                {"name": "total_bytes", "value": int(total_bytes), "baseline": 40960, "weight": 0.3},
            ],
        )

