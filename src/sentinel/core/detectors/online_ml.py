"""Online Machine Learning Anomaly Scorer using River HalfSpaceTrees.

Provides online, continuous incremental anomaly scoring on multidimensional entity
feature vectors without retraining batches.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

try:
    from river import anomaly
    RIVER_AVAILABLE = True
except ImportError:
    RIVER_AVAILABLE = False

from sentinel.core.detectors.base import BaseDetector, DetectionResult


class OnlineMLAnomalyDetector(BaseDetector):
    def __init__(self, score_threshold: float = 0.70) -> None:
        self.score_threshold = score_threshold
        self.model: Any = None
        if RIVER_AVAILABLE:
            # HalfSpaceTrees is an online, streaming isolation-tree variant
            self.model = anomaly.HalfSpaceTrees(
                n_trees=25,
                height=6,
                window_size=150,
                seed=42,
            )

    def _vectorize(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Convert feature dict to float mapping for River."""
        return {
            "req_rate": float(features.get("request_rate", 0.0)),
            "err_rate": float(features.get("error_rate", 0.0)),
            "r401": float(features.get("ratio_401", 0.0)),
            "r403": float(features.get("ratio_403", 0.0)),
            "r404": float(features.get("ratio_404", 0.0)),
            "distinct_routes": float(features.get("distinct_routes_count", 0)),
            "distinct_objs": float(features.get("distinct_objects_count", 0)),
            "cv": float(features.get("timing_cv", 1.0)),
            "seq_score": float(features.get("sequential_id_score", 0.0)),
        }

    def detect(self, features: Dict[str, Any], **kwargs: Any) -> Optional[DetectionResult]:
        if not RIVER_AVAILABLE or self.model is None:
            return None

        vec = self._vectorize(features)
        entity_key = features.get("entity_key", "entity")

        # River HST anomaly score is in [0, 1]
        raw_score = float(self.model.score_one(vec))
        # Update model stream
        self.model.learn_one(vec)

        if raw_score < self.score_threshold:
            return None

        confidence = min(0.90, 0.50 + (raw_score * 0.4))

        return DetectionResult(
            detector_name="OnlineMLAnomalyDetector",
            category="online_ml_anomaly",
            owasp="API4:2023",
            score=round(raw_score, 3),
            confidence=round(confidence, 2),
            entities={"entity_key": entity_key},
            observed={"anomaly_score": round(raw_score, 3), "features_evaluated": vec},
            baseline={"anomaly_score": 0.25},
            deviation={"ml_isolation_score": f"{round(raw_score, 2)} / 1.0"},
            top_features=[
                {"name": "half_space_tree_score", "value": round(raw_score, 2), "baseline": 0.25, "weight": 1.0}
            ],
        )

