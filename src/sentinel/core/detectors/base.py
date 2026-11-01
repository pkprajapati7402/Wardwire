"""Base detector interface."""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class DetectionResult(BaseModel):
    detector_name: str
    category: str
    owasp: str
    score: float  # [0.0, 1.0]
    confidence: float  # [0.0, 1.0]
    entities: Dict[str, Any]
    observed: Dict[str, Any]
    baseline: Dict[str, Any]
    deviation: Dict[str, Any]
    top_features: List[Dict[str, Any]] = []


class BaseDetector(abc.ABC):
    """Abstract base class for all Wardwire abuse detectors."""

    @abc.abstractmethod
    def detect(self, features: Dict[str, Any], **kwargs: Any) -> Optional[DetectionResult]:
        """
        Evaluate feature vector and return DetectionResult if anomalous.
        Returns None if activity is within normal operational parameters.
        """
        pass

