"""Distributed Credential Stuffing Detector (OWASP API2: Broken Authentication).

Catches attacks distributed across hundreds of IPs by aggregating at the
account, subnet, and fingerprint level rather than relying on per-IP thresholds.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from sentinel.core.config import settings
from sentinel.core.detectors.base import BaseDetector, DetectionResult


class CredentialStuffingDetector(BaseDetector):
    def __init__(
        self,
        min_failures: Optional[int] = None,
        fail_ratio: Optional[float] = None,
    ) -> None:
        self.min_failures = min_failures or settings.CREDENTIAL_STUFFING_MIN_FAILURES
        self.fail_ratio = fail_ratio or settings.CREDENTIAL_STUFFING_FAIL_RATIO

    def detect(self, features: Dict[str, Any], **kwargs: Any) -> Optional[DetectionResult]:
        """
        Evaluates entity features (e.g. for fingerprint, subnet, or aggregated auth route).
        Signals:
          - High total login failures
          - High failure ratio (failed / (failed + success))
          - High distinct accounts targeted per entity (fp/subnet)
          - Multiple IPs per target
        """
        failed = int(features.get("login_failed", 0))
        success = int(features.get("login_success", 0))
        distinct_accounts = int(features.get("distinct_accounts_count", 0))
        distinct_ips = int(features.get("distinct_ips_count", 0))
        distinct_subnets = int(features.get("distinct_subnets_count", 0))
        entity_key = features.get("entity_key", "auth_stream")

        total_auth = failed + success
        if total_auth == 0 or failed < self.min_failures:
            return None

        actual_fail_ratio = failed / total_auth
        if actual_fail_ratio < self.fail_ratio:
            return None

        # Cross-entity distribution signals
        is_distributed = distinct_ips >= 5 or distinct_subnets >= 3 or distinct_accounts >= 5

        # Score calculation
        base_score = 0.6 + min(0.3, (failed - self.min_failures) / 100.0)
        if is_distributed:
            base_score = min(1.0, base_score + 0.1)

        confidence = min(0.98, 0.65 + min(0.3, actual_fail_ratio * 0.35))
        dev_mult = round(failed / max(1, success), 1) if success > 0 else failed

        return DetectionResult(
            detector_name="CredentialStuffingDetector",
            category="credential_stuffing",
            owasp="API2:2023",
            score=round(base_score, 3),
            confidence=round(confidence, 2),
            entities={
                "target_entity": entity_key,
                "distinct_accounts": distinct_accounts,
                "distinct_ips": distinct_ips,
                "distinct_subnets": distinct_subnets,
                "is_distributed": is_distributed,
            },
            observed={
                "failed_logins": failed,
                "success_logins": success,
                "fail_ratio": round(actual_fail_ratio, 3),
                "distinct_accounts": distinct_accounts,
                "distinct_ips": distinct_ips,
            },
            baseline={
                "expected_fail_ratio": 0.08,
                "expected_distinct_accounts": 1,
            },
            deviation={
                "failed_to_success_ratio": f"{dev_mult}:1",
                "fail_rate_elevation": f"{round(actual_fail_ratio / 0.08, 1)}x",
            },
            top_features=[
                {"name": "failed_logins", "value": failed, "baseline": 2, "weight": 0.4},
                {"name": "fail_ratio", "value": round(actual_fail_ratio, 2), "baseline": 0.08, "weight": 0.35},
                {"name": "distinct_accounts", "value": distinct_accounts, "baseline": 1, "weight": 0.25},
            ],
        )

