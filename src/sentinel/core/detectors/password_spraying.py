"""Password Spraying Detector (OWASP API2: Broken Authentication).

Detects horizontal attacks testing one or few passwords across many distinct accounts.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from sentinel.core.detectors.base import BaseDetector, DetectionResult


class PasswordSprayingDetector(BaseDetector):
    def __init__(self, min_distinct_accounts: int = 8, max_attempts_per_account: float = 3.5) -> None:
        self.min_distinct_accounts = min_distinct_accounts
        self.max_attempts_per_account = max_attempts_per_account

    def detect(self, features: Dict[str, Any], **kwargs: Any) -> Optional[DetectionResult]:
        distinct_accounts = int(features.get("distinct_accounts_count", 0))
        failed = int(features.get("login_failed", 0))
        success = int(features.get("login_success", 0))
        entity_key = features.get("entity_key", "auth_stream")

        if distinct_accounts < self.min_distinct_accounts or failed == 0:
            return None

        attempts_per_account = failed / max(1, distinct_accounts)
        if attempts_per_account > self.max_attempts_per_account:
            # More likely stuffing than horizontal spraying
            return None

        # Spraying signature: many distinct accounts, very few attempts each, mostly failures
        total_auth = failed + success
        fail_ratio = failed / max(1, total_auth)
        if fail_ratio < 0.70:
            return None

        score = min(0.95, 0.60 + (distinct_accounts / 40.0))
        confidence = min(0.90, 0.60 + (fail_ratio * 0.3))

        return DetectionResult(
            detector_name="PasswordSprayingDetector",
            category="password_spraying",
            owasp="API2:2023",
            score=round(score, 3),
            confidence=round(confidence, 2),
            entities={"entity_key": entity_key, "distinct_accounts": distinct_accounts},
            observed={
                "distinct_accounts_targeted": distinct_accounts,
                "failed_logins": failed,
                "avg_attempts_per_account": round(attempts_per_account, 2),
                "fail_ratio": round(fail_ratio, 2),
            },
            baseline={"expected_distinct_accounts": 1, "expected_fail_ratio": 0.08},
            deviation={"distinct_accounts_multiplier": f"{distinct_accounts}x"},
            top_features=[
                {"name": "distinct_accounts", "value": distinct_accounts, "baseline": 1, "weight": 0.5},
                {"name": "attempts_per_account", "value": round(attempts_per_account, 2), "baseline": 1.0, "weight": 0.3},
            ],
        )

