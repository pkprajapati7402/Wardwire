"""Robust baselines (EWMA + MAD, diurnal-aware, frozen reference baseline, drift alarms)."""

from __future__ import annotations

import collections
import datetime
import math
from typing import Any, Dict, List, Optional, Tuple


class RobustBaseline:
    """
    Maintains Exponentially Weighted Moving Average (EWMA) and Median Absolute Deviation (MAD)
    per route and global traffic metrics.
    Features:
      - Diurnal-aware hourly seasonality multipliers.
      - Cold-start priors to prevent false alerts on fresh startup.
      - Slow-moving frozen reference baseline for drift detection and poisoning resistance (P1).
      - Anomaly exclusion: skips updating baseline during anomalous bursts.
    """

    def __init__(
        self,
        alpha: float = 0.05,
        reference_alpha: float = 0.005,
        drift_threshold_pct: float = 0.50,
    ) -> None:
        self.alpha = alpha  # Live baseline learning rate
        self.reference_alpha = reference_alpha  # Slow frozen reference baseline
        self.drift_threshold_pct = drift_threshold_pct

        # metric_name -> {"mean": float, "mad": float, "samples": int}
        self.global_metrics: Dict[str, Dict[str, float]] = collections.defaultdict(
            lambda: {"mean": 10.0, "mad": 3.0, "samples": 0}
        )

        # route -> metric_name -> {"mean": float, "mad": float, "samples": int}
        self.route_metrics: Dict[str, Dict[str, Dict[str, float]]] = collections.defaultdict(
            lambda: collections.defaultdict(lambda: {"mean": 2.0, "mad": 1.0, "samples": 0})
        )

        # Frozen reference baselines for poisoning detection
        self.reference_metrics: Dict[str, float] = collections.defaultdict(lambda: 10.0)

        # Baseline drift alarms
        self.drift_alarms: List[Dict[str, Any]] = []

    def get_diurnal_factor(self, dt: Optional[datetime.datetime] = None) -> float:
        """
        Returns diurnal curve multiplier (0.5 to 1.5) based on hour of day (UTC).
        Peak traffic around 14:00-18:00 UTC, trough around 03:00-06:00 UTC.
        """
        now = dt or datetime.datetime.now(datetime.timezone.utc)
        hour = now.hour + (now.minute / 60.0)
        # Sine wave oscillating between 0.6 and 1.4 centered at hour 15
        rad = (hour - 15) * 2 * math.pi / 24.0
        return 1.0 + 0.4 * math.cos(rad)

    def update(
        self,
        metric_name: str,
        value: float,
        route: Optional[str] = None,
        is_anomalous: bool = False,
    ) -> None:
        """
        Update robust running baseline. If window is anomalous, updates are skipped
        or throttled to prevent baseline poisoning (A9 resistance).
        """
        if is_anomalous:
            # Poisoning mitigation: do not absorb attack spikes into baseline
            return

        target = self.route_metrics[route][metric_name] if route else self.global_metrics[metric_name]

        # Initialize priors if cold start
        if target["samples"] == 0:
            target["mean"] = float(value)
            target["mad"] = max(1.0, float(value) * 0.25)
            target["samples"] = 1
            if not route:
                self.reference_metrics[metric_name] = float(value)
            return

        old_mean = target["mean"]
        diff = abs(value - old_mean)

        # EWMA update
        new_mean = (1 - self.alpha) * old_mean + self.alpha * value
        new_mad = (1 - self.alpha) * target["mad"] + self.alpha * diff

        target["mean"] = new_mean
        target["mad"] = max(0.5, new_mad)
        target["samples"] += 1

        # Update slow-moving frozen reference baseline (global only)
        if not route:
            ref = self.reference_metrics[metric_name]
            self.reference_metrics[metric_name] = (1 - self.reference_alpha) * ref + self.reference_alpha * value

            # Check for baseline drift (Poisoning Alarm)
            drift = abs(new_mean - ref) / max(1.0, ref)
            if drift > self.drift_threshold_pct and target["samples"] > 30:
                self.drift_alarms.append({
                    "metric": metric_name,
                    "live_mean": round(new_mean, 2),
                    "reference_mean": round(ref, 2),
                    "drift_pct": round(drift * 100, 1),
                    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                })

    def get_baseline(
        self,
        metric_name: str,
        route: Optional[str] = None,
        apply_diurnal: bool = True,
    ) -> Tuple[float, float]:
        """
        Returns (expected_mean, mad). If apply_diurnal is True, expected_mean is scaled by diurnal factor.
        """
        diurnal = self.get_diurnal_factor() if apply_diurnal else 1.0
        if route and route in self.route_metrics and metric_name in self.route_metrics[route]:
            b = self.route_metrics[route][metric_name]
            return b["mean"] * diurnal, b["mad"]

        b = self.global_metrics[metric_name]
        return b["mean"] * diurnal, b["mad"]

    def compute_robust_z_score(
        self,
        metric_name: str,
        value: float,
        route: Optional[str] = None,
        apply_diurnal: bool = True,
    ) -> float:
        """
        Computes robust z-score: (value - mean) / (1.4826 * MAD).
        Returns deviation in terms of median absolute deviations.
        """
        mean, mad = self.get_baseline(metric_name, route, apply_diurnal=apply_diurnal)
        denom = 1.4826 * max(0.5, mad)
        return (value - mean) / denom

