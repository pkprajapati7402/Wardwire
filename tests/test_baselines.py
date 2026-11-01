"""Tests for Robust Baselines (EWMA, MAD, Diurnal factors, drift alarms)."""

from sentinel.core.baselines import RobustBaseline


def test_ewma_mad_convergence():
    base = RobustBaseline(alpha=0.1)

    for _ in range(50):
        base.update("metric_a", 20.0)

    mean, mad = base.get_baseline("metric_a", apply_diurnal=False)
    assert abs(mean - 20.0) < 1.0
    assert mad > 0.0


def test_robust_z_score_calculation():
    base = RobustBaseline()
    base.global_metrics["rps"] = {"mean": 10.0, "mad": 2.0, "samples": 10}

    # Value at expected baseline mean should yield z close to 0
    mean, _ = base.get_baseline("rps")
    z_normal = base.compute_robust_z_score("rps", mean)
    assert abs(z_normal) < 0.1

    # Surge at 80 rps should yield high z > 8.0
    z_surge = base.compute_robust_z_score("rps", 80.0)
    assert z_surge > 8.0


def test_drift_and_poisoning_resistance():
    base = RobustBaseline(reference_alpha=0.001, drift_threshold_pct=0.40)
    # Train normal baseline
    for _ in range(40):
        base.update("rps", 10.0)

    # Attempt to poison baseline with sudden elevated values
    for _ in range(10):
        base.update("rps", 80.0, is_anomalous=True)

    # Anomaly exclusion prevents absorption
    mean, _ = base.get_baseline("rps")
    assert mean < 30.0  # Kept robust against attack poisoning
