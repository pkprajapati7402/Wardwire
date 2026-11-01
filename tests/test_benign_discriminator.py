"""Unit tests for Benign-Surge Discriminator and Calibrated Fusion."""

from sentinel.core.benign_discriminator import BenignSurgeDiscriminator, jensen_shannon_divergence
from sentinel.core.detectors.base import DetectionResult
from sentinel.core.fusion import FusionEngine


def test_jensen_shannon_divergence():
    p = {"/products": 0.5, "/cart": 0.5}
    q = {"/products": 0.5, "/cart": 0.5}
    # Identical distributions
    assert jensen_shannon_divergence(p, q) < 0.05

    # Completely skewed distribution
    r = {"/auth/login": 1.0}
    assert jensen_shannon_divergence(p, r) > 0.60


def test_benign_surge_discriminator_flash_sale():
    discrim = BenignSurgeDiscriminator()

    # Flash sale profile: normal auth success, wide catalog mix, multi-subnet
    flash_sale_window = {
        "route_distribution": {"/products": 150, "/search": 60, "/cart": 40, "/checkout": 20},
        "login_success": 45,
        "login_failed": 2,
        "unique_subnets_count": 28,
        "unique_ips_count": 65,
        "total_requests": 300,
        "status_totals": {200: 295, 400: 5},
    }

    benign_likelihood, checks = discrim.evaluate(
        current_window=flash_sale_window,
        baseline_profile={"route_distribution": {"/products": 40, "/search": 15, "/cart": 10, "/checkout": 5}},
    )

    # Benign likelihood should be high (> 0.70)
    assert benign_likelihood >= 0.70
    assert len(checks) == 6


def test_fusion_and_benign_suppression():
    fusion = FusionEngine(suppression_k=0.85)

    sample_detection = DetectionResult(
        detector_name="VolumetricFloodDetector",
        category="volumetric_flood",
        owasp="API4:2023",
        score=0.90,
        confidence=0.85,
        entities={"route": "/products"},
        observed={},
        baseline={},
        deviation={},
    )

    # 1. Without benign suppression (e.g. real volumetric DDoS)
    risk_attack, _ = fusion.compute_fused_risk([sample_detection], benign_likelihood=0.0)
    assert risk_attack >= 60

    # 2. With benign suppression (e.g. legitimate flash sale)
    risk_benign, _ = fusion.compute_fused_risk([sample_detection], benign_likelihood=0.90)
    # Risk should be significantly suppressed
    assert risk_benign < risk_attack
    assert risk_benign < 35

