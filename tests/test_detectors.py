"""Unit tests for all abuse detectors."""

from sentinel.core.detectors.bola import BolaEnumerationDetector
from sentinel.core.detectors.credential_stuffing import CredentialStuffingDetector
from sentinel.core.detectors.probing import ProbingFuzzingDetector
from sentinel.core.detectors.scraping import ScrapingDetector
from sentinel.core.detectors.volumetric import VolumetricFloodDetector


def test_volumetric_flood_detector():
    det = VolumetricFloodDetector(z_threshold=3.0)
    # Normal activity
    res_normal = det.detect({"request_rate": 10.0, "baseline_mean": 10.0, "z_score": 0.2})
    assert res_normal is None

    # Flood surge
    res_flood = det.detect({"request_rate": 150.0, "baseline_mean": 10.0, "z_score": 6.5})
    assert res_flood is not None
    assert res_flood.category == "volumetric_flood"
    assert res_flood.owasp == "API4:2023"
    assert res_flood.score >= 0.7


def test_credential_stuffing_detector():
    det = CredentialStuffingDetector(min_failures=15, fail_ratio=0.65)

    # Benign normal logins
    res_normal = det.detect({
        "login_failed": 2,
        "login_success": 25,
        "distinct_accounts_count": 1,
    })
    assert res_normal is None

    # Distributed credential stuffing attack
    res_attack = det.detect({
        "login_failed": 120,
        "login_success": 5,
        "distinct_accounts_count": 45,
        "distinct_ips_count": 40,
        "distinct_subnets_count": 15,
    })
    assert res_attack is not None
    assert res_attack.category == "credential_stuffing"
    assert res_attack.owasp == "API2:2023"
    assert res_attack.entities["is_distributed"] is True


def test_bola_enumeration_detector():
    det = BolaEnumerationDetector(monotonic_ratio_threshold=0.6, min_objects=5)

    # Sequential ID enumeration
    res_bola = det.detect({
        "distinct_objects_count": 25,
        "sequential_id_score": 0.88,
        "ratio_403": 0.20,
        "ratio_404": 0.10,
    })
    assert res_bola is not None
    assert res_bola.category == "bola_enumeration"
    assert res_bola.owasp == "API1:2023"


def test_scraping_detector():
    det = ScrapingDetector(min_resources=15, cv_threshold=0.25)

    # Headless scraping with robotic timing (CV=0.12)
    res_scrape = det.detect({
        "distinct_objects_count": 30,
        "total_requests": 60,
        "timing_cv": 0.12,
    })
    assert res_scrape is not None
    assert res_scrape.category == "scraping"
    assert res_scrape.owasp == "API6:2023"


def test_probing_detector():
    det = ProbingFuzzingDetector(min_404_count=8)

    # 404 scanning probe
    res_probe = det.detect({
        "total_requests": 20,
        "ratio_404": 0.70,
        "distinct_routes_count": 14,
        "has_undocumented_route": True,
    })
    assert res_probe is not None
    assert res_probe.category == "probing"
    assert res_probe.owasp == "API9:2023"
