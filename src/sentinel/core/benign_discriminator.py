"""Benign-Surge Discriminator (Critical Differentiator).

Differentiates genuine flash sales, marketing surges, deploy retry storms,
and legitimate automation from malicious volumetric attacks using 6 hypothesis tests.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Tuple

from sentinel.core.schemas import WhyNotBenignCheck


def jensen_shannon_divergence(p_dist: Dict[str, float], q_dist: Dict[str, float]) -> float:
    """
    Computes Jensen-Shannon divergence between two categorical probability distributions.
    Bounded between 0.0 (identical) and 1.0 (maximally disjoint).
    """
    all_keys = set(p_dist.keys()).union(set(q_dist.keys()))
    if not all_keys:
        return 0.0

    # Smooth distributions with Laplace-like epsilon
    eps = 1e-4
    p_sum = sum(p_dist.values()) + len(all_keys) * eps
    q_sum = sum(q_dist.values()) + len(all_keys) * eps

    p_norm = {k: (p_dist.get(k, 0.0) + eps) / p_sum for k in all_keys}
    q_norm = {k: (q_dist.get(k, 0.0) + eps) / q_sum for k in all_keys}

    m_norm = {k: 0.5 * (p_norm[k] + q_norm[k]) for k in all_keys}

    def kl(a, b):
        return sum(a[k] * math.log2(a[k] / b[k]) for k in all_keys if a[k] > 0)

    js = 0.5 * kl(p_norm, m_norm) + 0.5 * kl(q_norm, m_norm)
    return max(0.0, min(1.0, math.sqrt(js)))


class BenignSurgeDiscriminator:
    """
    Evaluates 6 benign hypotheses:
      1. Endpoint-mix divergence (Jensen-Shannon)
      2. Auth success ratio vs baseline
      3. Source diversity (distinct subnets/IPs)
      4. Session consistency (browse -> cart -> checkout flow)
      5. Error-driven retries (correlated with preceding 5xx spike)
      6. Known stable automation (established API key with low error history)
    """

    def evaluate(
        self,
        current_window: Dict[str, Any],
        baseline_profile: Dict[str, Any],
        preceding_5xx_rate: float = 0.0,
        is_known_partner: bool = False,
    ) -> Tuple[float, List[WhyNotBenignCheck]]:
        """
        Returns:
            benign_likelihood: float in [0.0, 1.0]
            checks: list of WhyNotBenignCheck objects for evidence and UI panel
        """
        checks: List[WhyNotBenignCheck] = []
        benign_votes = 0.0
        total_weight = 0.0

        # Check 1: Endpoint-Mix Divergence (Jensen-Shannon)
        curr_routes = current_window.get("route_distribution", {})
        base_routes = baseline_profile.get("route_distribution", {
            "/products": 40.0,
            "/products/{id}": 30.0,
            "/search": 15.0,
            "/cart": 10.0,
            "/checkout": 5.0,
        })
        js_div = jensen_shannon_divergence(curr_routes, base_routes)
        # Normal surges maintain similar mix (JS < 0.35); attacks hyper-focus (JS > 0.60)
        is_mix_benign = js_div < 0.38
        if is_mix_benign:
            benign_votes += 0.25
        total_weight += 0.25
        checks.append(
            WhyNotBenignCheck(
                check="endpoint_mix_divergence",
                observed=round(js_div, 3),
                baseline=0.20,
                verdict="consistent_with_benign" if is_mix_benign else "inconsistent_with_benign",
                detail=f"JS Divergence: {round(js_div, 3)}. Normal flash sales retain catalog mix; targeted attacks skew.",
            )
        )

        # Check 2: Auth Success Ratio
        login_succ = float(current_window.get("login_success", 0))
        login_fail = float(current_window.get("login_failed", 0))
        tot_auth = login_succ + login_fail
        auth_succ_ratio = (login_succ / tot_auth) if tot_auth > 0 else 0.95
        base_auth_ratio = float(baseline_profile.get("auth_success_ratio", 0.90))

        is_auth_benign = auth_succ_ratio >= (base_auth_ratio * 0.75)
        if is_auth_benign:
            benign_votes += 0.25
        total_weight += 0.25
        checks.append(
            WhyNotBenignCheck(
                check="auth_success_ratio",
                observed=round(auth_succ_ratio, 3),
                baseline=round(base_auth_ratio, 3),
                verdict="consistent_with_benign" if is_auth_benign else "inconsistent_with_benign",
                detail=f"Auth Success Rate: {round(auth_succ_ratio * 100, 1)}%. Real flash sales have high success; credential stuffing is <15%.",
            )
        )

        # Check 3: Source & Subnet Diversity
        subnets_count = int(current_window.get("unique_subnets_count", 0))
        ips_count = int(current_window.get("unique_ips_count", 0))
        # High subnet diversity spread across thousands of users indicates genuine broad audience
        # Botnets often cluster into narrow ASN/subnets or a single bot farm
        source_spread_ratio = (subnets_count / max(1, ips_count)) if ips_count > 0 else 1.0
        is_source_benign = subnets_count >= 8 or source_spread_ratio > 0.40
        if is_source_benign:
            benign_votes += 0.15
        total_weight += 0.15
        checks.append(
            WhyNotBenignCheck(
                check="source_subnet_diversity",
                observed=round(source_spread_ratio, 2),
                baseline=0.50,
                verdict="consistent_with_benign" if is_source_benign else "inconsistent_with_benign",
                detail=f"Distinct subnets: {subnets_count}, spread ratio: {round(source_spread_ratio, 2)}. Reflects genuine distributed public audience.",
            )
        )

        # Check 4: Session Consistency (Funnel depth)
        has_browse = "/products" in curr_routes or "/search" in curr_routes
        has_checkout = "/cart" in curr_routes or "/checkout" in curr_routes
        is_funnel_consistent = has_browse and has_checkout
        if is_funnel_consistent:
            benign_votes += 0.15
        total_weight += 0.15
        checks.append(
            WhyNotBenignCheck(
                check="session_funnel_consistency",
                observed=1.0 if is_funnel_consistent else 0.0,
                baseline=1.0,
                verdict="consistent_with_benign" if is_funnel_consistent else "inconsistent_with_benign",
                detail="Plausible user journeys observed across catalog browsing, cart operations, and checkout.",
            )
        )

        # Check 5: Error-Driven Retries
        is_retry_storm = preceding_5xx_rate > 0.05
        if is_retry_storm:
            benign_votes += 0.10
        total_weight += 0.10
        checks.append(
            WhyNotBenignCheck(
                check="error_driven_retries",
                observed=round(preceding_5xx_rate, 3),
                baseline=0.005,
                verdict="consistent_with_benign" if is_retry_storm else "inconsistent_with_benign",
                detail=f"Upstream 5xx rate: {round(preceding_5xx_rate * 100, 1)}%. Surge correlates with backend retries rather than adversarial intent.",
            )
        )

        # Check 6: Known Stable Automation Profile
        if is_known_partner:
            benign_votes += 0.10
        total_weight += 0.10
        checks.append(
            WhyNotBenignCheck(
                check="known_stable_automation",
                observed=1.0 if is_known_partner else 0.0,
                baseline=0.0,
                verdict="consistent_with_benign" if is_known_partner else "inconsistent_with_benign",
                detail="Traffic matches verified partner API credentials with historic low-error patterns.",
            )
        )

        benign_likelihood = benign_votes / max(0.01, total_weight)
        return round(benign_likelihood, 3), checks

