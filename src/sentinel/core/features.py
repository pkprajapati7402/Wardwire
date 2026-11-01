"""Feature extraction per entity and window."""

from __future__ import annotations

import collections
from typing import Any, Dict, List, Optional, Set

import numpy as np

from sentinel.core.windows import SlidingWindowAggregator


def compute_coefficient_of_variation(timestamps: List[float]) -> float:
    """
    Computes coefficient of variation (std / mean) of inter-arrival times.
    Scripted bots and crawlers have rigid timers (CV << 0.3),
    whereas human interactions have high jitter (CV > 0.6).
    """
    if len(timestamps) < 3:
        return 1.0  # Insufficient data, assume natural variance

    sorted_ts = sorted(timestamps)
    intervals = [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]
    intervals = [dt for dt in intervals if dt > 0.0]
    if len(intervals) < 2:
        return 1.0

    mean_dt = float(np.mean(intervals))
    if mean_dt <= 1e-6:
        return 0.0
    std_dt = float(np.std(intervals))
    return std_dt / mean_dt


def compute_sequential_score(id_list: List[int]) -> float:
    """
    Computes monotonic step score among accessed object IDs.
    Returns fraction of consecutive pairs with steps of 1, 2, or -1.
    High score indicates automated BOLA/ID enumeration.
    """
    if len(id_list) < 4:
        return 0.0

    monotonic_steps = 0
    total_pairs = len(id_list) - 1

    for i in range(total_pairs):
        step = id_list[i + 1] - id_list[i]
        if step in (1, 2, -1):
            monotonic_steps += 1

    return monotonic_steps / total_pairs


def extract_entity_features(
    aggregator: SlidingWindowAggregator,
    entity_key: str,
    window_sec: int,
    current_sec: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Extracts rich multidimensional feature vector for a specific entity key
    (e.g., 'ip:ip_123', 'fp:fp_abc', 'acc:u_884', 'net:net_41') over `window_sec`.
    """
    import time
    now = current_sec or int(time.time())
    start = now - window_sec

    total_reqs = 0
    status_counts: Dict[int, int] = collections.defaultdict(int)
    routes: Set[str] = set()
    object_ids: Set[str] = set()
    accounts_targeted: Set[str] = set()
    ips_seen: Set[str] = set()
    subnets_seen: Set[str] = set()
    bytes_out_total = 0
    latencies: List[float] = []
    arrival_times: List[float] = []
    login_success = 0
    login_failed = 0

    buckets = aggregator.entity_buckets.get(entity_key, {})
    for t in range(start, now + 1):
        if t in buckets:
            b = buckets[t]
            total_reqs += b["count"]
            bytes_out_total += b["bytes_out"]
            routes.update(b["routes"])
            object_ids.update(b["object_ids"])
            accounts_targeted.update(b["accounts_targeted"])
            ips_seen.update(b["ips_seen"])
            subnets_seen.update(b["subnets_seen"])
            latencies.extend(b["latencies"])
            arrival_times.extend(b["arrival_times"])
            login_success += b["login_success"]
            login_failed += b["login_failed"]
            for s, c in b["status_counts"].items():
                status_counts[s] += c

    req_rate = total_reqs / max(1, window_sec)
    err_count = sum(c for s, c in status_counts.items() if s >= 400)
    err_rate = err_count / max(1, total_reqs)

    c401 = status_counts.get(401, 0)
    c403 = status_counts.get(403, 0)
    c404 = status_counts.get(404, 0)
    r401 = c401 / max(1, total_reqs)
    r403 = c403 / max(1, total_reqs)
    r404 = c404 / max(1, total_reqs)

    mean_bytes = (bytes_out_total / total_reqs) if total_reqs > 0 else 0.0
    cv = compute_coefficient_of_variation(arrival_times)

    # Check sequential ID score for this entity
    # (if entity is ip or acc, inspect registered history)
    raw_id = entity_key.split(":", 1)[1] if ":" in entity_key else entity_key
    seq_scores = []
    for hist_key, id_history in aggregator.sequential_id_history.items():
        if hist_key.startswith(raw_id):
            seq_scores.append(compute_sequential_score(list(id_history)))
    seq_score = max(seq_scores) if seq_scores else 0.0

    return {
        "entity_key": entity_key,
        "window_sec": window_sec,
        "total_requests": total_reqs,
        "request_rate": req_rate,
        "error_rate": err_rate,
        "ratio_401": r401,
        "ratio_403": r403,
        "ratio_404": r404,
        "distinct_routes_count": len(routes),
        "distinct_objects_count": len(object_ids),
        "distinct_accounts_count": len(accounts_targeted),
        "distinct_ips_count": len(ips_seen),
        "distinct_subnets_count": len(subnets_seen),
        "mean_bytes_out": mean_bytes,
        "timing_cv": cv,
        "sequential_id_score": seq_score,
        "login_success": login_success,
        "login_failed": login_failed,
        "p95_latency": float(np.percentile(latencies, 95)) if latencies else 0.0,
    }

