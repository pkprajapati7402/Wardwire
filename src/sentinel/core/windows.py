"""Time-bucketed sliding windows and in-memory / Redis state aggregator."""

from __future__ import annotations

import collections
import time
from typing import Any, Dict, List, Optional, Set

import numpy as np


class SlidingWindowAggregator:
    """
    Maintains 1-second resolution buckets with TTL.
    Supports windows of 10s (short), 60s (mid), 300s (long).
    Tracks request counts, statuses, latencies, bytes, accounts, object IDs,
    inter-arrival timestamps, and sequential-ID histories per entity.
    Bounded memory with maximum key caps to prevent memory exhaustion attacks.
    """

    def __init__(self, max_entities: int = 10000, retention_seconds: int = 360) -> None:
        self.max_entities = max_entities
        self.retention_seconds = retention_seconds

        # Global bucket store: timestamp_second -> metric_dict
        self.global_buckets: Dict[int, Dict[str, Any]] = collections.defaultdict(
            lambda: {
                "count": 0,
                "status_counts": collections.defaultdict(int),
                "route_counts": collections.defaultdict(int),
                "latencies": [],
                "bytes_out": 0,
                "unique_ips": set(),
                "unique_subnets": set(),
                "unique_fps": set(),
                "login_success": 0,
                "login_failed": 0,
            }
        )

        # Entity stores: entity_key -> timestamp_second -> metric_dict
        # entity_key formats: "ip:ip_...", "net:net_...", "acc:u_...", "fp:...", "route:/..."
        self.entity_buckets: Dict[str, Dict[int, Dict[str, Any]]] = collections.defaultdict(
            lambda: collections.defaultdict(
                lambda: {
                    "count": 0,
                    "status_counts": collections.defaultdict(int),
                    "routes": set(),
                    "object_ids": set(),
                    "accounts_targeted": set(),
                    "ips_seen": set(),
                    "subnets_seen": set(),
                    "bytes_out": 0,
                    "latencies": [],
                    "arrival_times": [],
                    "login_success": 0,
                    "login_failed": 0,
                }
            )
        )

        # Recent sequential ID tracking: (principal, route) -> list of int IDs
        self.sequential_id_history: Dict[str, collections.deque[int]] = collections.defaultdict(
            lambda: collections.deque(maxlen=50)
        )

        # Eviction counter for self-protection metrics
        self.evictions_count = 0

    def clean_expired(self, current_sec: Optional[int] = None) -> None:
        """Evict buckets older than retention_seconds."""
        now = current_sec or int(time.time())
        cutoff = now - self.retention_seconds

        # Clean global
        expired_global = [t for t in self.global_buckets if t < cutoff]
        for t in expired_global:
            del self.global_buckets[t]

        # Clean entity buckets
        if len(self.entity_buckets) > self.max_entities:
            # Enforce hard cardinality cap: pop oldest keys
            excess = len(self.entity_buckets) - self.max_entities
            keys_to_remove = list(self.entity_buckets.keys())[:excess]
            for k in keys_to_remove:
                del self.entity_buckets[k]
                self.evictions_count += 1

        for entity_key in list(self.entity_buckets.keys()):
            buckets = self.entity_buckets[entity_key]
            for t in [t for t in buckets if t < cutoff]:
                del buckets[t]
            if not buckets:
                del self.entity_buckets[entity_key]

    def record_event(self, event_dict: Dict[str, Any]) -> None:
        """Record an ingested event into time buckets."""
        ts_raw = event_dict.get("ts")
        if isinstance(ts_raw, str):
            import datetime
            try:
                dt = datetime.datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                t_sec = int(dt.timestamp())
            except Exception:
                t_sec = int(time.time())
        elif ts_raw is not None and hasattr(ts_raw, "timestamp"):
            t_sec = int(ts_raw.timestamp())
        else:
            t_sec = int(time.time())

        status = int(event_dict.get("status", 200))
        route = event_dict.get("route") or event_dict.get("path", "/")
        latency = float(event_dict.get("latency_ms", 0.0))
        bytes_out = int(event_dict.get("bytes_out", 0))
        ip_id = event_dict.get("ip_id", "")
        net_id = event_dict.get("net_id", "")
        fp = event_dict.get("hdr_hash") or event_dict.get("ua_hash", "")
        acc_id = event_dict.get("account_id")
        auth_event = event_dict.get("auth_event")
        obj_id = event_dict.get("obj_id")

        # 1. Update Global
        gb = self.global_buckets[t_sec]
        gb["count"] += 1
        gb["status_counts"][status] += 1
        gb["route_counts"][route] += 1
        gb["latencies"].append(latency)
        gb["bytes_out"] += bytes_out
        if ip_id:
            gb["unique_ips"].add(ip_id)
        if net_id:
            gb["unique_subnets"].add(net_id)
        if fp:
            gb["unique_fps"].add(fp)
        if auth_event == "login_success":
            gb["login_success"] += 1
        elif auth_event == "login_failed":
            gb["login_failed"] += 1

        # 2. Update Entities
        entities_to_update = []
        if ip_id:
            entities_to_update.append((f"ip:{ip_id}", "ip"))
        if net_id:
            entities_to_update.append((f"net:{net_id}", "net"))
        if acc_id:
            entities_to_update.append((f"acc:{acc_id}", "acc"))
        if fp:
            entities_to_update.append((f"fp:{fp}", "fp"))
        if route:
            entities_to_update.append((f"route:{route}", "route"))

        arrival_precise = time.time()
        for ekey, etype in entities_to_update:
            eb = self.entity_buckets[ekey][t_sec]
            eb["count"] += 1
            eb["status_counts"][status] += 1
            eb["routes"].add(route)
            eb["bytes_out"] += bytes_out
            eb["latencies"].append(latency)
            eb["arrival_times"].append(arrival_precise)
            if obj_id:
                eb["object_ids"].add(obj_id)
            if acc_id:
                eb["accounts_targeted"].add(acc_id)
            if ip_id:
                eb["ips_seen"].add(ip_id)
            if net_id:
                eb["subnets_seen"].add(net_id)
            if auth_event == "login_success":
                eb["login_success"] += 1
            elif auth_event == "login_failed":
                eb["login_failed"] += 1

        # 3. Sequential ID tracking
        principal = acc_id or ip_id
        if principal and obj_id and obj_id.isdigit():
            history_key = f"{principal}:{route}"
            self.sequential_id_history[history_key].append(int(obj_id))

    def get_window_slice(self, window_sec: int, current_sec: Optional[int] = None) -> Dict[str, Any]:
        """Aggregate global metrics over the last `window_sec` seconds."""
        now = current_sec or int(time.time())
        start = now - window_sec

        total_requests = 0
        status_totals: Dict[int, int] = collections.defaultdict(int)
        route_totals: Dict[str, int] = collections.defaultdict(int)
        all_latencies: List[float] = []
        total_bytes = 0
        all_ips: Set[str] = set()
        all_subnets: Set[str] = set()
        all_fps: Set[str] = set()
        login_successes = 0
        login_failures = 0

        for t in range(start, now + 1):
            if t in self.global_buckets:
                b = self.global_buckets[t]
                total_requests += b["count"]
                total_bytes += b["bytes_out"]
                all_latencies.extend(b["latencies"])
                all_ips.update(b["unique_ips"])
                all_subnets.update(b["unique_subnets"])
                all_fps.update(b["unique_fps"])
                login_successes += b["login_success"]
                login_failures += b["login_failed"]
                for s, c in b["status_counts"].items():
                    status_totals[s] += c
                for r, c in b["route_counts"].items():
                    route_totals[r] += c

        req_rate = total_requests / max(1, window_sec)
        error_count = sum(c for s, c in status_totals.items() if s >= 400)
        error_rate = error_count / max(1, total_requests)
        p95_lat = float(np.percentile(all_latencies, 95)) if all_latencies else 0.0

        return {
            "window_sec": window_sec,
            "total_requests": total_requests,
            "request_rate": req_rate,
            "error_rate": error_rate,
            "status_totals": dict(status_totals),
            "route_distribution": dict(route_totals),
            "p95_latency_ms": p95_lat,
            "unique_ips_count": len(all_ips),
            "unique_subnets_count": len(all_subnets),
            "unique_fps_count": len(all_fps),
            "login_success": login_successes,
            "login_failed": login_failures,
        }

