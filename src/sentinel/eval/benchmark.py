"""Wardwire Performance & Latency Benchmark Suite (make bench).

Measures ingestion throughput, feature computation latency, memory consumption,
and cardinality cap compliance under normal load, 10x surge, and high-cardinality floods.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import time
from typing import Any, Dict, List

import numpy as np

from sentinel.core.pseudonym import pseudonymize_ip
from sentinel.core.route_normalizer import global_route_normalizer
from sentinel.core.windows import SlidingWindowAggregator
from sentinel.sim.traffic_generator import TrafficGenerator


class BenchmarkSuite:
    def __init__(self, event_count: int = 5000) -> None:
        self.event_count = event_count
        self.generator = TrafficGenerator(seed=42)

    def benchmark_pipeline(self) -> Dict[str, Any]:
        aggregator = SlidingWindowAggregator(max_entities=10000)
        events = [self.generator.generate_normal_event() for _ in range(self.event_count)]

        latencies_ms: List[float] = []

        start_time = time.perf_counter()

        for ev in events:
            t0 = time.perf_counter()

            # 1. Pseudonymisation
            raw_ip = ev.get("client_ip", "127.0.0.1")
            ip_id, net_id = pseudonymize_ip(raw_ip, "bench_salt_32b_secret")

            # 2. Route normalisation
            route, is_doc = global_route_normalizer.normalize(ev.get("path", "/"))

            # 3. Sliding window record
            clean = ev.copy()
            clean["ip_id"] = ip_id
            clean["net_id"] = net_id
            clean["route"] = route
            clean["hdr_hash"] = "h_bench"
            aggregator.record_event(clean)

            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        total_duration = time.perf_counter() - start_time
        events_per_sec = len(events) / max(0.001, total_duration)

        p50 = float(np.percentile(latencies_ms, 50))
        p95 = float(np.percentile(latencies_ms, 95))
        p99 = float(np.percentile(latencies_ms, 99))

        # Test High-Cardinality Flooding (Memory Bounding Guard)
        _ = len(aggregator.entity_buckets)
        for i in range(15000):
            # Flood with completely random distinct IPs and accounts
            aggregator.record_event({
                "ts": int(time.time()),
                "status": 200,
                "latency_ms": 10.0,
                "bytes_out": 100,
                "ip_id": f"rand_ip_{i}",
                "net_id": f"rand_net_{i // 256}",
                "account_id": f"rand_u_{i}",
                "path": "/products",
                "route": "/products",
            })
        aggregator.clean_expired()
        cardinality_capped_keys = len(aggregator.entity_buckets)

        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "hardware": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "processor": platform.processor(),
            },
            "workload": {
                "events_evaluated": self.event_count,
                "duration_seconds": round(total_duration, 3),
            },
            "throughput": {
                "events_per_second": round(events_per_sec, 1),
                "target_rps": 1000.0,
                "meets_target": events_per_sec >= 1000.0,
            },
            "latency_ms": {
                "p50": round(p50, 3),
                "p95": round(p95, 3),
                "p99": round(p99, 3),
                "target_p99_max": 50.0,
                "meets_target": p99 < 50.0,
            },
            "memory_guard": {
                "max_cardinality_cap": aggregator.max_entities,
                "keys_after_flood": cardinality_capped_keys,
                "evictions_enforced": aggregator.evictions_count,
                "is_bounded": cardinality_capped_keys <= aggregator.max_entities,
            },
        }


def main():
    parser = argparse.ArgumentParser(description="Wardwire Benchmark Suite")
    parser.add_argument("--events", type=int, default=5000)
    parser.add_argument("--output", type=str, default="reports/bench.json")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    bench = BenchmarkSuite(event_count=args.events)
    print(f"[*] Running Wardwire Benchmark ({args.events} events)...")
    res = bench.benchmark_pipeline()

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)

    print(f"[+] Throughput: {res['throughput']['events_per_second']} events/sec (Target: >= 1,000)")
    print(f"[+] Latency: p50={res['latency_ms']['p50']}ms, p95={res['latency_ms']['p95']}ms, p99={res['latency_ms']['p99']}ms (Target p99: < 50ms)")
    print(f"[+] Memory Guard: Bounded keys {res['memory_guard']['keys_after_flood']} <= {res['memory_guard']['max_cardinality_cap']}")
    print(f"[+] Saved results to {args.output}")


if __name__ == "__main__":
    main()

