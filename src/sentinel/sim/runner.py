"""Simulator Runner — Sends real HTTP traffic to allow-listed target app."""

from __future__ import annotations

import argparse
import asyncio
from typing import Any, Dict, List, Optional

import httpx

from sentinel.core.config import settings
from sentinel.sim.safety import validate_target_url
from sentinel.sim.traffic_generator import TrafficGenerator


class ScenarioRunner:
    def __init__(self, target_url: Optional[str] = None) -> None:
        raw_url = target_url or settings.TARGET_URL
        self.target_url = validate_target_url(raw_url)
        self.generator = TrafficGenerator(seed=42)
        self.active_scenarios: List[str] = []

    async def execute_event(self, client: httpx.AsyncClient, event: Dict[str, Any]) -> None:
        """Sends real HTTP call against ShopAPI target on localhost."""
        method = event.get("method", "GET")
        path = event.get("path", "/")
        url = f"{self.target_url}{path}"

        headers = {
            "User-Agent": event.get("ua", "WardwireSim/1.0"),
            "X-Forwarded-For": event.get("client_ip", "127.0.0.1"),
            "X-Sim-Label": event.get("label", "benign:normal"),
        }
        if event.get("account_id"):
            headers["X-Account-Id"] = str(event["account_id"])
        if event.get("api_key_id"):
            headers["X-API-Key"] = str(event["api_key_id"])
        if event.get("obj_id"):
            headers["X-Object-Id"] = str(event["obj_id"])

        json_body = None
        if path == "/auth/login":
            json_body = {
                "username": event.get("account_id", "admin"),
                "password": "wrong_password" if event.get("auth_event") == "login_failed" else "admin123",
            }
        elif path == "/cart":
            json_body = {"product_id": int(event.get("obj_id") or 1), "quantity": 1}

        try:
            if method == "POST":
                await client.post(url, headers=headers, json=json_body, timeout=2.0)
            else:
                await client.get(url, headers=headers, timeout=2.0)
        except Exception:
            # Demoware tolerance: target might be warming up
            pass

    async def run_scenario(self, scenario_name: str, count: int = 50, stealth: int = 1) -> int:
        """Run named scenario against the target app."""
        self.active_scenarios.append(scenario_name)

        gen_map = {
            "A1": lambda: self.generator.scenario_a1_credential_stuffing(count, stealth),
            "A2": lambda: self.generator.scenario_a2_password_spraying(count, stealth),
            "A3": lambda: self.generator.scenario_a3_bola_enumeration(count, stealth),
            "A4": lambda: self.generator.scenario_a4_catalog_scraping(count, stealth),
            "A5": lambda: self.generator.scenario_a5_volumetric_flood(count, stealth),
            "A6": lambda: self.generator.scenario_a6_low_and_slow(count, stealth),
            "A7": lambda: self.generator.scenario_a7_probing_fuzzing(count, stealth),
            "A8": lambda: self.generator.scenario_a8_data_exfiltration(count, stealth),
            "A9": lambda: self.generator.scenario_a9_baseline_poisoning(count, stealth),
            "B1": lambda: self.generator.scenario_b1_flash_sale(count),
            "B2": lambda: self.generator.scenario_b2_retry_storm(count),
            "B3": lambda: self.generator.scenario_b3_partner_poller(count),
            "B4": lambda: self.generator.scenario_b4_declared_crawler(count),
            "B5": lambda: self.generator.scenario_b5_marketing_login_spike(count),
        }

        # Normalize scenario key
        key = scenario_name.upper()
        if key.startswith("SCENARIO_"):
            key = key.replace("SCENARIO_", "")
        key = key[:2]

        events = gen_map.get(key, lambda: [self.generator.generate_normal_event() for _ in range(count)])()

        async with httpx.AsyncClient() as client:
            for ev in events:
                await self.execute_event(client, ev)
                await asyncio.sleep(0.01)

        if scenario_name in self.active_scenarios:
            self.active_scenarios.remove(scenario_name)

        return len(events)


def run_sim():
    parser = argparse.ArgumentParser(description="Wardwire Simulator")
    parser.add_argument("--scenario", type=str, default="normal")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--stealth", type=int, default=1)
    parser.add_argument("--mode", type=str, default="oneshot")
    args = parser.parse_args()

    runner = ScenarioRunner()
    if args.mode == "background":
        # Keep background normal traffic running for live demo
        async def background_loop():
            async with httpx.AsyncClient() as client:
                while True:
                    ev = runner.generator.generate_normal_event()
                    await runner.execute_event(client, ev)
                    await asyncio.sleep(0.05)

        asyncio.run(background_loop())
    else:
        asyncio.run(runner.run_scenario(args.scenario, count=args.count, stealth=args.stealth))


if __name__ == "__main__":
    run_sim()

