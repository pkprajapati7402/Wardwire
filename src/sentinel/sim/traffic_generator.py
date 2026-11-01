"""Synthetic Traffic Generators, Scenarios (A1-A9, B1-B5), and Stealth Levels (0-4)."""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

from faker import Faker

fake = Faker()
Faker.seed(42)
random.seed(42)

# User-Agent families for normal vs bot traffic
UA_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

UA_BOT = [
    "python-requests/2.31.0",
    "curl/8.4.0",
    "Go-http-client/1.1",
    "Apache-HttpClient/4.5.13 (Java/17.0.2)",
]


class TrafficGenerator:
    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_random_ip(self, subnet_idx: Optional[int] = None) -> str:
        s = subnet_idx if subnet_idx is not None else self.rng.randint(10, 200)
        host = self.rng.randint(2, 250)
        return f"198.51.{s}.{host}"

    def generate_normal_event(self) -> Dict[str, Any]:
        """Generates a realistic normal user session event."""
        # Markov state machine
        routes = ["/products", "/products/{id}", "/search", "/cart", "/checkout"]
        weights = [0.40, 0.30, 0.15, 0.10, 0.05]
        chosen_route = self.rng.choices(routes, weights=weights)[0]

        product_id = self.rng.randint(1, 100)
        path = chosen_route.replace("{id}", str(product_id))

        method = "POST" if chosen_route in ("/cart", "/checkout") else "GET"
        status = 200
        if chosen_route == "/checkout" and self.rng.random() < 0.05:
            status = 400

        user_num = self.rng.randint(100, 200)
        account_id = f"u_{user_num}"
        ip = self.generate_random_ip(user_num % 30)

        return {
            "method": method,
            "path": path,
            "route": chosen_route,
            "status": status,
            "latency_ms": round(self.rng.uniform(15.0, 75.0), 2),
            "bytes_in": 120,
            "bytes_out": self.rng.randint(800, 4000),
            "client_ip": ip,
            "ua": self.rng.choice(UA_NORMAL),
            "account_id": account_id,
            "obj_id": str(product_id) if "{id}" in chosen_route else None,
            "auth_event": None,
            "label": "benign:normal",
        }

    # ==========================================
    # Benign Look-Alike Scenarios (B1 - B5)
    # ==========================================

    def scenario_b1_flash_sale(self, count: int = 200) -> List[Dict[str, Any]]:
        """B1: Flash-sale surge (10x volume, normal auth success, wide catalog mix)."""
        events = []
        for _ in range(count):
            e = self.generate_normal_event()
            e["label"] = "benign:B1_flash_sale"
            # High source diversity (many distinct subnets)
            e["client_ip"] = self.generate_random_ip(self.rng.randint(1, 90))
            events.append(e)
        return events

    def scenario_b2_retry_storm(self, count: int = 100) -> List[Dict[str, Any]]:
        """B2: Deploy-day retry storm (preceding 5xx spikes followed by client retries)."""
        events = []
        for i in range(count):
            e = self.generate_normal_event()
            e["label"] = "benign:B2_retry_storm"
            e["status"] = 503 if i < 30 else 200
            events.append(e)
        return events

    def scenario_b3_partner_poller(self, count: int = 50) -> List[Dict[str, Any]]:
        """B3: Partner batch poller (stable periodic API key querying)."""
        events = []
        for _ in range(count):
            events.append({
                "method": "GET",
                "path": "/products?limit=100",
                "route": "/products",
                "status": 200,
                "latency_ms": 35.0,
                "bytes_in": 80,
                "bytes_out": 12500,
                "client_ip": "198.51.99.10",
                "ua": "PartnerSync/2.1 (AcmeCorp)",
                "api_key_id": "key_partner_acme",
                "label": "benign:B3_partner_poller",
            })
        return events

    def scenario_b4_declared_crawler(self, count: int = 60) -> List[Dict[str, Any]]:
        """B4: Declared search engine crawler (steady, polite)."""
        events = []
        for pid in range(1, min(count + 1, 100)):
            events.append({
                "method": "GET",
                "path": f"/products/{pid}",
                "route": "/products/{id}",
                "status": 200,
                "latency_ms": 40.0,
                "bytes_in": 50,
                "bytes_out": 2200,
                "client_ip": "198.51.55.5",
                "ua": "Googlebot/2.1 (+http://www.google.com/bot.html)",
                "label": "benign:B4_crawler",
            })
        return events

    def scenario_b5_marketing_login_spike(self, count: int = 80) -> List[Dict[str, Any]]:
        """B5: Marketing campaign login spike with normal auth success (>90%)."""
        events = []
        for i in range(count):
            succ = self.rng.random() < 0.92
            events.append({
                "method": "POST",
                "path": "/auth/login",
                "route": "/auth/login",
                "status": 200 if succ else 401,
                "latency_ms": 45.0,
                "bytes_in": 150,
                "bytes_out": 400 if succ else 120,
                "client_ip": self.generate_random_ip(),
                "ua": self.rng.choice(UA_NORMAL),
                "account_id": f"u_{self.rng.randint(100, 200)}",
                "auth_event": "login_success" if succ else "login_failed",
                "label": "benign:B5_marketing_login_spike",
            })
        return events

    # ==========================================
    # Attack Scenarios (A1 - A9) with Stealth (0-4)
    # ==========================================

    def _apply_stealth(
        self,
        event: Dict[str, Any],
        stealth: int,
        base_ip: str,
        subnet_range: int = 50,
    ) -> Dict[str, Any]:
        """
        Stealth 0: Naive burst from single IP, basic bot UA.
        Stealth 1: Low rate per IP.
        Stealth 2: IP rotation across wide subnets.
        Stealth 3: Realistic browser UA + header mimicry + timing jitter.
        Stealth 4: Low velocity blended into traffic.
        """
        if stealth == 0:
            event["client_ip"] = base_ip
            event["ua"] = self.rng.choice(UA_BOT)
        elif stealth == 1:
            event["client_ip"] = base_ip
            event["latency_ms"] = round(self.rng.uniform(30.0, 90.0), 2)
        elif stealth == 2:
            event["client_ip"] = self.generate_random_ip(self.rng.randint(1, subnet_range))
        elif stealth >= 3:
            event["client_ip"] = self.generate_random_ip(self.rng.randint(1, subnet_range))
            event["ua"] = self.rng.choice(UA_NORMAL)
            event["latency_ms"] = round(self.rng.uniform(25.0, 150.0), 2)
        return event

    def scenario_a1_credential_stuffing(self, count: int = 150, stealth: int = 2) -> List[Dict[str, Any]]:
        """A1: Credential stuffing (distributed failed logins across many accounts)."""
        events = []
        base_ip = "198.51.100.99"
        for i in range(count):
            account_id = f"victim_{self.rng.randint(1000, 9999)}"
            e = {
                "method": "POST",
                "path": "/auth/login",
                "route": "/auth/login",
                "status": 401,
                "latency_ms": 25.0,
                "bytes_in": 140,
                "bytes_out": 110,
                "account_id": account_id,
                "auth_event": "login_failed",
                "label": f"attack:A1:stealth{stealth}",
            }
            events.append(self._apply_stealth(e, stealth, base_ip, subnet_range=80))
        return events

    def scenario_a2_password_spraying(self, count: int = 80, stealth: int = 2) -> List[Dict[str, Any]]:
        """A2: Password spraying (few attempts across many victim accounts)."""
        events = []
        base_ip = "198.51.101.44"
        for i in range(count):
            acc_id = f"spray_acc_{i}"
            e = {
                "method": "POST",
                "path": "/auth/login",
                "route": "/auth/login",
                "status": 401,
                "latency_ms": 30.0,
                "bytes_in": 130,
                "bytes_out": 115,
                "account_id": acc_id,
                "auth_event": "login_failed",
                "label": f"attack:A2:stealth{stealth}",
            }
            events.append(self._apply_stealth(e, stealth, base_ip))
        return events

    def scenario_a3_bola_enumeration(self, count: int = 40, stealth: int = 1) -> List[Dict[str, Any]]:
        """A3: BOLA / ID enumeration (sequential monotonic object IDs)."""
        events = []
        principal_id = "attacker_user_42"
        base_ip = "198.51.102.12"
        start_id = 1001

        for i in range(count):
            order_id = start_id + i  # Sequential +1 progression
            e = {
                "method": "GET",
                "path": f"/orders/{order_id}",
                "route": "/orders/{id}",
                "status": 200 if i % 4 != 0 else 404,
                "latency_ms": 20.0,
                "bytes_in": 50,
                "bytes_out": 1800,
                "account_id": principal_id,
                "obj_id": str(order_id),
                "label": f"attack:A3:stealth{stealth}",
            }
            events.append(self._apply_stealth(e, stealth, base_ip))
        return events

    def scenario_a4_catalog_scraping(self, count: int = 80, stealth: int = 2) -> List[Dict[str, Any]]:
        """A4: Catalog scraping (harvesting all catalog objects, low timing variance)."""
        events = []
        base_ip = "198.51.103.50"
        for pid in range(1, count + 1):
            e = {
                "method": "GET",
                "path": f"/products/{pid}",
                "route": "/products/{id}",
                "status": 200,
                "latency_ms": 15.0,
                "bytes_in": 60,
                "bytes_out": 2800,
                "obj_id": str(pid),
                "label": f"attack:A4:stealth{stealth}",
            }
            events.append(self._apply_stealth(e, stealth, base_ip))
        return events

    def scenario_a5_volumetric_flood(self, count: int = 350, stealth: int = 0) -> List[Dict[str, Any]]:
        """A5: Volumetric L7 flood (high-rate burst)."""
        events = []
        base_ip = "198.51.104.1"
        for _ in range(count):
            e = {
                "method": "GET",
                "path": "/products",
                "route": "/products",
                "status": 200,
                "latency_ms": 10.0,
                "bytes_in": 40,
                "bytes_out": 4200,
                "label": f"attack:A5:stealth{stealth}",
            }
            events.append(self._apply_stealth(e, stealth, base_ip, subnet_range=50))
        return events

    def scenario_a6_low_and_slow(self, count: int = 60, stealth: int = 3) -> List[Dict[str, Any]]:
        """A6: Low-and-slow distributed flood."""
        events = []
        base_ip = "198.51.105.10"
        for _ in range(count):
            e = {
                "method": "GET",
                "path": "/search?q=query",
                "route": "/search",
                "status": 200,
                "latency_ms": 80.0,
                "bytes_in": 90,
                "bytes_out": 3500,
                "label": f"attack:A6:stealth{stealth}",
            }
            events.append(self._apply_stealth(e, stealth, base_ip, subnet_range=60))
        return events

    def scenario_a7_probing_fuzzing(self, count: int = 50, stealth: int = 1) -> List[Dict[str, Any]]:
        """A7: Endpoint probing / fuzzing (including undocumented routes)."""
        fuzz_paths = [
            "/v0/internal/catalog",
            "/legacy/user_export",
            "/admin/debug",
            "/api/v2/keys",
            "/.env",
            "/actuator/env",
            "/phpmyadmin",
        ]
        events = []
        base_ip = "198.51.106.88"
        for i in range(count):
            path = fuzz_paths[i % len(fuzz_paths)]
            e = {
                "method": "GET",
                "path": path,
                "route": path,
                "status": 404 if "env" in path or "php" in path or "debug" in path else 200,
                "latency_ms": 18.0,
                "bytes_in": 50,
                "bytes_out": 250,
                "label": f"attack:A7:stealth{stealth}",
            }
            events.append(self._apply_stealth(e, stealth, base_ip))
        return events

    def scenario_a8_data_exfiltration(self, count: int = 30, stealth: int = 1) -> List[Dict[str, Any]]:
        """A8: Data exfiltration via bulk exports or oversized responses."""
        events = []
        base_ip = "198.51.107.15"
        for i in range(count):
            e = {
                "method": "GET",
                "path": f"/products?limit=100&offset={i * 100}",
                "route": "/products",
                "status": 200,
                "latency_ms": 140.0,
                "bytes_in": 80,
                "bytes_out": 85000,  # 85 KB per request
                "account_id": "data_miner_u1",
                "label": f"attack:A8:stealth{stealth}",
            }
            events.append(self._apply_stealth(e, stealth, base_ip))
        return events

    def scenario_a9_baseline_poisoning(self, count: int = 200, stealth: int = 4) -> List[Dict[str, Any]]:
        """A9: Baseline poisoning (slow progressive ramp up to shift baseline)."""
        events = []
        base_ip = "198.51.108.9"
        for _ in range(count):
            e = {
                "method": "GET",
                "path": "/products",
                "route": "/products",
                "status": 200,
                "latency_ms": 30.0,
                "bytes_in": 50,
                "bytes_out": 3000,
                "label": f"attack:A9:stealth{stealth}",
            }
            events.append(self._apply_stealth(e, stealth, base_ip, subnet_range=50))
        return events

