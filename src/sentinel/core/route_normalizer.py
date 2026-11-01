"""Route normalisation and OpenAPI matching.

Learns templates by clustering path segments (numeric, UUID, hex, slug)
and validates paths against configured OpenAPI route specifications.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
HEX_REGEX = re.compile(r"^[0-9a-fA-F]{16,64}$")
INT_REGEX = re.compile(r"^\d+$")


class RouteNormalizer:
    def __init__(self, documented_routes: Optional[Set[str]] = None) -> None:
        self.documented_routes: Set[str] = documented_routes or set()
        self._learned_templates: Dict[str, str] = {}
        # Prepopulate standard documented routes if available
        for route in self.documented_routes:
            self.register_route(route)

    def register_route(self, route_pattern: str) -> None:
        """Register a known documented route pattern like '/orders/{id}'."""
        self.documented_routes.add(route_pattern)

    def normalize(self, raw_path: str) -> Tuple[str, bool]:
        """
        Normalizes a raw URI path to its parametrized template.
        Returns:
            (normalized_route, is_documented)
        """
        # Strip query parameters and clean trailing slashes
        clean_path = raw_path.split("?")[0].rstrip("/")
        if not clean_path:
            clean_path = "/"

        # 1. Exact match against documented routes
        if clean_path in self.documented_routes:
            return clean_path, True

        # 2. Check cached learned template
        if clean_path in self._learned_templates:
            route = self._learned_templates[clean_path]
            is_doc = route in self.documented_routes if self.documented_routes else True
            return route, is_doc

        # 3. Dynamic segment replacement
        segments = clean_path.split("/")
        norm_segments: List[str] = []

        for seg in segments:
            if not seg:
                norm_segments.append("")
                continue

            if INT_REGEX.match(seg):
                norm_segments.append("{id}")
            elif UUID_REGEX.match(seg):
                norm_segments.append("{uuid}")
            elif HEX_REGEX.match(seg):
                norm_segments.append("{hex}")
            elif seg.startswith("u_") and len(seg) > 3:
                norm_segments.append("{user_id}")
            elif seg.startswith("ord_") and len(seg) > 4:
                norm_segments.append("{order_id}")
            elif seg.startswith("prod_") and len(seg) > 5:
                norm_segments.append("{product_id}")
            else:
                norm_segments.append(seg)

        normalized = "/".join(norm_segments)
        if not normalized.startswith("/"):
            normalized = "/" + normalized

        # Cache template
        if len(self._learned_templates) < 5000:
            self._learned_templates[clean_path] = normalized

        is_documented = True
        if self.documented_routes:
            is_documented = normalized in self.documented_routes

        return normalized, is_documented


# Default global normalizer instance
global_route_normalizer = RouteNormalizer({
    "/auth/login",
    "/products",
    "/products/{id}",
    "/search",
    "/cart",
    "/checkout",
    "/orders/{id}",
    "/users/{id}/profile",
    "/admin/reports",
    "/healthz",
    "/readyz",
    "/metrics",
})

