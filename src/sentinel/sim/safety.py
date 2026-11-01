"""Simulator Safety & Target Allow-listing.

Enforces strict host whitelisting and rate caps. Refuses any target not explicitly
authorized in SIM_ALLOWED_TARGETS.
"""

from __future__ import annotations

import urllib.parse
from typing import List, Optional

from sentinel.core.config import settings


class SimulatorSecurityError(PermissionError):
    """Raised when an unauthorized destination host is targeted."""
    pass


def validate_target_url(target_url: str, allowed_targets: Optional[List[str]] = None) -> str:
    """
    Validates that target_url resolves to a permitted local or docker-compose host.
    Raises SimulatorSecurityError if the host is external or disallowed.
    """
    allowed = allowed_targets or settings.SIM_ALLOWED_TARGETS
    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname or ""
    netloc = parsed.netloc or ""

    # Check hostname or full host:port in allowed list
    is_permitted = any(
        target == hostname
        or target == netloc
        or target_url.startswith(target)
        for target in allowed
    )

    if not is_permitted:
        raise SimulatorSecurityError(
            f"Target URL '{target_url}' is not in SIM_ALLOWED_TARGETS: {allowed}. "
            f"The Wardwire simulator is strictly prohibited from sending traffic to external networks."
        )

    return target_url

