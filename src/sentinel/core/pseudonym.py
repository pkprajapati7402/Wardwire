"""HMAC Pseudonymisation for IP addresses and network subnets.

Ensures raw IP addresses are never stored in databases, logs, Redis streams,
or API responses.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from typing import Tuple


def extract_subnet_prefix(ip_str: str) -> str:
    """Extract /24 for IPv4 or /48 for IPv6 network prefix string."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.version == 4:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(net.network_address)
        else:
            net = ipaddress.ip_network(f"{ip}/48", strict=False)
            return str(net.network_address)
    except Exception:
        # Fallback for ill-formed IP or synthetic placeholder
        parts = ip_str.split(".")
        if len(parts) >= 3:
            return ".".join(parts[:3]) + ".0"
        return "unknown_net"


def pseudonymize_ip(ip_str: str, secret_salt: str) -> Tuple[str, str]:
    """
    Given a raw IP address and HMAC secret salt, produces:
      ip_id: HMAC-SHA256(secret_salt, ip)[:16]
      net_id: HMAC-SHA256(secret_salt, /24 or /48 prefix)[:16]
    """
    clean_ip = ip_str.strip()
    subnet_str = extract_subnet_prefix(clean_ip)

    salt_bytes = secret_salt.encode("utf-8")

    ip_hmac = hmac.new(salt_bytes, clean_ip.encode("utf-8"), hashlib.sha256).hexdigest()
    net_hmac = hmac.new(salt_bytes, subnet_str.encode("utf-8"), hashlib.sha256).hexdigest()

    ip_id = f"ip_{ip_hmac[:16]}"
    net_id = f"net_{net_hmac[:16]}"

    return ip_id, net_id

