"""
SSRF (Server-Side Request Forgery) protection utilities for LLMGuard.
Validates URLs and resolved network destinations to prevent exfiltration,
internal subnet pivoting, and cloud metadata access.
"""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional


BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # Broadcast / this host
    ipaddress.ip_network("10.0.0.0/8"),        # Private network RFC 1918
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),     # Private network RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),    # Private network RFC 1918
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("::/128"),            # Unspecified IPv6
    ipaddress.ip_network("::1/128"),           # Loopback IPv6
    ipaddress.ip_network("fc00::/7"),          # Unique local address IPv6
    ipaddress.ip_network("fe80::/10"),         # Link-local IPv6
    ipaddress.ip_network("ff00::/8"),          # Multicast IPv6
]


def is_ip_blocked(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Check whether an IP address belongs to a prohibited or private subnet."""
    if ip_obj.is_loopback:
        return True, "Loopback destination is blocked (SSRF protection)."
    if ip_obj.is_private:
        return True, "Private/internal RFC1918 address is blocked (SSRF protection)."
    if ip_obj.is_link_local:
        return True, "Link-local / cloud metadata address is blocked (SSRF protection)."
    if ip_obj.is_multicast:
        return True, "Multicast address is blocked."
    if ip_obj.is_reserved:
        return True, "Reserved IP space is blocked."
    if ip_obj.is_unspecified:
        return True, "Unspecified IP address is blocked."

    for net in BLOCKED_IP_NETWORKS:
        if ip_obj in net:
            return True, f"Destination belongs to restricted network range {net}."

    return False, ""


def validate_url_ssrf(url: str, allow_local_network: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validates a URL against SSRF rules.
    Returns (is_valid, error_reason).
    """
    if not url or not isinstance(url, str):
        return False, "Target URL must be a non-empty string."

    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()

    if scheme not in ("http", "https"):
        return False, f"Invalid URL scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "URL does not contain a valid hostname."

    # If local network is explicitly permitted for development, allow standard loopback/private destinations
    if allow_local_network:
        return True, None

    # Check blocked hostname words
    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".local") or hostname.endswith(".internal"):
        return False, f"Hostname '{hostname}' resolves to a restricted internal domain (SSRF protection)."

    # Try interpreting directly as IP address
    try:
        ip_obj = ipaddress.ip_address(hostname)
        blocked, reason = is_ip_blocked(ip_obj)
        if blocked:
            return False, reason
        return True, None
    except ValueError:
        pass

    # Resolve DNS to check resulting IPs
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        if not addr_info:
            return False, f"Could not resolve hostname '{hostname}'."

        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                blocked, reason = is_ip_blocked(ip_obj)
                if blocked:
                    return False, f"Destination '{hostname}' resolves to restricted IP {ip_str} ({reason})."
            except ValueError:
                continue

    except socket.gaierror as e:
        return False, f"DNS resolution failed for '{hostname}': {e}"
    except Exception as e:
        return False, f"Network destination verification error: {e}"

    return True, None
