"""Outbound-notification egress policy (single chokepoint).

Detections carry sensitive data (principals, ARNs, account ids, source IPs).
The generic-webhook / Slack / Discord / Jira destinations are customer-supplied
URLs, so without a policy the `settings` scope is an exfiltration channel: a
target pointed at any host receives every detection over TLS, indistinguishable
from normal operation.

`check_destination` is the one place every outbound notification funnels
through. Layers, from always-on to opt-in:

  1. HTTPS required (unchanged; raises EgressBlocked, a ValueError, so existing
     "must use HTTPS" call sites keep the same contract).
  2. Loopback / link-local IP *literals* are always refused (SSRF / metadata
     floor). Private ranges only when NOTIFY_BLOCK_PRIVATE_IPS is set. This is
     literal-only by default -- no DNS resolution, so no latency and nothing to
     mock in tests; set NOTIFY_RESOLVE_HOSTS to also resolve hostnames.
  3. Host allowlist (NOTIFY_ALLOWED_HOSTS, comma-separated). Empty = allow-all
     (today's behaviour, fully backward compatible). When configured, an
     out-of-list host is *warned and allowed* by default, and *blocked* only
     under NOTIFY_ENFORCE_ALLOWLIST -- the warn-first migration path.

Notification failure is invisible until someone notices alerts stopped, so
nothing here defaults to blocking an existing deployment's destinations.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import urllib.parse

_log = logging.getLogger(__name__)


class EgressBlocked(ValueError):
    """An outbound notification destination is not permitted by policy."""


def _flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


def _allowed_hosts() -> list[str]:
    return [
        h.strip().lower() for h in os.getenv("NOTIFY_ALLOWED_HOSTS", "").split(",") if h.strip()
    ]


def _ip_is_blocked(ip: ipaddress._BaseAddress) -> bool:
    if ip.is_loopback or ip.is_link_local:
        return True
    return _flag("NOTIFY_BLOCK_PRIVATE_IPS") and ip.is_private


def _candidate_ips(host: str) -> list[ipaddress._BaseAddress]:
    """IP literals for `host`. If host is a name, resolve only when
    NOTIFY_RESOLVE_HOSTS is set (off by default -> no DNS in the hot path)."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    if not _flag("NOTIFY_RESOLVE_HOSTS"):
        return []
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []  # resolution failed -- let the real request fail naturally
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return out


def check_destination(url: str, *, what: str = "URL") -> None:
    """Raise EgressBlocked if `url` is not a permitted notification destination.

    `what` labels the scheme error (e.g. "Slack webhook URL") to preserve
    existing operator-facing messages.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise EgressBlocked(f"{what} must use HTTPS, got: {url!r}")

    host = (parsed.hostname or "").lower()
    if not host:
        raise EgressBlocked(f"{what} has no host: {url!r}")

    for ip in _candidate_ips(host):
        if _ip_is_blocked(ip):
            raise EgressBlocked(
                f"notification destination {host!r} resolves to a blocked "
                f"(loopback/link-local/private) address {ip!r}"
            )

    allowed = _allowed_hosts()
    if allowed and not _host_matches(host, allowed):
        if _flag("NOTIFY_ENFORCE_ALLOWLIST"):
            raise EgressBlocked(
                f"notification destination host {host!r} is not in NOTIFY_ALLOWED_HOSTS"
            )
        _log.warning(
            "EGRESS_HOST_NOT_ALLOWED: notification destination host %r is not in "
            "NOTIFY_ALLOWED_HOSTS (delivered anyway -- warn-only; set "
            "NOTIFY_ENFORCE_ALLOWLIST to block)",
            host,
        )


def _host_matches(host: str, allowed: list[str]) -> bool:
    """Exact host match, or a subdomain of an allowed suffix (a.example.com ~ example.com)."""
    for a in allowed:
        if host == a or host.endswith("." + a):
            return True
    return False
