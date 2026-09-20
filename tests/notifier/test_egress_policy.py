"""Egress policy for outbound notifications (item 2).

Backward compatible by default (allow-all except the loopback/link-local IP
floor and the existing HTTPS requirement); the host allowlist is opt-in and
warn-first.
"""

from __future__ import annotations

import logging

import pytest

from src.notifier import egress_policy
from src.notifier.egress_policy import EgressBlocked, check_destination


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "NOTIFY_ALLOWED_HOSTS",
        "NOTIFY_ENFORCE_ALLOWLIST",
        "NOTIFY_BLOCK_PRIVATE_IPS",
        "NOTIFY_RESOLVE_HOSTS",
    ):
        monkeypatch.delenv(var, raising=False)


class TestHttpsFloor:
    def test_http_blocked_with_https_message(self):
        with pytest.raises(ValueError, match="HTTPS"):
            check_destination("http://hooks.slack.com/x")

    def test_egress_blocked_is_a_valueerror(self):
        assert issubclass(EgressBlocked, ValueError)

    def test_what_label_is_used(self):
        with pytest.raises(ValueError, match="Slack webhook URL must use HTTPS"):
            check_destination("http://x", what="Slack webhook URL")

    def test_https_normal_host_allowed(self):
        check_destination("https://hooks.slack.com/services/T/B/x")  # no raise


class TestIpFloor:
    def test_loopback_literal_blocked(self):
        with pytest.raises(EgressBlocked, match="loopback"):
            check_destination("https://127.0.0.1/x")

    def test_link_local_metadata_literal_blocked(self):
        with pytest.raises(EgressBlocked):
            check_destination("https://169.254.169.254/latest/meta-data/")

    def test_private_allowed_by_default(self):
        check_destination("https://10.0.0.5/hook")  # no raise unless opted in

    def test_private_blocked_when_opted_in(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_BLOCK_PRIVATE_IPS", "true")
        with pytest.raises(EgressBlocked):
            check_destination("https://10.0.0.5/hook")


class TestAllowlist:
    def test_empty_allowlist_allows_any_host(self):
        check_destination("https://anything.example.net/x")  # no raise

    def test_out_of_list_warns_and_allows_by_default(self, monkeypatch, caplog):
        monkeypatch.setenv("NOTIFY_ALLOWED_HOSTS", "hooks.slack.com")
        with caplog.at_level(logging.WARNING, logger="src.notifier.egress_policy"):
            check_destination("https://evil.example.com/x")  # allowed
        assert any("EGRESS_HOST_NOT_ALLOWED" in r.message for r in caplog.records)

    def test_out_of_list_blocked_when_enforced(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_ALLOWED_HOSTS", "hooks.slack.com")
        monkeypatch.setenv("NOTIFY_ENFORCE_ALLOWLIST", "true")
        with pytest.raises(EgressBlocked, match="not in NOTIFY_ALLOWED_HOSTS"):
            check_destination("https://evil.example.com/x")

    def test_in_list_host_passes_when_enforced(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_ALLOWED_HOSTS", "hooks.slack.com, discord.com")
        monkeypatch.setenv("NOTIFY_ENFORCE_ALLOWLIST", "true")
        check_destination("https://hooks.slack.com/x")  # no raise
        check_destination("https://discord.com/api/webhooks/1/2")  # no raise

    def test_subdomain_of_allowed_suffix_passes(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_ALLOWED_HOSTS", "example.com")
        monkeypatch.setenv("NOTIFY_ENFORCE_ALLOWLIST", "true")
        check_destination("https://hooks.example.com/x")  # no raise

    def test_similar_but_not_subdomain_blocked(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_ALLOWED_HOSTS", "example.com")
        monkeypatch.setenv("NOTIFY_ENFORCE_ALLOWLIST", "true")
        with pytest.raises(EgressBlocked):
            check_destination("https://notexample.com/x")


class TestHostnameResolution:
    def test_hostname_not_resolved_by_default(self, monkeypatch):
        # Even a name that would resolve to loopback is allowed when resolution
        # is off (default) -- literal-only floor, no DNS in the hot path.
        called = {"n": 0}

        def _boom(*a, **k):
            called["n"] += 1
            raise AssertionError("getaddrinfo should not be called by default")

        monkeypatch.setattr(egress_policy.socket, "getaddrinfo", _boom)
        check_destination("https://localhost.example.test/x")
        assert called["n"] == 0

    def test_hostname_resolved_and_blocked_when_opted_in(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_RESOLVE_HOSTS", "true")

        def _fake_resolve(host, *a, **k):
            return [(2, 1, 6, "", ("127.0.0.1", 0))]

        monkeypatch.setattr(egress_policy.socket, "getaddrinfo", _fake_resolve)
        with pytest.raises(EgressBlocked, match="loopback|blocked"):
            check_destination("https://sneaky.example.com/x")

    def test_resolution_failure_is_fail_open(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_RESOLVE_HOSTS", "true")

        def _fail(*a, **k):
            raise OSError("dns down")

        monkeypatch.setattr(egress_policy.socket, "getaddrinfo", _fail)
        check_destination("https://host.example.com/x")  # no raise -- request fails naturally later
