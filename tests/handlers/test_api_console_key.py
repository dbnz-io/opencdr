"""Discriminated console API key + bare-key deprecation (item 3).

The DBNZ control plane should hold a named, independently revocable key rather
than the bare all-scopes key. The `console` discriminator token is ignored by
`tokens & ALL_SCOPES`, so the key carries the same five scopes but is
attributable; the bare key logs a deprecation marker on use.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import api

_SERVERLESS = Path(__file__).resolve().parents[2] / "serverless.yml"
_CONSOLE_SUFFIX = "console-read-rules-settings-ir_roles-ir_actions"


def _console_key_name() -> str:
    return f"{api._API_KEY_NAME_PREFIX}-{_CONSOLE_SUFFIX}"


def test_console_key_carries_all_scopes_discriminator_ignored():
    assert api._scopes_from_key_name(_console_key_name()) == api.ALL_SCOPES


def test_console_key_is_minted_in_serverless():
    text = _SERVERLESS.read_text()
    assert f"api-key-{_CONSOLE_SUFFIX}" in text, (
        "console key not declared in serverless.yml apiKeys"
    )


def test_bare_key_still_all_scopes_and_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="src.handlers.api"):
        scopes = api._scopes_from_key_name(api._API_KEY_NAME_PREFIX)
    assert scopes == api.ALL_SCOPES
    assert any("DEPRECATED_BARE_API_KEY_USED" in r.message for r in caplog.records)


def test_named_keys_do_not_warn(caplog):
    with caplog.at_level(logging.WARNING, logger="src.handlers.api"):
        api._scopes_from_key_name(_console_key_name())
        api._scopes_from_key_name(f"{api._API_KEY_NAME_PREFIX}-read-rules")
    assert not any("DEPRECATED_BARE_API_KEY_USED" in r.message for r in caplog.records)


def test_unrecognized_key_still_fails_closed():
    assert api._scopes_from_key_name("totally-unrelated-key") == frozenset()
