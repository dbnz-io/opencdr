"""Shared fixtures for tests/handlers/."""
from __future__ import annotations

import pytest

from src.handlers import api


@pytest.fixture(autouse=True)
def _default_full_scope_api_key(monkeypatch):
    """
    Route-level API key scoping (src/handlers/api.py's _get_key_scopes)
    gates every route but /status and /help behind a resolved key scope.
    Every test under tests/handlers/ that calls api.lambda_handler
    predates scoping and builds events with no requestContext.identity.
    apiKeyId at all -- default every call here to a full-access key so
    none of them need to know scoping exists.
    tests/handlers/test_api.py's TestApiKeyScoping and related classes
    override this per-test to prove enforcement actually works.
    """
    monkeypatch.setattr(api, "_get_key_scopes", lambda api_key_id: api.ALL_SCOPES)
