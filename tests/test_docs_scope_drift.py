"""CI drift guard: docs/security.md's scope list must match ALL_SCOPES.

docs/security.md is the page a customer reads to understand who can do what
(including who can undo containment). It previously undercounted the scopes --
"Four scopes" while the code enforces five (the missing one, ir_actions,
governs rollback). This binds the documented list to the source of truth so it
cannot silently drift again.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from src.handlers import api

_SECURITY_MD = Path(__file__).resolve().parents[1] / "docs" / "security.md"

# Number word the doc uses for the scope count, bound to len(ALL_SCOPES).
_COUNT_WORDS = {1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five", 6: "Six", 7: "Seven"}


def _doc_text() -> str:
    return _SECURITY_MD.read_text()


def test_security_md_lists_exactly_all_scopes():
    text = _doc_text()
    # "<Word> scopes exist (`read`, `rules`, ... — see ...)"
    m = re.search(r"(\w+) scopes exist \(([^)]*?)—", text)
    assert m, "could not find the 'N scopes exist (...)' sentence in docs/security.md"

    count_word, scope_segment = m.group(1), m.group(2)
    documented = set(re.findall(r"`([a-z_]+)`", scope_segment))

    assert documented == set(api.ALL_SCOPES), (
        f"docs/security.md scope list {sorted(documented)} != ALL_SCOPES "
        f"{sorted(api.ALL_SCOPES)} -- update the doc"
    )
    assert count_word == _COUNT_WORDS[len(api.ALL_SCOPES)], (
        f"docs/security.md says '{count_word} scopes' but ALL_SCOPES has "
        f"{len(api.ALL_SCOPES)} -- update the number word"
    )


def test_every_scope_is_mentioned_somewhere_in_security_md():
    text = _doc_text()
    missing = [s for s in api.ALL_SCOPES if f"`{s}`" not in text]
    assert not missing, f"scopes never mentioned in docs/security.md: {sorted(missing)}"


def test_ir_actions_rollback_scope_is_documented():
    # Regression for the specific omission: the rollback-governing scope.
    assert "ir_actions" in api.ALL_SCOPES
    assert "`ir_actions`" in _doc_text()
