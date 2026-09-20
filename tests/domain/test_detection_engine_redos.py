"""ReDoS protection in detection_engine regex evaluation (item 1).

`matches`/`not_matches` run rule-supplied patterns via the `regex` engine with
a per-call timeout. On timeout / oversized subject / invalid pattern the match
is "could not evaluate" -> the condition is not satisfied (no hang, no spurious
detection).
"""

from src.domain import detection_engine as de
from src.domain.detection_engine import _bounded_regex_search, evaluate_condition
from src.domain.ocsf_min_parser import ApiCall, NormalizedEvent


def make_event(activity="CreateUser") -> NormalizedEvent:
    return NormalizedEvent(
        event_id="e",
        source="cloudtrail",
        time="2026-01-01T00:00:00Z",
        category="iam",
        class_name="api_activity",
        activity_name=activity,
        api=ApiCall(operation=activity),
    )


class TestRegexHappyPath:
    def test_matches_true(self):
        cond = {"field": "activity_name", "op": "matches", "value": "^Create"}
        assert evaluate_condition(make_event(), cond) is True

    def test_matches_false(self):
        cond = {"field": "activity_name", "op": "matches", "value": "^Delete"}
        assert evaluate_condition(make_event(), cond) is False

    def test_not_matches_true_when_no_match(self):
        cond = {"field": "activity_name", "op": "not_matches", "value": "^Delete"}
        assert evaluate_condition(make_event(), cond) is True

    def test_not_matches_false_when_match(self):
        cond = {"field": "activity_name", "op": "not_matches", "value": "^Create"}
        assert evaluate_condition(make_event(), cond) is False


class TestBoundedSearch:
    def test_normal_match(self):
        assert _bounded_regex_search("foo", "xfooy", "f", "matches") is True

    def test_normal_no_match(self):
        assert _bounded_regex_search("foo", "bar", "f", "matches") is False

    def test_invalid_pattern_returns_none(self):
        # Unbalanced group -- invalid in regex too.
        assert _bounded_regex_search("(", "anything", "f", "matches") is None

    def test_oversized_subject_returns_none(self, monkeypatch):
        monkeypatch.setattr(de, "_REGEX_MAX_SUBJECT_LEN", 5)
        assert _bounded_regex_search("a", "aaaaaaaa", "f", "matches") is None

    def test_timeout_returns_none(self, monkeypatch):
        def _raise(*a, **k):
            raise TimeoutError("simulated")

        monkeypatch.setattr(de.regex, "search", _raise)
        assert _bounded_regex_search("(a+)+$", "a" * 50, "f", "matches") is None


class TestTimeoutCausesNoSpuriousFire:
    def _patch_timeout(self, monkeypatch):
        def _raise(*a, **k):
            raise TimeoutError("simulated")

        monkeypatch.setattr(de.regex, "search", _raise)

    def test_matches_timeout_does_not_fire(self, monkeypatch):
        self._patch_timeout(monkeypatch)
        cond = {"field": "activity_name", "op": "matches", "value": "(a+)+$"}
        assert evaluate_condition(make_event(), cond) is False

    def test_not_matches_timeout_does_not_fire(self, monkeypatch):
        # Indeterminate must NOT be treated as "no match" -> would spuriously fire.
        self._patch_timeout(monkeypatch)
        cond = {"field": "activity_name", "op": "not_matches", "value": "(a+)+$"}
        assert evaluate_condition(make_event(), cond) is False

    def test_oversized_subject_does_not_fire(self, monkeypatch):
        monkeypatch.setattr(de, "_REGEX_MAX_SUBJECT_LEN", 3)
        cond = {"field": "activity_name", "op": "matches", "value": "Create"}
        assert evaluate_condition(make_event(), cond) is False
