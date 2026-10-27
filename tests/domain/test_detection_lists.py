import pytest

from src.domain.detection_lists import list_matches, validate_list_document


def test_exact_matcher_compares_normalized_strings():
    assert list_matches("alice", {"matcher": "exact", "values": ["alice", "bob"]})
    assert not list_matches("Alice", {"matcher": "exact", "values": ["alice"]})


def test_cidr_matcher_supports_ipv4_and_ipv6():
    snapshot = {"matcher": "cidr", "values": ["10.0.0.0/8", "2001:db8::/32"]}
    assert list_matches("10.2.3.4", snapshot)
    assert list_matches("2001:db8::5", snapshot)
    assert not list_matches("192.0.2.1", snapshot)
    assert not list_matches("not-an-ip", snapshot)


def test_validation_normalizes_cidr_and_deduplicates_values():
    result = validate_list_document(
        {
            "list_id": "corp-networks",
            "matcher": "cidr",
            "value_type": "cidr",
            "values": ["10.1.2.3/8", "10.0.0.0/8"],
        }
    )
    assert result["values"] == ["10.0.0.0/8"]


def test_validation_requires_non_empty_values_and_supported_matcher():
    with pytest.raises(ValueError, match="matcher is required"):
        validate_list_document({"list_id": "missing-matcher", "values": ["x"]})
    with pytest.raises(ValueError, match="non-empty"):
        validate_list_document({"list_id": "empty", "matcher": "exact", "values": []})
    with pytest.raises(ValueError, match="matcher"):
        validate_list_document({"list_id": "bad", "matcher": "regex", "values": ["x"]})
