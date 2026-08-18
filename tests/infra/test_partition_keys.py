"""Tests for src/infra/partition_keys.py's day_bucket_key()."""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from src.infra.partition_keys import day_bucket_key


class TestDayBucketKey:
    def test_basic_format(self):
        assert day_bucket_key("HIGH", "2026-08-12T14:30:00Z") == "HIGH#2026-08-12"

    def test_offset_timestamp(self):
        assert day_bucket_key("OPENCDR-API", "2026-08-12T23:59:59+05:00") == "OPENCDR-API#2026-08-12"

    def test_utc_midnight_boundary(self):
        # 23:59:59 UTC on the 11th stays on the 11th, not the 12th.
        assert day_bucket_key("LOW", "2026-08-11T23:59:59Z") == "LOW#2026-08-11"
        assert day_bucket_key("LOW", "2026-08-12T00:00:00Z") == "LOW#2026-08-12"

    def test_missing_prefix_falls_back_to_unknown(self):
        assert day_bucket_key(None, "2026-08-12T00:00:00Z") == "UNKNOWN#2026-08-12"
        assert day_bucket_key("", "2026-08-12T00:00:00Z") == "UNKNOWN#2026-08-12"

    def test_missing_timestamp_falls_back_to_now(self):
        fixed_now = datetime(2026, 8, 12, 10, 0, 0, tzinfo=UTC)
        with patch("src.infra.partition_keys.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_now
            mock_dt.fromisoformat.side_effect = ValueError("bad format")
            assert day_bucket_key("HIGH", None) == "HIGH#2026-08-12"
            assert day_bucket_key("HIGH", "not-a-timestamp") == "HIGH#2026-08-12"

    def test_malformed_timestamp_does_not_raise(self):
        # No mocking -- a genuinely garbage string must still produce a
        # usable bucket key, not propagate an exception into the caller
        # (a partition-key problem must never be able to block a write).
        result = day_bucket_key("HIGH", "definitely not iso format")
        assert result.startswith("HIGH#")
        assert len(result) == len("HIGH#YYYY-MM-DD")
