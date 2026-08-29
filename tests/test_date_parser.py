"""
Test date parsing utilities.
"""

from datetime import UTC

from taskhound.utils.date_parser import (
    _FILETIME_EPOCH_DIFF,
    parse_ad_timestamp,
    parse_filetime_hex,
    parse_iso_date,
    parse_timestamp,
)


class TestDateParser:
    def test_parse_timestamp_unix(self):
        """Test parsing Unix timestamps."""
        # 2023-01-01 00:00:00 UTC
        ts = 1672531200
        dt = parse_timestamp(ts)
        assert dt.year == 2023
        assert dt.month == 1
        assert dt.day == 1
        assert dt.tzinfo == UTC

    def test_parse_timestamp_windows(self):
        """Test parsing Windows FILETIME."""
        # 2023-01-01 00:00:00 UTC in FILETIME
        # (1672531200 + 11644473600) * 10000000
        ts = 133170048000000000
        dt = parse_timestamp(ts)
        assert dt.year == 2023
        assert dt.month == 1
        assert dt.day == 1
        assert dt.tzinfo == UTC

    def test_parse_timestamp_string(self):
        """Test parsing string timestamps."""
        assert parse_timestamp("1672531200").year == 2023
        assert parse_timestamp("133170048000000000").year == 2023

    def test_parse_timestamp_invalid(self):
        """Test parsing invalid timestamps."""
        assert parse_timestamp(None) is None
        assert parse_timestamp("") is None
        assert parse_timestamp("0") is None
        assert parse_timestamp(0) is None
        assert parse_timestamp("invalid") is None

    def test_parse_timestamp_zero_float_string(self):
        """Test parsing '0.0' string triggers numeric zero check."""
        # This is truthy string but converts to 0.0
        assert parse_timestamp("0.0") is None
        # Also test other zero variants
        assert parse_timestamp("0.00") is None
        assert parse_timestamp(" 0.0 ") is None

    def test_parse_timestamp_overflow(self):
        """Test that overflow errors are handled."""
        # Very large timestamp that would cause overflow
        huge = 10 ** 30
        assert parse_timestamp(huge) is None

    def test_parse_iso_date_basic(self):
        """Test parsing basic ISO dates."""
        dt = parse_iso_date("2023-01-01T12:00:00")
        assert dt.year == 2023
        assert dt.hour == 12
        assert dt.tzinfo == UTC

    def test_parse_iso_date_z_suffix(self):
        """Test parsing ISO dates with Z suffix."""
        dt = parse_iso_date("2023-01-01T12:00:00Z")
        assert dt.year == 2023
        assert dt.hour == 12
        assert dt.tzinfo == UTC

    def test_parse_iso_date_timezone(self):
        """Test parsing ISO dates with timezone offset."""
        dt = parse_iso_date("2023-01-01T12:00:00+01:00")
        assert dt.year == 2023
        assert dt.hour == 12
        # Should preserve timezone info
        assert dt.utcoffset().total_seconds() == 3600

    def test_parse_iso_date_invalid(self):
        """Test parsing invalid ISO dates."""
        assert parse_iso_date(None) is None
        assert parse_iso_date("") is None
        assert parse_iso_date("invalid") is None


class TestParseAdTimestamp:
    """Tests for parse_ad_timestamp function."""

    def test_parse_ad_timestamp_valid(self):
        """Test parsing valid AD timestamp."""
        # AD timestamp for Jan 1, 2024
        ad_timestamp = (1704067200 + _FILETIME_EPOCH_DIFF) * 10_000_000
        result = parse_ad_timestamp(ad_timestamp)
        assert result is not None
        assert result.year == 2024

    def test_parse_ad_timestamp_zero_returns_none(self):
        """Test parsing zero returns None."""
        assert parse_ad_timestamp(0) is None

    def test_parse_ad_timestamp_never_expires(self):
        """Test parsing 'never expires' value returns None."""
        # Special value indicating never expires
        assert parse_ad_timestamp(9223372036854775807) is None

    def test_parse_ad_timestamp_overflow_returns_none(self):
        """Test parsing value that causes overflow returns None."""
        # Very large value that would cause overflow
        result = parse_ad_timestamp(999999999999999999999999999999)
        assert result is None

    def test_result_is_utc_aware(self):
        """Test result is timezone-aware UTC."""
        ad_timestamp = (1704067200 + _FILETIME_EPOCH_DIFF) * 10_000_000
        result = parse_ad_timestamp(ad_timestamp)
        assert result is not None
        assert result.tzinfo == UTC


class TestParseFiletimeHex:
    """Tests for parse_filetime_hex function."""

    def test_parse_filetime_hex_valid(self):
        """Test parsing valid FILETIME hex string."""
        # Create hex representation for known timestamp
        filetime = (1704067200 + _FILETIME_EPOCH_DIFF) * 10_000_000
        hex_str = format(filetime, 'x')
        result = parse_filetime_hex(hex_str)
        assert result is not None
        assert result.year == 2024

    def test_parse_filetime_hex_uppercase(self):
        """Test parsing FILETIME hex string uppercase."""
        filetime = (1704067200 + _FILETIME_EPOCH_DIFF) * 10_000_000
        hex_str = format(filetime, 'X')
        result = parse_filetime_hex(hex_str)
        assert result is not None

    def test_parse_filetime_hex_with_prefix(self):
        """Test parsing FILETIME hex string with 0x prefix."""
        filetime = (1704067200 + _FILETIME_EPOCH_DIFF) * 10_000_000
        hex_str = "0x" + format(filetime, 'x')
        result = parse_filetime_hex(hex_str)
        assert result is not None

    def test_parse_filetime_hex_invalid_returns_none(self):
        """Test parsing invalid hex returns None."""
        assert parse_filetime_hex("not_hex") is None
        assert parse_filetime_hex("zzzzz") is None

    def test_parse_filetime_hex_overflow_returns_none(self):
        """Test parsing hex that causes overflow returns None."""
        # Create a very large hex that would overflow
        result = parse_filetime_hex("ffffffffffffffffffffffff")
        assert result is None

    def test_result_is_utc_aware(self):
        """Test result is timezone-aware UTC."""
        filetime = (1704067200 + _FILETIME_EPOCH_DIFF) * 10_000_000
        hex_str = format(filetime, 'x')
        result = parse_filetime_hex(hex_str)
        assert result is not None
        assert result.tzinfo == UTC


class TestFiletimeEpochDiff:
    """Tests for FILETIME epoch difference constant."""

    def test_epoch_diff_value(self):
        """Test FILETIME epoch diff has correct value."""
        # Difference between Jan 1, 1601 and Jan 1, 1970 in seconds
        # 369 years, accounting for leap years
        assert _FILETIME_EPOCH_DIFF == 11644473600

    def test_epoch_diff_calculation(self):
        """Test epoch diff is used correctly in calculations."""
        # Known Unix timestamp
        unix_ts = 0  # Jan 1, 1970
        # Corresponding AD timestamp
        ad_ts = (unix_ts + _FILETIME_EPOCH_DIFF) * 10_000_000
        result = parse_ad_timestamp(ad_ts)
        assert result is not None
        assert result.year == 1970
        assert result.month == 1
        assert result.day == 1
