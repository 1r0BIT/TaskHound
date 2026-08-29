"""
Date parsing utilities for TaskHound.

This module provides centralized date parsing logic to handle various formats
encountered in Windows Task Scheduler XML and BloodHound data.
"""

from datetime import UTC, datetime


def parse_timestamp(timestamp_value: str | int | float | None) -> datetime | None:
    """
    Convert various timestamp formats to datetime.
    Supports Windows FILETIME, Unix timestamps, and string representations.
    Returns None if conversion fails or timestamp is 0/invalid.
    """
    if not timestamp_value:
        return None

    if isinstance(timestamp_value, str):
        if timestamp_value.strip() == "" or timestamp_value == "0":
            return None
        try:
            timestamp = float(timestamp_value)
        except ValueError:
            return None
    else:
        timestamp = float(timestamp_value)

    if timestamp == 0:
        return None

    try:
        # Detect format based on magnitude
        # Windows FILETIME is very large (> 100 billion for dates after 1970)
        # Unix timestamp is smaller (< 10 billion for dates before 2286)
        if timestamp > 10000000000:  # Likely Windows FILETIME
            # Windows FILETIME epoch: January 1, 1601 00:00:00 UTC
            # Convert 100-nanosecond intervals to seconds
            unix_timestamp = (timestamp - 116444736000000000) / 10000000.0
            return datetime.fromtimestamp(unix_timestamp, tz=UTC)
        else:  # Likely Unix timestamp
            return datetime.fromtimestamp(timestamp, tz=UTC)

    except (ValueError, OSError, OverflowError):
        return None


def parse_iso_date(date_str: str) -> datetime | None:
    """
    Parse ISO 8601 date strings with various formats.
    Handles 'Z' suffix, timezone offsets, and missing timezones.
    Always returns timezone-aware datetime (UTC if not specified).
    """
    if not date_str:
        return None

    try:
        # Handle 'Z' suffix for UTC
        if date_str.endswith("Z"):
            # Replace Z with +00:00 for fromisoformat compatibility in older Python versions
            # (though Python 3.11+ handles Z natively, we want to be robust)
            clean_str = date_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
        elif "+" in date_str or date_str.count("-") > 2:
            # Likely has timezone offset already
            dt = datetime.fromisoformat(date_str)
        else:
            # Naive datetime, assume UTC
            dt = datetime.fromisoformat(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)

        return dt
    except (ValueError, TypeError):
        return None


# Windows FILETIME epoch difference from Unix epoch
# FILETIME epoch: January 1, 1601
# Unix epoch: January 1, 1970
# Difference: 11644473600 seconds
_FILETIME_EPOCH_DIFF = 11644473600


def parse_ad_timestamp(timestamp: int) -> datetime | None:
    """
    Parse AD timestamp (100-nanosecond intervals since January 1, 1601).

    Used in LAPS expiration times, AD account expiration, password last set, etc.

    Args:
        timestamp: Integer timestamp from AD attribute

    Returns:
        datetime object or None if parsing fails or timestamp indicates "never"
    """
    try:
        # Special values that indicate "never expires" or not set
        if timestamp == 0 or timestamp == 9223372036854775807:
            return None

        unix_timestamp = (timestamp / 10_000_000) - _FILETIME_EPOCH_DIFF
        return datetime.fromtimestamp(unix_timestamp, tz=UTC)
    except (ValueError, OSError, OverflowError):
        return None


def parse_filetime_hex(filetime_hex: str) -> datetime | None:
    """
    Parse Windows FILETIME from hex string.

    Windows FILETIME is 100-nanosecond intervals since January 1, 1601.
    Often found in JSON attributes like msLAPS-Password.

    Args:
        filetime_hex: Hex string representing FILETIME (e.g., "1d9a2b3c...")

    Returns:
        datetime object or None if parsing fails
    """
    try:
        # Convert hex to integer
        filetime = int(filetime_hex, 16)

        # Convert to Unix timestamp
        unix_timestamp = (filetime / 10_000_000) - _FILETIME_EPOCH_DIFF

        return datetime.fromtimestamp(unix_timestamp, tz=UTC)
    except (ValueError, OSError, OverflowError):
        return None
