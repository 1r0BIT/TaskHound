"""
Test DPAPI blob parsing functionality.
"""
from taskhound.dpapi.parser import DPAPIBlobParser


def test_parser_initialization():
    """Test DPAPIBlobParser can be instantiated."""
    parser = DPAPIBlobParser()
    assert parser is not None
    assert parser.parsed_blobs == []


def test_parse_blob_too_small():
    """Test that blobs smaller than 16 bytes are rejected."""
    parser = DPAPIBlobParser()
    small_blob = b'\x00' * 8

    result = parser.parse_blob(small_blob)
    assert result is None


def test_parse_blob_valid_structure():
    """Test parsing a minimal valid DPAPI blob structure."""
    parser = DPAPIBlobParser()

    # Create minimal valid blob: version (4) + reserved (8) + minimal data
    blob = b'\x02\x00\x00\x00'  # version 2
    blob += b'\x00' * 8           # reserved
    blob += b'test'               # some data

    result = parser.parse_blob(blob)
    assert result is not None
    assert result['version'] == 2
    assert result['total_size'] == len(blob)


def test_algorithm_name_lookup():
    """Test algorithm ID to name conversion."""
    parser = DPAPIBlobParser()

    assert 'AES_256' in parser._algorithm_name(0x6610)
    assert '3DES' in parser._algorithm_name(0x6609)
    assert 'Unknown' in parser._algorithm_name(0x9999)


def test_analyze_blob_collection():
    """Test collection analysis with multiple blobs."""
    parser = DPAPIBlobParser()

    # Create test blob files list (empty for now)
    analysis = parser.analyze_blob_collection([])

    assert analysis['total_blobs'] == 0
    assert analysis['successfully_parsed'] == 0
    assert isinstance(analysis['credential_guids'], list)
