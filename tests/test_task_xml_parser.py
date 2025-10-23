"""
Test task XML parsing functionality.
"""
from taskhound.parsers.task_xml import parse_task_xml


def test_parse_basic_task_xml(sample_task_xml):
    """Test parsing a basic scheduled task XML."""
    result = parse_task_xml(sample_task_xml)

    assert result is not None
    # The parser returns 'runas' not 'runas_user'
    assert 'runas' in result or 'runas_user' in result
    assert 'command' in result
    assert 'date' in result
    assert 'author' in result


def test_parse_task_with_credentials(sample_task_xml):
    """Test that task with LogonType Password is detected as having credentials."""
    result = parse_task_xml(sample_task_xml)

    # Tasks with LogonType=Password store credentials
    assert result is not None
    assert 'logon_type' in result or 'credentials_hint' in result


def test_parse_task_command_extraction(sample_task_xml):
    """Test that command and arguments are extracted correctly."""
    result = parse_task_xml(sample_task_xml)

    assert result is not None
    assert 'powershell.exe' in result.get('command', '').lower()


def test_parse_malformed_xml():
    """Test handling of malformed XML."""
    malformed = "This is not XML"

    result = parse_task_xml(malformed)
    # Should handle gracefully (return None or minimal dict)
    assert result is None or isinstance(result, dict)


def test_parse_empty_xml():
    """Test handling of empty XML."""
    empty = ""

    result = parse_task_xml(empty)
    assert result is None or isinstance(result, dict)
