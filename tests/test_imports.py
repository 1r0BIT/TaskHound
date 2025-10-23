"""
Test that all modules can be imported without errors.
"""
import pytest


def test_import_cli():
    """Test CLI module imports."""
    from taskhound import cli
    assert hasattr(cli, 'main')


def test_import_engine():
    """Test engine module imports."""
    from taskhound import engine
    assert hasattr(engine, 'process_target')
    assert hasattr(engine, 'process_offline_directory')


def test_import_dpapi_modules():
    """Test DPAPI module imports."""
    from taskhound.dpapi import looter
    from taskhound.dpapi import parser
    from taskhound.dpapi import decryptor
    
    assert hasattr(looter, 'loot_credentials')
    assert hasattr(parser, 'DPAPIBlobParser')
    assert hasattr(decryptor, 'DPAPIDecryptor')


def test_import_bloodhound_connector():
    """Test BloodHound connector imports."""
    from taskhound.connectors import bloodhound
    assert hasattr(bloodhound, 'connect_bloodhound')


def test_import_parsers():
    """Test parser modules."""
    from taskhound.parsers import task_xml
    from taskhound.parsers import highvalue
    
    assert hasattr(task_xml, 'parse_task_xml')
    assert hasattr(highvalue, 'HighValueLoader')


def test_import_utils():
    """Test utility modules."""
    from taskhound.utils import helpers
    from taskhound.utils import logging
    from taskhound.utils import sid_resolver
    
    # Basic smoke test - modules import without errors
    assert helpers is not None
    assert logging is not None
    assert sid_resolver is not None
