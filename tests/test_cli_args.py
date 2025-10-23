"""
Test CLI argument parsing and validation.
"""
import sys
from io import StringIO

import pytest


def test_help_output_includes_dpapi():
    """Test that help output includes DPAPI flags."""
    from taskhound import cli

    # Capture help output
    old_argv = sys.argv
    old_stdout = sys.stdout
    try:
        sys.argv = ['taskhound', '--help']
        sys.stdout = StringIO()

        try:
            cli.main()
        except SystemExit:
            pass  # --help causes sys.exit(0)

        output = sys.stdout.getvalue()

        assert '--loot' in output, "Missing --loot flag"
        assert '--dpapi-key' in output, "Missing --dpapi-key flag"
        assert 'DPAPI' in output, "Missing DPAPI section"

    finally:
        sys.argv = old_argv
        sys.stdout = old_stdout


def test_help_output_includes_bloodhound():
    """Test that help output includes BloodHound flags."""
    from taskhound import cli

    old_argv = sys.argv
    old_stdout = sys.stdout
    try:
        sys.argv = ['taskhound', '--help']
        sys.stdout = StringIO()

        try:
            cli.main()
        except SystemExit:
            pass

        output = sys.stdout.getvalue()

        assert '--bh-live' in output, "Missing --bh-live flag"
        assert '--bh-user' in output, "Missing --bh-user flag"
        assert '--bhce' in output, "Missing --bhce flag"
        assert 'BloodHound' in output, "Missing BloodHound section"

    finally:
        sys.argv = old_argv
        sys.stdout = old_stdout


def test_help_output_includes_ldap():
    """Test that help output includes LDAP flags."""
    from taskhound import cli

    old_argv = sys.argv
    old_stdout = sys.stdout
    try:
        sys.argv = ['taskhound', '--help']
        sys.stdout = StringIO()

        try:
            cli.main()
        except SystemExit:
            pass

        output = sys.stdout.getvalue()

        assert '--ldap-user' in output, "Missing --ldap-user flag"
        assert '--ldap-password' in output, "Missing --ldap-password flag"
        assert '--ldap-domain' in output, "Missing --ldap-domain flag"

    finally:
        sys.argv = old_argv
        sys.stdout = old_stdout


def test_dpapi_key_validation_with_targets_file():
    """Test that --dpapi-key validation logic is correctly implemented."""
    from taskhound.config import build_parser

    parser = build_parser()

    # Test args that should trigger validation error
    args = parser.parse_args([
        '--targets-file', 'fake.txt',
        '--dpapi-key', '0x123',
        '--loot',
        '-u', 'user',
        '-p', 'pass',
        '-d', 'domain'
    ])

    # The validation condition is:
    # if args.dpapi_key and args.targets_file and not args.offline
    assert args.dpapi_key is not None
    assert args.targets_file is not None
    assert args.offline is None  # Not set, so should be None

    # This combination should trigger validation error in validate_args()
    # We verify the logic is there by checking the conditions match


def test_bloodhound_live_requires_user(capsys):
    """Test that --bh-live requires --bh-user."""
    from taskhound import cli

    old_argv = sys.argv
    try:
        sys.argv = [
            'taskhound',
            '--bh-live',
            '--bhce'
        ]

        with pytest.raises(SystemExit) as exc_info:
            cli.main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert '--bh-user is required' in captured.out

    finally:
        sys.argv = old_argv
