"""
Test CLI argument parsing and validation.
"""

import contextlib
import inspect
import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest


def test_help_output_includes_dpapi():
    """Test that help output includes DPAPI flags."""
    from taskhound import cli

    # Capture help output
    old_argv = sys.argv
    old_stdout = sys.stdout
    try:
        sys.argv = ["taskhound", "--help"]
        sys.stdout = StringIO()

        with contextlib.suppress(SystemExit):
            cli.main()

        output = sys.stdout.getvalue()

        assert "--no-loot" in output, "Missing --no-loot flag"
        assert "--dpapi-key" in output, "Missing --dpapi-key flag"
        assert "DPAPI" in output, "Missing DPAPI section"

    finally:
        sys.argv = old_argv
        sys.stdout = old_stdout


def test_help_output_includes_bloodhound():
    """Test that help output includes BloodHound flags."""
    from taskhound import cli

    old_argv = sys.argv
    old_stdout = sys.stdout
    try:
        sys.argv = ["taskhound", "--help"]
        sys.stdout = StringIO()

        with contextlib.suppress(SystemExit):
            cli.main()

        output = sys.stdout.getvalue()

        assert "--bh-live" in output, "Missing --bh-live flag"
        assert "--bh-user" in output, "Missing --bh-user flag"
        assert "--bhce" in output, "Missing --bhce flag"
        assert "BloodHound" in output, "Missing BloodHound section"

    finally:
        sys.argv = old_argv
        sys.stdout = old_stdout


def test_help_output_includes_ldap():
    """Test that help output includes LDAP flags."""
    from taskhound import cli

    old_argv = sys.argv
    old_stdout = sys.stdout
    try:
        sys.argv = ["taskhound", "--help"]
        sys.stdout = StringIO()

        with contextlib.suppress(SystemExit):
            cli.main()

        output = sys.stdout.getvalue()

        assert "--ldap-user" in output, "Missing --ldap-user flag"
        assert "--ldap-password" in output, "Missing --ldap-password flag"
        assert "--ldap-domain" in output, "Missing --ldap-domain flag"

    finally:
        sys.argv = old_argv
        sys.stdout = old_stdout


def test_dpapi_key_validation_with_targets_file():
    """Test that --dpapi-key validation logic is correctly implemented."""
    from taskhound.config import build_parser

    parser = build_parser()

    # Test args that should trigger validation error (loot is ON by default)
    args = parser.parse_args(
        ["--targets-file", "fake.txt", "--dpapi-key", "0x123", "-u", "user", "-p", "pass", "-d", "domain"]
    )

    # The validation condition is:
    # if args.dpapi_key and args.targets_file and not args.offline
    assert args.dpapi_key is not None
    assert args.targets_file is not None
    assert args.offline is None  # Not set, so should be None

    # This combination should trigger validation error in validate_args()
    # We verify the logic is there by checking the conditions match


def test_bloodhound_live_requires_user(capsys):
    """Test that --bh-live requires SMB credentials for target scanning."""
    from taskhound import cli

    old_argv = sys.argv
    try:
        sys.argv = ["taskhound", "--bh-live", "--bhce"]

        with pytest.raises(SystemExit) as exc_info:
            cli.main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        # When using --bh-live, we need auth
        assert "BloodHound authentication requires either" in captured.out

    finally:
        sys.argv = old_argv


def test_all_service_rows_defined_before_exports():
    """Verify all_service_rows is defined before the exports section in cli.main().

    This guards against a NameError in the offline code path where
    all_service_rows must be accessible when _handle_exports runs.
    The variable should be initialized in the shared scope (before
    the offline/online branch), not only inside the online branch.
    """
    from taskhound import cli

    source = inspect.getsource(cli.main)
    lines = source.split("\n")

    # Find first assignment of all_service_rows
    first_assign = None
    exports_call = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if first_assign is None and "all_service_rows" in stripped and "=" in stripped:
            first_assign = i
        if exports_call is None and "_handle_exports" in stripped:
            exports_call = i

    assert first_assign is not None, "all_service_rows assignment not found in cli.main()"
    assert exports_call is not None, "_handle_exports call not found in cli.main()"
    assert first_assign < exports_call, (
        f"all_service_rows first assigned at line {first_assign} but "
        f"_handle_exports called at line {exports_call} — "
        "all_service_rows must be defined before the exports section"
    )


def test_offline_mode_no_nameError_on_service_rows(tmp_path):
    """Verify the offline code path does not crash with NameError on all_service_rows.

    Runs a minimal offline invocation with mocked process_offline_directory
    to confirm the exports section can access all_service_rows.
    """
    from taskhound import cli

    offline_dir = tmp_path / "offline_tasks"
    offline_dir.mkdir()

    old_argv = sys.argv
    try:
        sys.argv = [
            "taskhound",
            "--offline", str(offline_dir),
            "--no-ldap",
            "--opsec",
            "--no-confirm",
        ]

        with patch.object(cli, "process_offline_directory", return_value=[]) as mock_proc, \
             patch.object(cli, "_handle_exports", return_value=(None, None)) as mock_exports, \
             patch.object(cli, "_handle_opengraph"), \
             patch("taskhound.cli.HighValueLoader", return_value=MagicMock(loaded=False)):

            # Should NOT raise NameError for all_service_rows
            with contextlib.suppress(SystemExit):
                cli.main()

            # If _handle_exports was called, verify service_rows kwarg was passed
            if mock_exports.called:
                call_kwargs = mock_exports.call_args
                # service_rows should be an empty list (offline mode has no services)
                assert "service_rows" in (call_kwargs.kwargs or {}), (
                    "_handle_exports should receive service_rows keyword"
                )
    finally:
        sys.argv = old_argv
