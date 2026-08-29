"""
Test suite for console utility functions.

Tests cover:
- status message functions (good, warn, error, info)
- verbosity control functions
- print_banner function
"""

from unittest.mock import patch

import pytest

from taskhound.utils import console
from taskhound.utils.console import (
    _is_debug,
    _is_verbose,
    debug,
    error,
    good,
    info,
    print_banner,
    set_verbosity,
    status,
    warn,
)

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture(autouse=True)
def reset_verbosity():
    """Reset verbosity flags before each test"""
    set_verbosity(False, False)
    yield
    set_verbosity(False, False)


# ============================================================================
# Test: print_banner
# ============================================================================


class TestPrintBanner:
    """Tests for print_banner function"""

    @patch.object(console, 'console')
    def test_prints_banner(self, mock_console):
        """Should print the banner"""
        print_banner()

        mock_console.print.assert_called_once()
        call_args = mock_console.print.call_args[0][0]
        # Banner is ASCII art spelling out letters
        assert "TTTTT" in call_args  # Part of ASCII art

    @patch.object(console, 'console')
    def test_banner_includes_author(self, mock_console):
        """Should include author in banner"""
        print_banner()

        call_args = mock_console.print.call_args[0][0]
        assert "0xr0BIT" in call_args


# ============================================================================
# Test: Status Messages
# ============================================================================


class TestStatusMessages:
    """Tests for status message functions"""

    @patch.object(console, 'console')
    def test_status_prints_message(self, mock_console):
        """Should print status message"""
        status("Test status message")

        mock_console.print.assert_called_once_with("Test status message")

    @patch.object(console, 'console')
    def test_good_prints_green(self, mock_console):
        """Should print good message with green prefix"""
        good("Success message")

        mock_console.print.assert_called_once()
        call_args = mock_console.print.call_args[0][0]
        assert "[green]" in call_args
        assert "[+]" in call_args
        assert "Success message" in call_args

    @patch.object(console, 'console')
    def test_good_verbose_only_not_printed(self, mock_console):
        """Should not print verbose_only good message when not verbose"""
        good("Verbose message", verbose_only=True)

        mock_console.print.assert_not_called()

    @patch.object(console, 'console')
    def test_good_verbose_only_printed_when_verbose(self, mock_console):
        """Should print verbose_only good message when verbose"""
        set_verbosity(True, False)
        good("Verbose message", verbose_only=True)

        mock_console.print.assert_called_once()

    @patch.object(console, 'console')
    def test_warn_prints_yellow(self, mock_console):
        """Should print warning message with yellow prefix"""
        warn("Warning message")

        mock_console.print.assert_called_once()
        call_args = mock_console.print.call_args[0][0]
        assert "[yellow]" in call_args
        assert "[!]" in call_args
        assert "Warning message" in call_args

    @patch.object(console, 'console')
    def test_error_prints_red(self, mock_console):
        """Should print error message with red prefix"""
        error("Error message")

        mock_console.print.assert_called_once()
        call_args = mock_console.print.call_args[0][0]
        assert "[red]" in call_args
        assert "[-]" in call_args
        assert "Error message" in call_args

    @patch.object(console, 'console')
    def test_info_prints_blue(self, mock_console):
        """Should print info message with blue prefix"""
        info("Info message")

        mock_console.print.assert_called_once()
        call_args = mock_console.print.call_args[0][0]
        assert "[blue]" in call_args
        assert "[*]" in call_args
        assert "Info message" in call_args

    @patch.object(console, 'console')
    def test_info_verbose_only_not_printed(self, mock_console):
        """Should not print verbose_only info message when not verbose"""
        info("Verbose info", verbose_only=True)

        mock_console.print.assert_not_called()

    @patch.object(console, 'console')
    def test_info_verbose_only_printed_when_verbose(self, mock_console):
        """Should print verbose_only info message when verbose"""
        set_verbosity(True, False)
        info("Verbose info", verbose_only=True)

        mock_console.print.assert_called_once()


# ============================================================================
# Test: Debug Messages
# ============================================================================


class TestDebugMessages:
    """Tests for debug message function"""

    @patch.object(console, 'console')
    def test_debug_not_printed_when_not_debug(self, mock_console):
        """Should not print debug message when debug disabled"""
        debug("Debug message")

        mock_console.print.assert_not_called()

    @patch.object(console, 'console')
    def test_debug_printed_when_debug_enabled(self, mock_console):
        """Should print debug message when debug enabled"""
        set_verbosity(False, True)
        debug("Debug message")

        mock_console.print.assert_called_once()
        call_args = mock_console.print.call_args[0][0]
        assert "[DEBUG]" in call_args
        assert "Debug message" in call_args

    @patch.object(console, 'console')
    def test_debug_with_exc_info(self, mock_console):
        """Should print exception info when exc_info=True"""
        set_verbosity(False, True)
        debug("Debug with exception", exc_info=True)

        assert mock_console.print.call_count == 1
        mock_console.print_exception.assert_called_once()


# ============================================================================
# Test: Verbosity Control
# ============================================================================


class TestVerbosityControl:
    """Tests for verbosity control functions"""

    def test_set_verbosity_verbose(self):
        """Should set verbose flag"""
        set_verbosity(True, False)

        assert _is_verbose() is True
        assert _is_debug() is False

    def test_set_verbosity_debug(self):
        """Should set debug flag"""
        set_verbosity(False, True)

        assert _is_verbose() is True  # debug implies verbose
        assert _is_debug() is True

    def test_set_verbosity_both(self):
        """Should set both flags"""
        set_verbosity(True, True)

        assert _is_verbose() is True
        assert _is_debug() is True

    def test_set_verbosity_neither(self):
        """Should clear both flags"""
        set_verbosity(True, True)
        set_verbosity(False, False)

        assert _is_verbose() is False
        assert _is_debug() is False

    def test_is_verbose_true_when_debug(self):
        """_is_verbose should return True when debug is enabled"""
        set_verbosity(False, True)

        assert _is_verbose() is True


# ============================================================================
# ============================================================================

