from taskhound.output.printer import format_block


class TestConciseOutput:
    """Unit tests for concise output formatting."""

    def test_concise_output_format(self):
        """Verify that concise output produces a single line with expected fields."""

        # Test data
        kind = "TASK"
        rel_path = "Windows\\System32\\Tasks\\MyTask"
        runas = "DOMAIN\\User"
        what = "cmd.exe /c echo hello"
        author = "Author"
        date = "2023-01-01"

        # Call format_block with concise=True
        lines = format_block(
            kind=kind,
            rel_path=rel_path,
            runas=runas,
            what=what,
            author=author,
            date=date,
            concise=True
        )

        # Verify output
        assert len(lines) == 1
        line = lines[0]

        # Check format: [KIND] RunAs | Path | What
        assert line.startswith("[TASK]")
        assert f"{runas} | MyTask | {what}" in line

    def test_concise_output_with_reason(self):
        """Verify that concise output includes the reason if provided."""

        kind = "TIER-0"
        rel_path = "Windows\\System32\\Tasks\\AdminTask"
        runas = "DOMAIN\\Admin"
        what = "powershell.exe"
        reason = "Tier 0 Account"

        lines = format_block(
            kind=kind,
            rel_path=rel_path,
            runas=runas,
            what=what,
            author="Admin",
            date="2023-01-01",
            extra_reason=reason,
            concise=True
        )

        assert len(lines) == 1
        line = lines[0]

        assert "[TIER-0]" in line
        assert reason in line

    def test_concise_output_vs_verbose(self):
        """Verify that concise output is significantly shorter than verbose output."""

        kind = "TASK"
        rel_path = "Path"
        runas = "User"
        what = "Command"

        # Concise
        concise_lines = format_block(
            kind=kind,
            rel_path=rel_path,
            runas=runas,
            what=what,
            author="Author",
            date="Date",
            concise=True
        )

        # Verbose (default)
        verbose_lines = format_block(
            kind=kind,
            rel_path=rel_path,
            runas=runas,
            what=what,
            author="Author",
            date="Date",
            concise=False
        )

        assert len(concise_lines) == 1
        assert len(verbose_lines) > 1
