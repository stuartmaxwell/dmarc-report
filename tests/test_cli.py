"""Focused tests for the installed Rich command-line interface."""

import os
import subprocess
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

import dmarc_report
from dmarc_report.display import display_console
from dmarc_report.parser import DMARCParser, ParserLimits

REPORTS = Path(__file__).parent / "reports"


def _run_cli(filepath: Path, *, verbose: bool = False) -> subprocess.CompletedProcess[str]:
    """Run the installed command at a stable terminal width."""
    environment = os.environ.copy()
    environment.update({"COLUMNS": "160", "LINES": "50"})
    command = ["dmarc-report"]
    if verbose:
        command.append("--verbose")
    command.append(str(filepath))
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


@pytest.mark.parametrize("option", ["--version", "-V"])
def test_installed_cli_displays_package_version(option: str) -> None:
    """Return the package version without requiring a report filepath."""
    result = subprocess.run(
        ["dmarc-report", option],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == f"dmarc-report {dmarc_report.__version__}\n"
    assert result.stderr == ""


@pytest.mark.parametrize(
    "filename",
    ["dmarc-sample-1.xml", "dmarc-sample-1.xml.gz", "dmarc-sample-1.xml.zip"],
)
def test_installed_cli_renders_legacy_xml_gzip_and_zip(filename) -> None:
    """Keep all legacy attachment formats useful through the installed command."""
    result = _run_cli(REPORTS / filename)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "DMARC Report for example.com" in result.stdout
    assert "Format" in result.stdout
    assert "Legacy" in result.stdout
    assert "Policy (p)" in result.stdout
    assert "quarantine" in result.stdout
    assert "Sampling (pct)" in result.stdout
    assert "100%" in result.stdout
    assert "DKIM pass example.com selector=default" in result.stdout
    assert "SPF pass example.com scope=mfrom" in result.stdout
    assert "Parser Warnings" not in result.stdout
    assert "legacy_no_namespace" not in result.stdout


def test_installed_cli_verbose_renders_parser_warnings() -> None:
    """Show tolerated parser deviations only when verbose output is requested."""
    result = _run_cli(REPORTS / "dmarc-sample-1.xml", verbose=True)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Parser Warnings" in result.stdout
    assert "legacy_no_namespace" in result.stdout
    assert "legacy_missing_version" in result.stdout


def test_installed_cli_renders_rfc9990_fields_authentication_and_warnings() -> None:
    """Show current-only fields without inventing a legacy sampling percentage."""
    result = _run_cli(REPORTS / "rfc9990-sample.xml")

    assert result.returncode == 0
    assert result.stderr == ""
    assert "RFC 9990" in result.stdout
    assert "urn:ietf:params:xml:ns:dmarc-2.0" in result.stdout
    assert "Example DMARC Aggregate Reporter v1.2" in result.stdout
    assert "One policy lookup was temporarily unavailable." in result.stdout
    assert "Nonexistent (np)" in result.stdout
    assert "Testing (t)" in result.stdout
    assert "Discovery method" in result.stdout
    assert "treewalk" in result.stdout
    assert "Sampling (pct)" not in result.stdout
    assert "DKIM pass example.com selector=abc123" in result.stdout
    assert "SPF softfail bounce.example.com scope=mfrom" in result.stdout
    assert "Override policy_test_mode" in result.stdout
    assert "none reported" in result.stdout
    assert "Parser Warnings" not in result.stdout


def test_installed_cli_renders_legacy_np_extension_and_warning() -> None:
    """Make the retained legacy np extension visible rather than silently ignoring it."""
    result = _run_cli(REPORTS / "legacy-np-extension.xml", verbose=True)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Legacy" in result.stdout
    assert "Nonexistent (np)" in result.stdout
    assert "reject" in result.stdout
    assert "legacy_np_extension" in result.stdout
    assert "<np> policy extension was retained" in result.stdout


def test_display_handles_missing_legacy_optional_fields() -> None:
    """Do not dereference missing contact, selector, scope, or policy fields."""
    report = DMARCParser.parse_file(REPORTS / "dmarc-sample-3.xml")
    output = StringIO()
    console = Console(file=output, force_terminal=False, color_system=None, width=160)

    display_console(report, console=console)

    rendered = output.getvalue()
    assert "DMARC Report for example.net" in rendered
    assert "Extra contact" not in rendered
    assert "Generator" not in rendered
    assert "DKIM fail example.net" in rendered
    assert "SPF fail example.net" in rendered


def test_display_aligns_detail_table_columns() -> None:
    """Keep metadata, policy, and summary dividers at the same position."""
    report = DMARCParser.parse_file(REPORTS / "dmarc-sample-3.xml")
    output = StringIO()
    console = Console(file=output, force_terminal=False, color_system=None, width=120)

    display_console(report, console=console)

    lines = output.getvalue().splitlines()
    divider_positions = []
    for label in ("Format", "Domain", "Total messages"):
        row = next(line for line in lines if label in line)
        divider_positions.append(row.index("│", row.index(label) + len(label)))
    assert len(set(divider_positions)) == 1


@pytest.mark.parametrize(
    ("filename", "error_code"),
    [
        ("dmarc-invalid-4.xml", "invalid_xml"),
        ("multiple_reports.zip", "archive_report_ambiguous"),
    ],
)
def test_cli_malformed_inputs_are_concise(filename, error_code) -> None:
    """Return a stable error without a default traceback for malformed content."""
    result = _run_cli(REPORTS / filename)

    assert result.returncode == 1
    assert result.stdout == ""
    assert "Error:" in result.stderr
    assert "Failed to process" in result.stderr
    assert error_code in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_unsupported_report_is_concise(tmp_path: Path) -> None:
    """Show unsupported namespace failures without a traceback."""
    report_file = tmp_path / "unsupported.xml"
    report_file.write_text('<feedback xmlns="urn:example:unsupported"/>', encoding="utf-8")

    result = _run_cli(report_file)

    assert result.returncode == 1
    assert result.stdout == ""
    assert "unsupported XML namespace" in result.stderr
    assert "[unsupported_report]" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_oversized_report_is_concise(tmp_path: Path) -> None:
    """Apply default input limits through the command entry point."""
    report_file = tmp_path / "oversized.xml"
    report_file.write_bytes(b"x" * (ParserLimits().max_input_bytes + 1))

    result = _run_cli(report_file)

    assert result.returncode == 1
    assert result.stdout == ""
    assert "input_limit_exceeded" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_missing_file_is_concise(tmp_path: Path) -> None:
    """Return a clear nonzero result when the requested path is absent."""
    result = _run_cli(tmp_path / "missing.xml")

    assert result.returncode == 1
    assert result.stdout == ""
    assert "Error: File not found:" in result.stderr
    assert "Traceback" not in result.stderr
