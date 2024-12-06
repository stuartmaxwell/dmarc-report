"""Tests for the reports module."""

from pathlib import Path
import subprocess
import pytest

valid_xml_reports = ["reports/dmarc-sample-1.xml", "reports/dmarc-sample-2.xml", "reports/dmarc-sample-3.xml"]
invalid_xml_reports = [
    "reports/dmarc-invalid-1.xml",
    "reports/dmarc-invalid-2.xml",
    "reports/dmarc-invalid-3.xml",
    "reports/dmarc-invalid-4.xml",
]
valid_gz_reports = ["reports/dmarc-sample-1.xml.gz", "reports/dmarc-sample-2.xml.gz", "reports/dmarc-sample-3.xml.gz"]
invalid_gz_reports = [
    "reports/dmarc-invalid-1.xml.gz",
    "reports/dmarc-invalid-2.xml.gz",
    "reports/dmarc-invalid-3.xml.gz",
]
valid_zip_reports = [
    "reports/dmarc-sample-1.xml.zip",
    "reports/dmarc-sample-2.xml.zip",
    "reports/dmarc-sample-3.xml.zip",
]
invalid_zip_reports = [
    "reports/dmarc-invalid-1.xml.zip",
    "reports/dmarc-invalid-2.xml.zip",
    "reports/dmarc-invalid-3.xml.zip",
    "reports/dmarc-invalid-4.xml.zip",
]


@pytest.mark.parametrize(
    "report",
    valid_xml_reports
    + valid_gz_reports
    + valid_zip_reports
    + invalid_xml_reports
    + invalid_gz_reports
    + invalid_zip_reports,
)
def test_reports_exist(report) -> None:
    """Test all the reports can be found."""
    # Check all reports run
    test_file = Path(__file__).parent / report
    assert test_file.exists()


@pytest.mark.parametrize(
    "invalid_report",
    invalid_xml_reports + invalid_gz_reports + invalid_zip_reports,
)
def test_invalid_report(invalid_report) -> None:
    """Test an invalid report."""
    from dmarc_report.dmarc_parser import DMARCParser

    test_file = Path(__file__).parent / invalid_report
    with pytest.raises(Exception):
        DMARCParser.parse_file(test_file)


@pytest.mark.parametrize(
    "invalid_report",
    invalid_xml_reports + invalid_gz_reports + invalid_zip_reports,
)
def test_invalid_report_cli(invalid_report) -> None:
    """Test an invalid report."""
    test_file = Path(__file__).parent / invalid_report

    # Run the command
    result = subprocess.run(["dmarc-report", str(test_file)], capture_output=True, text=True)

    # Check it worked
    assert result.returncode == 1
    assert "Failed to process" in result.stderr


@pytest.mark.parametrize(
    "valid_report",
    valid_xml_reports + valid_gz_reports + valid_zip_reports,
)
def test_valid_report_cli(valid_report) -> None:
    """Test an invalid report."""
    test_file = Path(__file__).parent / valid_report

    # Run the command
    result = subprocess.run(["dmarc-report", str(test_file)], capture_output=True, text=True)

    # Check it worked
    assert result.returncode == 0
    assert "End of report" in result.stdout
