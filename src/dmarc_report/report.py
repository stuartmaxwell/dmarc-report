"""Command line interface for parsing and displaying DMARC reports."""

import argparse
import sys
from pathlib import Path

from rich.console import Console

from dmarc_report.dmarc_parser import DMARCParser


def report() -> None:
    """Parse and display DMARC reports from the command line."""
    parser = argparse.ArgumentParser(description="Parse and display DMARC reports")
    parser.add_argument("filepath", type=str, help="Path to DMARC report file (.xml, .xml.gz, or .zip)")
    args = parser.parse_args()

    console = Console(stderr=True)
    filepath = Path(args.filepath)

    if not filepath.exists():
        console.print(f"[red]Error:[/red] File not found: {filepath}")
        sys.exit(1)

    try:
        report = DMARCParser.parse_file(args.filepath)
        report.display()
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Error:[/red] Failed to process {filepath}: {e!s}")
        sys.exit(1)


if __name__ == "__main__":
    report()
