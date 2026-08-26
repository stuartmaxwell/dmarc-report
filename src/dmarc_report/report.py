"""Command line interface for parsing and displaying DMARC reports."""

import argparse
from pathlib import Path

from rich.console import Console
from rich.text import Text

from dmarc_report import __version__
from dmarc_report.display import display_console
from dmarc_report.exceptions import DMARCParseError
from dmarc_report.parser import DMARCParser


def report() -> None:
    """Parse and display DMARC reports from the command line."""
    parser = argparse.ArgumentParser(description="Parse and display DMARC reports")
    parser.add_argument("filepath", type=str, help="Path to DMARC report file (.xml, .xml.gz, or .zip)")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show parser warnings for tolerated report deviations",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args()

    filepath = Path(args.filepath)
    error_console = Console(stderr=True)

    try:
        dmarc_report = DMARCParser.parse_file(filepath)
    except FileNotFoundError:
        _print_error(error_console, f"File not found: {filepath}")
        raise SystemExit(1) from None
    except DMARCParseError as error:
        _print_error(error_console, f"Failed to process {filepath}: {error} [{error.code.value}]")
        raise SystemExit(1) from None
    except OSError as error:
        detail = error.strerror or str(error)
        _print_error(error_console, f"Could not read {filepath}: {detail}")
        raise SystemExit(1) from None

    display_console(dmarc_report, verbose=args.verbose)


def _print_error(console: Console, message: str) -> None:
    """Print one concise error without interpreting message text as Rich markup."""
    output = Text("Error: ", style="bold red")
    output.append(message)
    console.print(output)


if __name__ == "__main__":
    report()
