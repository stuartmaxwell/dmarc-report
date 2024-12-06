"""Parse DMARC XML reports and display the results using Rich tables and panels."""

import gzip
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import ClassVar, Optional
from xml.etree.ElementTree import Element

from defusedxml import ElementTree
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


class PolicyType(Enum):
    """Policy types for DMARC."""

    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class AlignmentMode(Enum):
    """Alignment modes for DKIM and SPF."""

    RELAXED = "r"
    STRICT = "s"


class AuthResultType(Enum):
    """Authentication result types for DKIM and SPF.

    The AuthResultType enum corresponds to the <result> element in the <dkim> and <spf> elements of the DMARC XML
    report.
    """

    NONE = "none"
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    POLICY = "policy"
    NEUTRAL = "neutral"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    SOFTFAIL = "softfail"  # SPF only


@dataclass
class DateRange:
    """Date range object containing begin and end timestamps.

    The DateRange object corresponds to the <date_range> element in the DMARC XML report.
    """

    begin: int
    end: int

    def __str__(self) -> str:
        """Return formatted date range string."""
        return f"{self.format_timestamp(self.begin)} to {self.format_timestamp(self.end)}"

    @staticmethod
    def format_timestamp(timestamp: int) -> str:
        """Convert UTC Unix timestamp to formatted UTC date string."""
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")  # noqa: UP017


@dataclass
class ReportMetadata:
    """Report metadata object containing report recipient details.

    The ReportMetadata object corresponds to the <report_metadata> element in the DMARC XML report.
    """

    org_name: str
    email: str
    report_id: str
    date_range: DateRange
    extra_contact_info: Optional[str] = None
    errors: Optional[list[str]] = None  # Not yet implemented


@dataclass
class PolicyPublished:
    """Policy published object containing DMARC policy details.

    The PolicyPublished object corresponds to the <policy_published> element in the DMARC XML report.
    """

    domain: str
    p: PolicyType
    sp: PolicyType
    pct: int  # 0-100
    adkim: AlignmentMode
    aspf: AlignmentMode
    fo: Optional[str] = None

    def __post_init__(self) -> None:
        """Convert string values to enums if needed and validate percentage."""
        if isinstance(self.p, str):
            self.p = PolicyType(self.p)
        if isinstance(self.sp, str):
            self.sp = PolicyType(self.sp)
        if isinstance(self.adkim, str):
            self.adkim = AlignmentMode(self.adkim)
        if isinstance(self.aspf, str):
            self.aspf = AlignmentMode(self.aspf)

        # Validate percentage
        if not 0 <= self.pct <= 100:  # noqa: PLR2004
            msg = f"Percentage must be between 0 and 100, got {self.pct}"
            raise ValueError(msg)


@dataclass
class PolicyEvaluated:
    """Policy evaluated object containing disposition and authentication results.

    The PolicyEvaluated object corresponds to the <policy_evaluated> element in the <record> element of DMARC XML
    report.
    """

    disposition: PolicyType
    dkim: AuthResultType
    spf: AuthResultType
    reason: Optional[list[dict]] = None  # type and comment. Not yet implemented

    def __post_init__(self) -> None:
        """Convert string values to enums if needed."""
        if isinstance(self.disposition, str):
            self.disposition = PolicyType(self.disposition)
        if isinstance(self.dkim, str):
            self.dkim = AuthResultType(self.dkim)
        if isinstance(self.spf, str):
            self.spf = AuthResultType(self.spf)


@dataclass
class Identifier:
    """Identifier object containing message header and envelope details.

    The Identifier object corresponds to the <identifiers> element in the <record> element of DMARC XML report.
    """

    header_from: str
    envelope_to: Optional[str] = None
    envelope_from: Optional[str] = None


@dataclass
class DKIMAuthResult:
    """DKIM authentication result object.

    The DKIMAuthResult object corresponds to the <dkim> element in the <auth_results> element of DMARC XML report.
    """

    domain: str
    result: AuthResultType
    selector: Optional[str] = None
    human_result: Optional[str] = None

    def __post_init__(self) -> None:
        """Convert string values to enums if needed."""
        if isinstance(self.result, str):
            self.result = AuthResultType(self.result)


@dataclass
class SPFAuthResult:
    """SPF authentication result object.

    The SPFAuthResult object corresponds to the <spf> element in the <auth_results> element of DMARC XML report.
    """

    domain: str
    result: AuthResultType
    scope: Optional[str] = None
    human_result: Optional[str] = None

    VALID_SCOPES: ClassVar[set[str]] = {"helo", "mfrom"}

    def __post_init__(self) -> None:
        """Convert string values to enums if needed and validate scope."""
        if isinstance(self.result, str):
            self.result = AuthResultType(self.result)
        if self.scope and self.scope not in self.VALID_SCOPES:
            msg = f"Invalid scope: {self.scope}. Must be one of {self.VALID_SCOPES}"
            raise ValueError(msg)


@dataclass
class AuthResults:
    """Authentication results for DKIM and SPF.

    The AuthResults object corresponds to the <auth_results> element in the DMARC XML report.
    """

    dkim: list[DKIMAuthResult]
    spf: list[SPFAuthResult]


@dataclass
class Record:
    """DMARC record object containing message details and authentication results.

    The Record object corresponds to the <record> element in the DMARC XML report.
    """

    source_ip: str
    count: int
    policy_evaluated: PolicyEvaluated
    identifiers: Identifier
    auth_results: AuthResults


@dataclass
class Report:
    """DMARC report object containing metadata, policy, and records.

    This class provides properties and methods to access and display the DMARC report data.
    """

    report_metadata: ReportMetadata
    policy_published: PolicyPublished
    records: list[Record]

    @property
    def org_name(self) -> str:
        """Return the organization name of the report recipient."""
        return self.report_metadata.org_name

    @property
    def email(self) -> str:
        """Return the email address of the report recipient."""
        return self.report_metadata.email

    @property
    def report_id(self) -> str:
        """Return the report ID."""
        return self.report_metadata.report_id

    @property
    def date_range(self) -> tuple[int, int]:
        """Return the date range of the DMARC report."""
        return (self.report_metadata.date_range.begin, self.report_metadata.date_range.end)

    @property
    def domain(self) -> str:
        """Return the domain of the DMARC report."""
        return self.policy_published.domain

    def get_summary_stats(self) -> dict:
        """Generate summary statistics for the report."""
        total_messages = sum(record.count for record in self.records)

        # Calculate pass rates
        dkim_pass = sum(record.count for record in self.records if record.policy_evaluated.dkim == "pass")
        spf_pass = sum(record.count for record in self.records if record.policy_evaluated.spf == "pass")

        # Count dispositions
        dispositions = {}
        for record in self.records:
            disp = record.policy_evaluated.disposition.value
            dispositions[disp] = dispositions.get(disp, 0) + record.count

        return {
            "total_messages": total_messages,
            "unique_sources": len({record.source_ip for record in self.records}),
            "dkim_pass_rate": dkim_pass / total_messages if total_messages > 0 else 0,
            "spf_pass_rate": spf_pass / total_messages if total_messages > 0 else 0,
            "dispositions": dispositions,
            "report_period": str(self.report_metadata.date_range),
        }

    def display(self) -> None:
        """Display the DMARC report using Rich tables and panels."""
        console = Console()

        # Create header panel with today's date and time
        header = f"""
[bold]Domain:[/bold] [green]{self.policy_published.domain}[/green]
[bold]Report Period:[/bold] [green]{self.report_metadata.date_range}[/green]
"""
        console.print(
            Panel(
                header,
                title=f"DMARC Report for {self.policy_published.domain}",
                border_style="blue",
            ),
        )

        # Display summary statistics
        stats = self.get_summary_stats()
        stats_table = Table(title="Summary Statistics", box=box.ROUNDED, show_header=False)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")

        stats_table.add_row("Total Messages", str(stats["total_messages"]))
        stats_table.add_row("Unique Sources", str(stats["unique_sources"]))
        stats_table.add_row("DKIM Pass Rate", f"{stats['dkim_pass_rate']:.1%}")
        stats_table.add_row("SPF Pass Rate", f"{stats['spf_pass_rate']:.1%}")

        console.print(stats_table)

        # Report Details table
        details_table = Table(title="DMARC Report Metadata", box=box.ROUNDED, show_header=False)
        details_table.add_column("Field", style="cyan")
        details_table.add_column("Value", style="green")
        details_table.add_row("Org name", self.report_metadata.org_name)
        details_table.add_row("Email", self.report_metadata.email)
        details_table.add_row("Extra contact info", self.report_metadata.extra_contact_info)
        details_table.add_row("Report ID", self.report_metadata.report_id)
        details_table.add_row("Date range", str(self.report_metadata.date_range))

        console.print(details_table)
        console.print()

        # Create policy table
        policy_table = Table(title="DMARC Policy Details", box=box.ROUNDED, show_header=False)
        policy_table.add_column("Setting", style="cyan")
        policy_table.add_column("Value", style="green")

        policy_table.add_row("Domain", self.policy_published.domain)
        policy_table.add_row("DKIM Alignment", self.policy_published.adkim.value)
        policy_table.add_row("SPF Alignment", self.policy_published.aspf.value)
        policy_table.add_row("Policy", self.policy_published.p.value)
        policy_table.add_row("Subdomain Policy", self.policy_published.sp.value)
        policy_table.add_row("Percent", str(self.policy_published.pct))
        if self.policy_published.fo:
            policy_table.add_row("Failure Options", self.policy_published.fo)

        console.print(policy_table)
        console.print()

        # Create records table
        records_table = Table(title="Message Records", box=box.ROUNDED)
        records_table.add_column("Source IP", style="cyan")
        records_table.add_column("Count", style="magenta")
        records_table.add_column("Disposition", style="green")
        records_table.add_column("DKIM", style="yellow")
        records_table.add_column("SPF", style="yellow")
        records_table.add_column("Header From", style="blue")
        records_table.add_column("Auth Results", style="green")

        for record in self.records:
            dkim_auth_results_str = "\n".join(
                f"dkim: {ar_d.domain} ({ar_d.result.value})" for ar_d in record.auth_results.dkim
            )
            spf_auth_results_str = "\n".join(
                f"spf: {ar_s.domain} ({ar_s.result.value})" for ar_s in record.auth_results.spf
            )

            records_table.add_row(
                record.source_ip,
                str(record.count),
                record.policy_evaluated.disposition.value,
                record.policy_evaluated.dkim.value,
                record.policy_evaluated.spf.value,
                record.identifiers.header_from,
                dkim_auth_results_str + "\n" + spf_auth_results_str,
            )

        console.print(records_table)

        console.print("\n :rocket: [bold]End of report[/bold]")
        console.rule()


class DMARCParser:
    """Parse DMARC XML reports.

    This class provides methods to parse DMARC XML reports from files and strings.

    When used with the `parse_file` method, it can handle .xml, .xml.gz, and .zip file types, and will return a Report
    object.
    """

    @staticmethod
    def parse_file(filepath: str) -> Report:
        """Parse a DMARC report file and return a Report object.

        Handles .xml, .xml.gz, and .zip file types.

        Args:
            filepath (str): Path to the DMARC report file.

        Returns:
            Report: A Report object containing the parsed DMARC report data.

        Raises:
            ValueError: If the file type is not supported.
        """
        filepath = Path(filepath)
        suffix = filepath.suffix.lower()

        if suffix == ".zip":
            content = DMARCParser._read_zip(filepath)
        elif suffix == ".gz":
            content = DMARCParser._read_gzip(filepath)
        elif suffix == ".xml":
            content = DMARCParser._read_xml(filepath)
        else:
            msg = f"Unsupported file type: {filepath.suffix}"
            raise ValueError(msg)

        # Parse the content into a Report object
        root = ElementTree.fromstring(content)
        return DMARCParser.parse_xml(root)

    @staticmethod
    def _read_zip(filepath: str) -> str:
        """Parse a zipped DMARC XML report file and return the content.

        Looks for the first .xml file in the zip archive.

        Args:
            filepath (str): Path to the zip archive containing the DMARC XML report.

        Returns:
            str: The content of the first XML file found in the zip archive.

        Raises:
            ValueError: If no XML file is found in the zip archive.
        """
        with zipfile.ZipFile(filepath) as zip_file:
            # Find the first XML file in the archive
            xml_files = [f for f in zip_file.namelist() if f.lower().endswith(".xml")]
            if not xml_files:
                msg = f"No XML file found in zip archive: {filepath}"
                raise ValueError(msg)

            # Read the first XML file
            with zip_file.open(xml_files[0]) as f:
                return f.read().decode("utf-8")

    @staticmethod
    def _read_gzip(filepath: str) -> str:
        """Parse a gzipped DMARC XML report file and return the content.

        Args:
            filepath (str): Path to the gzipped DMARC XML report file.

        Returns:
            str: The content of the gzipped XML file.
        """
        with gzip.open(filepath, "rt", encoding="utf-8") as f:
            return f.read()

    @staticmethod
    def _read_xml(filepath: str) -> str:
        """Parse a DMARC XML report file and return the content.

        Args:
            filepath (str): Path to the DMARC XML report file.

        Returns:
            str: The content of the XML file.
        """
        with Path.open(filepath, encoding="utf-8") as f:
            return f.read()

    @staticmethod
    def parse_xml(root: Element) -> Report:
        """Parse an XML ElementTree and return a Report object.

        This is the main logic that parses the DMARC XML report.

        Args:
            root (Element): The root of the XML ElementTree.

        Returns:
            Report: A Report object containing the parsed DMARC report data.

        Raises:
            ValueError: If the XML structure is invalid or missing required fields.
        """
        # Extract report metadata
        report_metadata = root.find("report_metadata")
        metadata = ReportMetadata(
            org_name=report_metadata.findtext("org_name"),
            email=report_metadata.findtext("email"),
            report_id=report_metadata.findtext("report_id"),
            date_range=DateRange(
                begin=int(report_metadata.find("date_range").findtext("begin")),
                end=int(report_metadata.find("date_range").findtext("end")),
            ),
            extra_contact_info=report_metadata.findtext("extra_contact_info"),
        )

        # Extract policy published
        policy_published = root.find("policy_published")
        policy = PolicyPublished(
            domain=policy_published.findtext("domain"),
            p=policy_published.findtext("p"),
            sp=policy_published.findtext("sp", "none"),
            pct=int(policy_published.findtext("pct", "100")),
            adkim=policy_published.findtext("adkim", "r"),
            aspf=policy_published.findtext("aspf", "r"),
            fo=policy_published.findtext("fo"),
        )

        # Extract records
        records: list[Record] = []
        for record in root.findall(".//record"):
            # Parse authentication results
            auth_results_elem = record.find("auth_results")

            dkim_results_elem = auth_results_elem.findall("dkim")
            dkim_auth_results = [
                DKIMAuthResult(
                    domain=dkim_result.findtext("domain"),
                    result=dkim_result.findtext("result"),
                    selector=dkim_result.findtext("selector"),
                    human_result=dkim_result.findtext("human_result"),
                )
                for dkim_result in dkim_results_elem
            ]

            spf_results_elem = auth_results_elem.findall("spf")
            spf_auth_results = [
                SPFAuthResult(
                    domain=spf_result.findtext("domain"),
                    result=spf_result.findtext("result"),
                    scope=spf_result.findtext("scope"),
                    human_result=spf_result.findtext("human_result"),
                )
                for spf_result in spf_results_elem
            ]

            auth_results = AuthResults(
                dkim=dkim_auth_results,
                spf=spf_auth_results,
            )

            # Create row object
            row = Record(
                source_ip=record.findtext(".//source_ip"),
                count=int(record.findtext(".//count")),
                policy_evaluated=PolicyEvaluated(
                    disposition=record.findtext(".//disposition"),
                    dkim=record.findtext(".//dkim"),
                    spf=record.findtext(".//spf"),
                ),
                identifiers=Identifier(
                    header_from=record.findtext(".//identifier/header_from"),
                    envelope_from=record.findtext(".//identifier/envelope_from"),
                    envelope_to=record.findtext(".//identifier/envelope_to"),
                ),
                auth_results=auth_results,
            )
            records.append(row)

        return Report(
            report_metadata=metadata,
            policy_published=policy,
            records=records,
        )

    @staticmethod
    def format_date_range(timestamp: int) -> str:
        """Convert UTC Unix timestamp to formatted UTC date string."""
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")  # noqa: UP017
