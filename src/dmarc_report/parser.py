"""Parse DMARC XML reports and display the results using Rich tables and panels."""

import gzip
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.etree.ElementTree import Element

from defusedxml import ElementTree

from dmarc_report.schema import (
    AuthResults,
    DateRange,
    DKIMAuthResult,
    Identifier,
    PolicyEvaluated,
    PolicyPublished,
    Record,
    Report,
    ReportMetadata,
    SPFAuthResult,
)


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
        return DMARCParser._parse_xml(root)

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
    def _parse_xml(root: Element) -> Report:
        """Parse an XML ElementTree and return a Report object.

        This is the main logic that parses the DMARC XML report.

        Args:
            root (Element): The root of the XML ElementTree.

        Returns:
            Report: A Report object containing the parsed DMARC report data.

        Raises:
            ValueError: If the XML structure is invalid or missing required fields.
        """
        # Check for default namespace
        default_ns = ""
        if root.tag.startswith("{"):
            default_ns = root.tag.split("}")[0] + "}"
        # Extract report metadata
        report_metadata = root.find(f"{default_ns}report_metadata")
        metadata = ReportMetadata(
            org_name=report_metadata.findtext(f"{default_ns}org_name"),
            email=report_metadata.findtext(f"{default_ns}email"),
            report_id=report_metadata.findtext(f"{default_ns}report_id"),
            date_range=DateRange(
                begin=int(report_metadata.find(f"{default_ns}date_range").findtext(f"{default_ns}begin")),
                end=int(report_metadata.find(f"{default_ns}date_range").findtext(f"{default_ns}end")),
            ),
            extra_contact_info=report_metadata.findtext(f"{default_ns}extra_contact_info"),
        )

        # Extract policy published
        policy_published = root.find(f"{default_ns}policy_published")
        policy = PolicyPublished(
            domain=policy_published.findtext(f"{default_ns}domain"),
            p=policy_published.findtext(f"{default_ns}p"),
            sp=policy_published.findtext(f"{default_ns}sp", "none") or "none",
            pct=int(policy_published.findtext(f"{default_ns}pct", "100")),
            adkim=policy_published.findtext(f"{default_ns}adkim", "r"),
            aspf=policy_published.findtext(f"{default_ns}aspf", "r"),
            fo=policy_published.findtext(f"{default_ns}fo"),
        )

        # Extract records
        records: list[Record] = []
        all_records = root.findall(f".//{default_ns}record")
        for record in all_records:
            # Parse authentication results
            auth_results_elem = record.find(f"{default_ns}auth_results")

            dkim_results_elem = auth_results_elem.findall(f"{default_ns}dkim")
            dkim_auth_results = [
                DKIMAuthResult(
                    domain=dkim_result.findtext(f"{default_ns}domain"),
                    result=dkim_result.findtext(f"{default_ns}result"),
                    selector=dkim_result.findtext(f"{default_ns}selector"),
                    human_result=dkim_result.findtext(f"{default_ns}human_result"),
                )
                for dkim_result in dkim_results_elem
            ]

            spf_results_elem = auth_results_elem.findall(f"{default_ns}spf")
            spf_auth_results = [
                SPFAuthResult(
                    domain=spf_result.findtext(f"{default_ns}domain"),
                    result=spf_result.findtext(f"{default_ns}result"),
                    scope=spf_result.findtext(f"{default_ns}scope"),
                    human_result=spf_result.findtext(f"{default_ns}human_result"),
                )
                for spf_result in spf_results_elem
            ]

            auth_results = AuthResults(
                dkim=dkim_auth_results,
                spf=spf_auth_results,
            )

            # Create row object
            row = Record(
                source_ip=record.findtext(f".//{default_ns}source_ip"),
                count=int(record.findtext(f".//{default_ns}count")),
                policy_evaluated=PolicyEvaluated(
                    disposition=record.findtext(f".//{default_ns}disposition"),
                    dkim=record.findtext(f".//{default_ns}dkim"),
                    spf=record.findtext(f".//{default_ns}spf"),
                ),
                identifiers=Identifier(
                    header_from=record.findtext(f".//{default_ns}identifier/{default_ns}header_from"),
                    envelope_from=record.findtext(f".//{default_ns}identifier/{default_ns}envelope_from"),
                    envelope_to=record.findtext(f".//{default_ns}identifier/{default_ns}envelope_to"),
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
    def _format_date_range(timestamp: int) -> str:
        """Convert UTC Unix timestamp to formatted UTC date string."""
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")  # noqa: UP017
