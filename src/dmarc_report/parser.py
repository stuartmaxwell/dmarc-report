"""Parse DMARC XML reports and display the results using Rich tables and panels."""

import gzip
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

from defusedxml import ElementTree

from dmarc_report import exceptions, schema

# https://garykessler.net/library/file_sigs_GCK_latest.html
GZIP_MAGIC = b"\x1f\x8b\x08"
ZIP_MAGIC = b"PK\x03\x04"

# Exceptions that indicate the input was malformed rather than a bug in the parser itself.
_MALFORMED_INPUT_ERRORS = (AttributeError, TypeError, ValueError, OSError, zipfile.BadZipFile, ParseError)


class DMARCParser:
    """Parse DMARC XML reports.

    This class provides methods to parse DMARC XML reports from files and in-memory bytes.

    Gzip-compressed, zip-compressed, and plain XML content are detected from the "magic bytes" rather than a filename.
    """

    @staticmethod
    def parse_file(filepath: str) -> schema.Report:
        """Parse a DMARC report file and return a Report object.

        Handles .xml, .xml.gz, and .zip file types.

        Args:
            filepath (str): Path to the DMARC report file.

        Returns:
            Report: A Report object containing the parsed DMARC report data.

        Raises:
            OSError: If the file can't be read (e.g. it doesn't exist).
            DMARCParseError: If the file's content is corrupt, isn't valid XML, or doesn't match the
                expected DMARC report structure.
        """
        content = Path(filepath).read_bytes()
        return DMARCParser.parse_bytes(content)

    @staticmethod
    def parse_bytes(content: bytes) -> schema.Report:
        """Parse DMARC report content and return a Report object.

        Handles gzip-compressed, zip-compressed, and plain XML content, detected by inspecting the leading
        bytes.

        Args:
            content (bytes): The raw DMARC report content.

        Returns:
            Report: A Report object containing the parsed DMARC report data.

        Raises:
            DMARCParseError: If the content is corrupt, isn't valid XML, or doesn't match the expected
                DMARC report structure.
        """
        try:
            xml_content = DMARCParser._decompress(content)
            root = ElementTree.fromstring(xml_content)
            return DMARCParser._parse_xml(root)
        except _MALFORMED_INPUT_ERRORS as e:
            msg = f"Failed to parse DMARC report: {e}"
            raise exceptions.DMARCParseError(msg) from e

    @staticmethod
    def _decompress(content: bytes) -> str:
        """Decode raw DMARC report bytes to an XML string.

        Detects gzip and zip compression from the content's magic bytes, and then decompresses and returns the content
        as utf-8. If the content doesn't match gzip or zip types, then it assumes xml and returns as utf-8.

        Args:
            content (bytes): The raw DMARC report content.

        Returns:
            str: The decoded XML content.

        Raises:
            ValueError: If a zip archive is provided but contains no XML file.
        """
        if content.startswith(GZIP_MAGIC):
            return gzip.decompress(content).decode("utf-8")

        if content.startswith(ZIP_MAGIC):
            with zipfile.ZipFile(BytesIO(content)) as zip_file:
                # Find the first XML file in the archive
                xml_files = [f for f in zip_file.namelist() if f.lower().endswith(".xml")]
                if not xml_files:
                    msg = "No XML file found in zip archive"
                    raise ValueError(msg)

                # Read the first XML file
                with zip_file.open(xml_files[0]) as f:
                    return f.read().decode("utf-8")

        return content.decode("utf-8")

    @staticmethod
    def _parse_xml(root: Element) -> schema.Report:
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
        metadata = schema.ReportMetadata(
            org_name=report_metadata.findtext(f"{default_ns}org_name"),
            email=report_metadata.findtext(f"{default_ns}email"),
            report_id=report_metadata.findtext(f"{default_ns}report_id"),
            date_range=schema.DateRange(
                begin=int(report_metadata.find(f"{default_ns}date_range").findtext(f"{default_ns}begin")),
                end=int(report_metadata.find(f"{default_ns}date_range").findtext(f"{default_ns}end")),
            ),
            extra_contact_info=report_metadata.findtext(f"{default_ns}extra_contact_info"),
        )

        # Extract policy published
        policy_published = root.find(f"{default_ns}policy_published")
        policy = schema.PolicyPublished(
            domain=policy_published.findtext(f"{default_ns}domain"),
            p=policy_published.findtext(f"{default_ns}p"),
            sp=policy_published.findtext(f"{default_ns}sp", "none") or "none",
            pct=int(policy_published.findtext(f"{default_ns}pct", "100")),
            adkim=policy_published.findtext(f"{default_ns}adkim", "r"),
            aspf=policy_published.findtext(f"{default_ns}aspf", "r"),
            fo=policy_published.findtext(f"{default_ns}fo"),
        )

        # Extract records
        records: list[schema.Record] = []
        all_records = root.findall(f".//{default_ns}record")
        for record in all_records:
            # Parse authentication results
            auth_results_elem = record.find(f"{default_ns}auth_results")

            dkim_results_elem = auth_results_elem.findall(f"{default_ns}dkim")
            dkim_auth_results = [
                schema.DKIMAuthResult(
                    domain=dkim_result.findtext(f"{default_ns}domain"),
                    result=dkim_result.findtext(f"{default_ns}result"),
                    selector=dkim_result.findtext(f"{default_ns}selector"),
                    human_result=dkim_result.findtext(f"{default_ns}human_result"),
                )
                for dkim_result in dkim_results_elem
            ]

            spf_results_elem = auth_results_elem.findall(f"{default_ns}spf")
            spf_auth_results = [
                schema.SPFAuthResult(
                    domain=spf_result.findtext(f"{default_ns}domain"),
                    result=spf_result.findtext(f"{default_ns}result"),
                    scope=spf_result.findtext(f"{default_ns}scope"),
                    human_result=spf_result.findtext(f"{default_ns}human_result"),
                )
                for spf_result in spf_results_elem
            ]

            auth_results = schema.AuthResults(
                dkim=dkim_auth_results,
                spf=spf_auth_results,
            )

            # Create row object
            row = schema.Record(
                source_ip=record.findtext(f".//{default_ns}source_ip"),
                count=int(record.findtext(f".//{default_ns}count")),
                policy_evaluated=schema.PolicyEvaluated(
                    disposition=record.findtext(f".//{default_ns}disposition"),
                    dkim=record.findtext(f".//{default_ns}dkim"),
                    spf=record.findtext(f".//{default_ns}spf"),
                ),
                identifiers=schema.Identifier(
                    header_from=record.findtext(f".//{default_ns}identifiers/{default_ns}header_from"),
                    envelope_from=record.findtext(f".//{default_ns}identifiers/{default_ns}envelope_from"),
                    envelope_to=record.findtext(f".//{default_ns}identifiers/{default_ns}envelope_to"),
                ),
                auth_results=auth_results,
            )
            records.append(row)

        return schema.Report(
            report_metadata=metadata,
            policy_published=policy,
            records=records,
        )

    @staticmethod
    def _format_date_range(timestamp: int) -> str:
        """Convert UTC Unix timestamp to formatted UTC date string."""
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
