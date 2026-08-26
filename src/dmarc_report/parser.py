"""Public API for parsing legacy and RFC 9990 DMARC aggregate reports.

The parsing pipeline has three stages:

1. read the attachment file to bytes keeping within `ParserLimits`;
2. decode the attachment bytes to plain XML, extracting from gzip, or zip files if needed;
3. parse the XML tree into the public schema dataclasses.
"""

from dataclasses import dataclass, fields
from pathlib import Path
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from dmarc_report import _attachments, _xml_parser, exceptions, schema


@dataclass(frozen=True)
class ParserLimits:
    """Resource limits applied independently to each parser call."""

    max_input_bytes: int = 10 * 1024 * 1024
    max_decompressed_bytes: int = 100 * 1024 * 1024
    max_zip_members: int = 10
    max_records: int = 100_000
    max_dkim_results_per_record: int = 100
    max_spf_results_per_record: int = 10
    max_text_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        """Reject invalid configuration before it can disable a safety limit."""
        for limit in fields(self):
            value = getattr(self, limit.name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                msg = f"{limit.name} must be a positive integer"
                raise ValueError(msg)


class DMARCParser:
    """Parse plain XML, gzip, and legacy zip aggregate reports."""

    @staticmethod
    def parse_file(filepath: str | Path, *, limits: ParserLimits | None = None) -> schema.Report:
        """Read and parse one report file without trusting its size metadata."""
        parser_limits = limits if limits is not None else ParserLimits()
        with Path(filepath).open("rb") as report_file:
            # Step 1: Read the original attachment as bytes, not exceeding the limit configured in the parser limits
            content = _attachments.read_limited(
                report_file,
                parser_limits.max_input_bytes,
                exceptions.ParseErrorCode.INPUT_LIMIT_EXCEEDED,
                "The report attachment exceeds the configured input limit.",
            )
        # Now parse the attachment bytes to the next step: parse_bytes
        return DMARCParser.parse_bytes(content, limits=parser_limits)

    @staticmethod
    def parse_bytes(content: bytes, *, limits: ParserLimits | None = None) -> schema.Report:
        """Decode and parse one in-memory report attachment."""
        parser_limits = limits if limits is not None else ParserLimits()
        if len(content) > parser_limits.max_input_bytes:
            msg = "The report attachment exceeds the configured input limit."
            raise exceptions.ResourceLimitError(
                msg,
                code=exceptions.ParseErrorCode.INPUT_LIMIT_EXCEEDED,
            )

        # Step 2: Decode the attachment bytes to plain XML, extracting from gzip or zip files if needed
        xml_content = _attachments.decode_attachment(content, parser_limits)
        try:
            # Parse the XML tree using defusedxml to prevent entity-expansion and external-entity attacks
            root = ElementTree.fromstring(xml_content)
        except (ParseError, DefusedXmlException) as error:
            msg_0 = "The report is not safe, well-formed XML."
            raise exceptions.XMLSyntaxError(msg_0) from error

        # Step 3: Parse the XML using the rules for the detected DMARC format
        xml_parser = _xml_parser.DMARCXMLParser(root, parser_limits)
        return xml_parser.parse()
