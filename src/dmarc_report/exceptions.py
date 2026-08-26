"""Stable exceptions raised for malformed DMARC report content."""

from enum import Enum


class ParseErrorCode(str, Enum):
    """Machine-readable malformed-input reason codes."""

    UNSUPPORTED_REPORT = "unsupported_report"
    INPUT_LIMIT_EXCEEDED = "input_limit_exceeded"
    DECOMPRESSION_LIMIT_EXCEEDED = "decompression_limit_exceeded"
    ZIP_MEMBER_LIMIT_EXCEEDED = "zip_member_limit_exceeded"
    RECORD_LIMIT_EXCEEDED = "record_limit_exceeded"
    AUTH_RESULT_LIMIT_EXCEEDED = "auth_result_limit_exceeded"
    TEXT_LIMIT_EXCEEDED = "text_limit_exceeded"
    CORRUPT_ARCHIVE = "corrupt_archive"
    ARCHIVE_REPORT_MISSING = "archive_report_missing"
    ARCHIVE_REPORT_AMBIGUOUS = "archive_report_ambiguous"
    NESTED_ARCHIVE = "nested_archive"
    INVALID_XML = "invalid_xml"
    INVALID_STRUCTURE = "invalid_structure"
    MISSING_FIELD = "missing_field"
    INVALID_VALUE = "invalid_value"


class DMARCParseError(ValueError):
    """Base class for failures caused by caller-supplied report content."""

    default_code = ParseErrorCode.INVALID_STRUCTURE

    def __init__(
        self,
        message: str,
        *,
        code: ParseErrorCode | str | None = None,
    ) -> None:
        """Store the stable error category alongside the readable message."""
        self.code = ParseErrorCode(code or self.default_code)
        super().__init__(message)


class UnsupportedReportError(DMARCParseError):
    """Raised for a report namespace or version the package does not support."""

    default_code = ParseErrorCode.UNSUPPORTED_REPORT


class ResourceLimitError(DMARCParseError):
    """Raised when report content exceeds a configured parser resource limit."""

    default_code = ParseErrorCode.INPUT_LIMIT_EXCEEDED


class ArchiveError(DMARCParseError):
    """Raised for a corrupt, missing, ambiguous, or nested archive payload."""

    default_code = ParseErrorCode.CORRUPT_ARCHIVE


class XMLSyntaxError(DMARCParseError):
    """Raised when decompressed content is not safe, well-formed XML."""

    default_code = ParseErrorCode.INVALID_XML


class ReportStructureError(DMARCParseError):
    """Raised when XML does not have the required DMARC report structure."""

    default_code = ParseErrorCode.INVALID_STRUCTURE


class FieldValueError(DMARCParseError):
    """Raised when an XML field has an invalid value."""

    default_code = ParseErrorCode.INVALID_VALUE
