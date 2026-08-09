"""Custom exceptions for the dmarc_report package."""


class DMARCParseError(ValueError):
    """Raised when DMARC report content can't be parsed.

    Covers corrupt/unreadable archives, invalid XML, and XML that doesn't match the expected DMARC report structure.
    """
