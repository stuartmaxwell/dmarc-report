"""Safely turn an attachment into XML bytes.

DMARC reports arrive as plain XML, gzip, or zip attachments. We use magic bytes to determine the file type.
"""

from __future__ import annotations

import gzip
import zipfile
from io import BytesIO
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, BinaryIO

from dmarc_report import exceptions

if TYPE_CHECKING:
    from dmarc_report.parser import ParserLimits


GZIP_MAGIC = b"\x1f\x8b\x08"
ZIP_MAGICS = (
    b"PK\x03\x04",  # normal archive
    b"PK\x05\x06",  # empty archive
    b"PK\x07\x08",  # spanned/split archive marker
)
_READ_CHUNK_SIZE = 64 * 1024  # enables bounded streaming reads


def read_limited(
    stream: BinaryIO,
    limit: int,
    code: exceptions.ParseErrorCode,
    message: str,
) -> bytes:
    """Helper function to read no more than one byte beyond a configured limit."""
    content = bytearray()
    while len(content) <= limit:
        remaining = limit + 1 - len(content)
        chunk = stream.read(min(_READ_CHUNK_SIZE, remaining))
        if not chunk:
            return bytes(content)
        content.extend(chunk)
    raise exceptions.ResourceLimitError(message, code=code)


def decode_attachment(content: bytes, limits: ParserLimits) -> bytes:
    """Detect attachment packaging by signature and return XML content as bytes.

    Attachments are checked for magic bytes matching either GZIP or ZIP files, otherwise assumed to be plain XML.
    GZIP files are read with `_read_gzip` and ZIP files are read with `_read_zip`.
    Both of these methods are expected to return XML content as bytes.
    But before the XML is parsed, there's one final check to see if the GZIP or ZIP functions have returned a nested
    archive instead of the expected XML file.
    """
    if content.startswith(GZIP_MAGIC):
        xml_content = _read_gzip(content, limits)
    elif content.startswith(ZIP_MAGICS):
        xml_content = _read_zip(content, limits)
    else:
        if len(content) > limits.max_decompressed_bytes:
            msg = "The XML exceeds the configured decompressed-size limit."
            raise exceptions.ResourceLimitError(
                msg,
                code=exceptions.ParseErrorCode.DECOMPRESSION_LIMIT_EXCEEDED,
            )
        xml_content = content

    # A decoded payload must be XML, not another archive layer.  Rejecting it
    # here applies the same rule to both gzip and zip outer containers.
    if xml_content.startswith(GZIP_MAGIC) or xml_content.startswith(ZIP_MAGICS):
        msg_0 = "Nested report archives are not supported."
        raise exceptions.ArchiveError(
            msg_0,
            code=exceptions.ParseErrorCode.NESTED_ARCHIVE,
        )
    return xml_content


def _read_gzip(content: bytes, limits: ParserLimits) -> bytes:
    """Decompress gzip through the bounded reader instead of in one allocation."""
    try:
        with gzip.GzipFile(fileobj=BytesIO(content)) as gzip_file:
            # Read the gzip file content, limiting to the configured decompressed size
            return read_limited(
                gzip_file,
                limits.max_decompressed_bytes,
                exceptions.ParseErrorCode.DECOMPRESSION_LIMIT_EXCEEDED,
                "The XML exceeds the configured decompressed-size limit.",
            )
    except (gzip.BadGzipFile, EOFError, OSError) as error:
        msg = "The gzip report attachment is corrupt."
        raise exceptions.ArchiveError(msg) from error


def _read_zip(content: bytes, limits: ParserLimits) -> bytes:
    """Read the zip and attempt to extract exactly one XML file.

    We don't extract the files to disk and check for the following:
        - too many files in the zip archive;
        - no nested zip files;
        - no XML files in the zip archive;
        - more than one XML file in the zip archive;
        - ignore common macOS files that may look like xml files;
        - ignore encrypted files in the zip archive;
        - decompressed files too large;
        - corrupt files.
    """
    try:
        with zipfile.ZipFile(BytesIO(content)) as zip_file:
            members = zip_file.infolist()
            if len(members) > limits.max_zip_members:
                msg = "The zip archive exceeds the configured member limit."
                raise exceptions.ResourceLimitError(
                    msg,
                    code=exceptions.ParseErrorCode.ZIP_MEMBER_LIMIT_EXCEEDED,
                )

            eligible = [member for member in members if _is_report_member(member)]
            if not eligible:
                if any(_is_archive_member(member) for member in members):
                    msg_0 = "Nested report archives are not supported."
                    raise exceptions.ArchiveError(
                        msg_0,
                        code=exceptions.ParseErrorCode.NESTED_ARCHIVE,
                    )
                msg_1 = "The zip archive contains no eligible XML report member."
                raise exceptions.ArchiveError(
                    msg_1,
                    code=exceptions.ParseErrorCode.ARCHIVE_REPORT_MISSING,
                )
            if len(eligible) > 1:
                msg_2 = "The zip archive contains multiple eligible XML report members."
                raise exceptions.ArchiveError(
                    msg_2,
                    code=exceptions.ParseErrorCode.ARCHIVE_REPORT_AMBIGUOUS,
                )

            report_member = eligible[0]
            if report_member.flag_bits & 0x1:
                msg_3 = "Encrypted zip report members are not supported."
                raise exceptions.ArchiveError(msg_3)
            if report_member.file_size > limits.max_decompressed_bytes:
                msg_4 = "The XML exceeds the configured decompressed-size limit."
                raise exceptions.ResourceLimitError(
                    msg_4,
                    code=exceptions.ParseErrorCode.DECOMPRESSION_LIMIT_EXCEEDED,
                )

            with zip_file.open(report_member) as report_file:
                return read_limited(
                    report_file,
                    limits.max_decompressed_bytes,
                    exceptions.ParseErrorCode.DECOMPRESSION_LIMIT_EXCEEDED,
                    "The XML exceeds the configured decompressed-size limit.",
                )
    except (zipfile.BadZipFile, EOFError, NotImplementedError, OSError) as error:
        msg_5 = "The zip report attachment is corrupt."
        raise exceptions.ArchiveError(msg_5) from error


def _is_report_member(member: zipfile.ZipInfo) -> bool:
    """Ignore directories and common macOS metadata when choosing the report."""
    member_path = PurePosixPath(member.filename)
    is_macos_metadata = "__MACOSX" in member_path.parts or member_path.name.startswith("._")
    return not member.is_dir() and not is_macos_metadata and member_path.suffix.lower() == ".xml"


def _is_archive_member(member: zipfile.ZipInfo) -> bool:
    """Recognize a nested archive by name so it receives the error code."""
    archive_suffixes = {".gz", ".gzip", ".zip"}
    return not member.is_dir() and PurePosixPath(member.filename).suffix.lower() in archive_suffixes
