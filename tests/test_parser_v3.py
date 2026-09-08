"""Version 3 schema, compatibility, validation, and resource-safety tests."""

import gzip
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import pytest

from dmarc_report import exceptions, schema
from dmarc_report.parser import DMARCParser, ParserLimits

REPORTS = Path(__file__).parent / "reports"
RFC_9990_NAMESPACE = "urn:ietf:params:xml:ns:dmarc-2.0"
RFC_9990_XML = (REPORTS / "rfc9990-sample.xml").read_bytes()
LEGACY_XML = (REPORTS / "dmarc-sample-1.xml").read_bytes()
LEGACY_DEFAULT_PERCENTAGE = 100
LEGACY_SPF_RESULT_COUNT = 2


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    """Return an in-memory zip containing the supplied members."""
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return output.getvalue()


def _replace(xml: bytes, old: bytes, new: bytes) -> bytes:
    """Replace one fixture fragment and assert that it existed."""
    assert old in xml
    return xml.replace(old, new, 1)


def test_rfc9990_sample_exposes_current_schema() -> None:
    """Parse every supported RFC 9990 field without conflating its enums."""
    report = DMARCParser.parse_bytes(RFC_9990_XML)

    assert report.format is schema.ReportFormat.RFC_9990
    assert report.namespace == RFC_9990_NAMESPACE
    assert report.version == "1.0"
    assert report.report_metadata.generator == "Example DMARC Aggregate Reporter v1.2"
    assert report.report_metadata.errors == ["One policy lookup was temporarily unavailable."]

    policy = report.policy_published
    assert policy.domain == "example.com"
    assert policy.p is schema.PublishedPolicy.QUARANTINE
    assert policy.sp is schema.PublishedPolicy.NONE
    assert policy.np is schema.PublishedPolicy.REJECT
    assert policy.pct is None
    assert policy.adkim is schema.AlignmentMode.STRICT
    assert policy.aspf is schema.AlignmentMode.RELAXED
    assert policy.fo == "1"
    assert policy.testing is schema.TestingMode.YES
    assert policy.discovery_method is schema.DiscoveryMethod.TREEWALK
    assert policy.effective_np is schema.PublishedPolicy.REJECT
    assert policy.effective_pct is None

    record = report.records[0]
    assert record.source_ip == "2001:db8::1"
    assert record.policy_evaluated.disposition is schema.ActionDisposition.PASS
    assert record.policy_evaluated.dkim is schema.DMARCResult.PASS
    assert record.policy_evaluated.spf is schema.DMARCResult.FAIL
    assert [reason.type for reason in record.policy_evaluated.reasons] == [
        schema.PolicyOverrideType.LOCAL_POLICY,
        schema.PolicyOverrideType.MAILING_LIST,
        schema.PolicyOverrideType.OTHER,
        schema.PolicyOverrideType.POLICY_TEST_MODE,
        schema.PolicyOverrideType.TRUSTED_FORWARDER,
    ]
    assert record.identifiers.envelope_from == ""
    assert record.auth_results.dkim[1].result is schema.DKIMResult.NEUTRAL
    assert record.auth_results.spf[0].result is schema.SPFResult.SOFTFAIL
    assert record.auth_results.spf[0].scope is schema.SPFScope.MFROM
    assert report.records[1].auth_results == schema.AuthResults()
    assert report.warnings == []


def test_date_range_exposes_epoch_and_utc_datetime_values() -> None:
    """Keep source timestamps while providing convenient timezone-aware dates."""
    date_range = DMARCParser.parse_bytes(LEGACY_XML).report_metadata.date_range

    assert date_range.begin == 1_577_836_800
    assert date_range.end == 1_577_923_199
    assert date_range.begin_datetime == datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert date_range.end_datetime == datetime(2020, 1, 1, 23, 59, 59, tzinfo=timezone.utc)
    assert str(date_range) == "2020-01-01 00:00:00 UTC to 2020-01-01 23:59:59 UTC"


def test_namespaced_legacy_report_preserves_source_defaults_and_legacy_values() -> None:
    """Keep absent legacy values as None while exposing explicit effective defaults."""
    report = DMARCParser.parse_file(REPORTS / "legacy-namespaced.xml")
    policy = report.policy_published

    assert report.format is schema.ReportFormat.LEGACY
    assert report.namespace == "http://dmarc.org/dmarc-xml/0.1"
    assert report.version == "1.0"
    assert report.report_metadata.email == "contact text retained exactly"
    assert report.report_metadata.errors == ["First policy error.", "Second policy error."]
    assert policy.sp is None
    assert policy.pct is None
    assert policy.adkim is None
    assert policy.aspf is None
    assert policy.testing is None
    assert policy.discovery_method is None
    assert policy.effective_sp is schema.PublishedPolicy.REJECT
    assert policy.effective_pct == LEGACY_DEFAULT_PERCENTAGE
    assert policy.effective_adkim is schema.AlignmentMode.RELAXED
    assert policy.effective_aspf is schema.AlignmentMode.RELAXED
    assert policy.effective_np is None
    assert policy.effective_testing is None
    assert report.records[0].policy_evaluated.reasons[0].type is schema.PolicyOverrideType.FORWARDED
    assert report.records[0].policy_evaluated.reasons[1].type is schema.PolicyOverrideType.SAMPLED_OUT
    assert len(report.records[0].auth_results.spf) == LEGACY_SPF_RESULT_COUNT
    assert report.records[0].auth_results.spf[0].scope is schema.SPFScope.HELO
    assert {warning.code for warning in report.warnings} == {"legacy_missing_pct"}


def test_legacy_decimal_version_is_accepted() -> None:
    """Accept a decimal report version from a legacy report generator."""
    report = DMARCParser.parse_file(REPORTS / "legacy-decimal-version.xml")

    assert report.format is schema.ReportFormat.LEGACY
    assert report.version == "0.1"
    assert len(report.records) == 1
    assert report.records[0].count == 2
    assert {warning.code for warning in report.warnings} == {"legacy_no_namespace"}


def test_namespace_free_legacy_report_treats_empty_sp_as_absent() -> None:
    """Use the standard p fallback when a legacy sender leaves sp empty."""
    report = DMARCParser.parse_file(REPORTS / "dmarc-empty-sp.xml")

    assert report.policy_published.sp is None
    assert report.policy_published.effective_sp is schema.PublishedPolicy.QUARANTINE
    assert {warning.code for warning in report.warnings} == {
        "legacy_no_namespace",
        "legacy_missing_version",
    }


def test_rfc9990_empty_sp_is_rejected() -> None:
    """Require a valid policy value when an RFC 9990 sp element is present."""
    content = _replace(RFC_9990_XML, b"<sp>none</sp>", b"<sp></sp>")

    with pytest.raises(exceptions.FieldValueError) as caught:
        DMARCParser.parse_bytes(content)

    assert caught.value.code is exceptions.ParseErrorCode.INVALID_VALUE
    assert "<sp> field contains an invalid value" in str(caught.value)


def test_legacy_np_extension_is_retained_with_a_warning() -> None:
    """Accept deployed legacy reports that include the later np policy field."""
    report = DMARCParser.parse_file(REPORTS / "legacy-np-extension.xml")

    assert report.format is schema.ReportFormat.LEGACY
    assert report.policy_published.np is schema.PublishedPolicy.REJECT
    assert report.policy_published.effective_np is schema.PublishedPolicy.REJECT
    assert (
        schema.ParserWarning(
            code="legacy_np_extension",
            message="A legacy report's <np> policy extension was retained.",
        )
        in report.warnings
    )


def test_current_namespace_selects_rfc9990_format() -> None:
    """Use RFC 9990 rules when the root declares the current namespace."""
    report = DMARCParser.parse_file(REPORTS / "dmarc-feedback_namespace.xml")

    assert report.format is schema.ReportFormat.RFC_9990
    assert report.namespace == RFC_9990_NAMESPACE
    assert report.version == "1.0"
    assert report.policy_published.discovery_method is schema.DiscoveryMethod.PSL
    assert report.policy_published.pct is None
    assert report.warnings == []


def test_rfc9990_multiple_reported_errors_are_rejected() -> None:
    """Enforce RFC 9990's zero-or-one cardinality for reported errors."""
    content = _replace(
        RFC_9990_XML,
        b"<error>One policy lookup was temporarily unavailable.</error>",
        b"<error>First reported error.</error><error>Second reported error.</error>",
    )

    with pytest.raises(exceptions.ReportStructureError) as caught:
        DMARCParser.parse_bytes(content)

    assert caught.value.code is exceptions.ParseErrorCode.INVALID_STRUCTURE
    assert "<error> field appears more than once" in str(caught.value)


@pytest.mark.parametrize(
    ("content", "limits", "code"),
    [
        (LEGACY_XML, ParserLimits(max_input_bytes=10), exceptions.ParseErrorCode.INPUT_LIMIT_EXCEEDED),
        (
            gzip.compress(LEGACY_XML),
            ParserLimits(max_decompressed_bytes=100),
            exceptions.ParseErrorCode.DECOMPRESSION_LIMIT_EXCEEDED,
        ),
        (RFC_9990_XML, ParserLimits(max_records=1), exceptions.ParseErrorCode.RECORD_LIMIT_EXCEEDED),
        (
            RFC_9990_XML,
            ParserLimits(max_dkim_results_per_record=1),
            exceptions.ParseErrorCode.AUTH_RESULT_LIMIT_EXCEEDED,
        ),
        (RFC_9990_XML, ParserLimits(max_text_bytes=4), exceptions.ParseErrorCode.TEXT_LIMIT_EXCEEDED),
    ],
)
def test_configured_limits_have_stable_error_codes(content, limits, code) -> None:
    """Return one stable resource-limit outcome for each bounded resource."""
    with pytest.raises(exceptions.ResourceLimitError) as caught:
        DMARCParser.parse_bytes(content, limits=limits)

    assert caught.value.code is code


def test_parse_file_enforces_input_limit_during_read() -> None:
    """Apply the same input limit to the file entry point."""
    with pytest.raises(exceptions.ResourceLimitError) as caught:
        DMARCParser.parse_file(REPORTS / "dmarc-sample-1.xml", limits=ParserLimits(max_input_bytes=10))

    assert caught.value.code is exceptions.ParseErrorCode.INPUT_LIMIT_EXCEEDED


def test_zip_member_limit_is_bounded() -> None:
    """Reject excessive zip members before choosing report content."""
    content = _zip_bytes({f"metadata-{index}.txt": b"x" for index in range(3)} | {"report.xml": LEGACY_XML})

    with pytest.raises(exceptions.ResourceLimitError) as caught:
        DMARCParser.parse_bytes(content, limits=ParserLimits(max_zip_members=3))

    assert caught.value.code is exceptions.ParseErrorCode.ZIP_MEMBER_LIMIT_EXCEEDED


@pytest.mark.parametrize(
    ("members", "code"),
    [
        ({"readme.txt": b"not a report"}, exceptions.ParseErrorCode.ARCHIVE_REPORT_MISSING),
        (
            {"one.xml": LEGACY_XML, "two.XML": LEGACY_XML},
            exceptions.ParseErrorCode.ARCHIVE_REPORT_AMBIGUOUS,
        ),
        ({"report.xml.gz": gzip.compress(LEGACY_XML)}, exceptions.ParseErrorCode.NESTED_ARCHIVE),
        ({"report.xml": gzip.compress(LEGACY_XML)}, exceptions.ParseErrorCode.NESTED_ARCHIVE),
    ],
)
def test_zip_structure_has_stable_archive_codes(members, code) -> None:
    """Reject missing, ambiguous, and nested report payloads distinctly."""
    with pytest.raises(exceptions.ArchiveError) as caught:
        DMARCParser.parse_bytes(_zip_bytes(members))

    assert caught.value.code is code


@pytest.mark.parametrize("content", [b"\x1f\x8b\x08broken", b"PK\x03\x04broken"])
def test_corrupt_archives_have_stable_errors(content) -> None:
    """Map corrupt gzip and zip attachments to the archive category."""
    with pytest.raises(exceptions.ArchiveError) as caught:
        DMARCParser.parse_bytes(content)

    assert caught.value.code is exceptions.ParseErrorCode.CORRUPT_ARCHIVE


def test_macos_resource_fork_is_not_an_eligible_zip_report() -> None:
    """Ignore common macOS metadata while still requiring one real XML member."""
    content = _zip_bytes({"report.xml": LEGACY_XML, "__MACOSX/._report.xml": b"metadata"})

    assert DMARCParser.parse_bytes(content).policy_published.domain == "example.com"


@pytest.mark.parametrize(
    ("content", "error_type", "code", "message_part"),
    [
        (b"not xml", exceptions.XMLSyntaxError, exceptions.ParseErrorCode.INVALID_XML, "well-formed XML"),
        (
            b"<not_feedback/>",
            exceptions.ReportStructureError,
            exceptions.ParseErrorCode.INVALID_STRUCTURE,
            "root element must be <feedback>",
        ),
        (
            b'<feedback xmlns="urn:unsupported"><version>1.0</version></feedback>',
            exceptions.UnsupportedReportError,
            exceptions.ParseErrorCode.UNSUPPORTED_REPORT,
            "unsupported XML namespace",
        ),
        (
            _replace(RFC_9990_XML, b"<version>1.0</version>", b"<version>2.0</version>"),
            exceptions.UnsupportedReportError,
            exceptions.ParseErrorCode.UNSUPPORTED_REPORT,
            "version is not supported",
        ),
        (
            _replace(LEGACY_XML, b"<report_id>1234567890</report_id>", b""),
            exceptions.ReportStructureError,
            exceptions.ParseErrorCode.MISSING_FIELD,
            "required <report_id> field is missing from <report_metadata>",
        ),
        (
            _replace(LEGACY_XML, b"<source_ip>203.0.113.1</source_ip>", b"<source_ip>bad ip</source_ip>"),
            exceptions.FieldValueError,
            exceptions.ParseErrorCode.INVALID_VALUE,
            "<source_ip> field in <row> is not a valid IP address",
        ),
    ],
)
def test_malformed_input_categories_are_stable(content, error_type, code, message_part) -> None:
    """Expose a stable category and useful field description without leaking source XML."""
    with pytest.raises(error_type) as caught:
        DMARCParser.parse_bytes(content)

    assert isinstance(caught.value, exceptions.DMARCParseError)
    assert caught.value.code is code
    assert message_part in str(caught.value)


def test_invalid_enum_message_does_not_echo_attacker_value() -> None:
    """Keep attacker-controlled field values out of parser messages."""
    attacker_value = b"invalid-" + b"x" * 1000
    content = _replace(LEGACY_XML, b"<p>quarantine</p>", b"<p>" + attacker_value + b"</p>")

    with pytest.raises(exceptions.FieldValueError) as caught:
        DMARCParser.parse_bytes(content)

    assert attacker_value.decode() not in str(caught.value)
    assert "<p> field" in str(caught.value)


def test_entity_declaration_is_rejected_as_invalid_xml() -> None:
    """Keep XML entity expansion disabled."""
    content = b'<!DOCTYPE feedback [<!ENTITY x "expanded">]><feedback>&x;</feedback>'

    with pytest.raises(exceptions.XMLSyntaxError) as caught:
        DMARCParser.parse_bytes(content)

    assert caught.value.code is exceptions.ParseErrorCode.INVALID_XML


def test_rfc9990_multiple_spf_results_are_rejected() -> None:
    """Enforce RFC 9990's zero-or-one cardinality for SPF results."""
    two_spf = _replace(
        RFC_9990_XML,
        b"</spf>\n    </auth_results>",
        b"</spf><spf><domain>second.example</domain><result>pass</result></spf>\n    </auth_results>",
    )

    with pytest.raises(exceptions.ReportStructureError) as caught:
        DMARCParser.parse_bytes(two_spf)

    assert caught.value.code is exceptions.ParseErrorCode.INVALID_STRUCTURE
    assert "must not contain multiple <spf> results" in str(caught.value)


def test_rfc9990_missing_dkim_selector_is_rejected() -> None:
    """Require the selector element defined by the RFC 9990 DKIM result shape."""
    no_selector = _replace(RFC_9990_XML, b"<selector>abc123</selector>", b"")

    with pytest.raises(exceptions.ReportStructureError) as caught:
        DMARCParser.parse_bytes(no_selector)

    assert caught.value.code is exceptions.ParseErrorCode.MISSING_FIELD
    assert "required <selector> field is missing from <dkim>" in str(caught.value)


def test_rfc9990_blank_dkim_selector_is_preserved_as_none() -> None:
    """Distinguish an explicitly blank selector from an absent required element."""
    blank_selector = _replace(
        RFC_9990_XML,
        b"<selector>abc123</selector>",
        b"<selector></selector>",
    )

    report = DMARCParser.parse_bytes(blank_selector)

    assert report.records[0].auth_results.dkim[0].selector is None


def test_legacy_missing_dkim_selector_remains_accepted() -> None:
    """Keep accepting the selector omission seen in legacy reports."""
    no_selector = _replace(LEGACY_XML, b"<selector>default</selector>", b"")

    report = DMARCParser.parse_bytes(no_selector)

    assert report.records[0].auth_results.dkim[0].selector is None


def test_missing_spf_results_and_empty_optional_envelope_are_preserved() -> None:
    """Keep the rest of a record when optional detail is absent or empty."""
    no_spf = _replace(
        LEGACY_XML,
        b"      <spf>\n        <domain>example.com</domain>\n        <result>pass</result>\n"
        b"        <scope>mfrom</scope>\n      </spf>\n",
        b"",
    )
    empty_envelope_to = _replace(
        RFC_9990_XML,
        b"<envelope_to>recipient.example</envelope_to>",
        b"<envelope_to></envelope_to>",
    )

    assert DMARCParser.parse_bytes(no_spf).records[0].auth_results.spf == []
    assert DMARCParser.parse_bytes(empty_envelope_to).records[0].identifiers.envelope_to == ""


def test_domain_handling_keeps_only_basic_parser_safeguards() -> None:
    """Trim domains and enforce storage/type checks without full DNS validation."""
    whitespace = _replace(
        RFC_9990_XML,
        b"<header_from>mail.example.com</header_from>",
        b"<header_from>  mail.example.com  </header_from>",
    )
    unusual_label = _replace(
        RFC_9990_XML,
        b"<header_from>mail.example.com</header_from>",
        b"<header_from>_mail.example.com</header_from>",
    )
    oversized = _replace(
        RFC_9990_XML,
        b"<header_from>mail.example.com</header_from>",
        b"<header_from>" + b"a" * 254 + b"</header_from>",
    )
    ip_address_domain = _replace(
        RFC_9990_XML,
        b"<header_from>mail.example.com</header_from>",
        b"<header_from>192.0.2.1</header_from>",
    )

    assert DMARCParser.parse_bytes(whitespace).records[0].identifiers.header_from == "mail.example.com"
    assert DMARCParser.parse_bytes(unusual_label).records[0].identifiers.header_from == "_mail.example.com"
    with pytest.raises(exceptions.FieldValueError, match="exceeds 253 characters"):
        DMARCParser.parse_bytes(oversized)
    with pytest.raises(exceptions.FieldValueError, match="must not be an IP address"):
        DMARCParser.parse_bytes(ip_address_domain)


def test_rfc9990_legacy_spf_scope_is_rejected() -> None:
    """Accept only the mfrom scope allowed by RFC 9990 when scope is present."""
    current_helo = _replace(
        RFC_9990_XML,
        b"<scope>mfrom</scope>",
        b"<scope>helo</scope>",
    )

    with pytest.raises(exceptions.FieldValueError) as caught:
        DMARCParser.parse_bytes(current_helo)

    assert caught.value.code is exceptions.ParseErrorCode.INVALID_VALUE
    assert "must be 'mfrom'" in str(caught.value)


def test_rfc9990_legacy_policy_override_is_rejected() -> None:
    """Reject override tokens that were removed from the current schema."""
    current_forwarded = _replace(
        RFC_9990_XML,
        b"<type>local_policy</type>",
        b"<type>forwarded</type>",
    )

    with pytest.raises(exceptions.FieldValueError) as caught:
        DMARCParser.parse_bytes(current_forwarded)

    assert caught.value.code is exceptions.ParseErrorCode.INVALID_VALUE
    assert "legacy policy override value" in str(caught.value)


def test_legacy_understood_values_remain_accepted() -> None:
    """Keep existing tolerance for legacy values used by deployed reporters."""
    legacy_pass = _replace(LEGACY_XML, b"<disposition>none</disposition>", b"<disposition>pass</disposition>")
    legacy_policy_result = _replace(
        LEGACY_XML,
        b"<spf>\n        <domain>example.com</domain>\n        <result>pass</result>",
        b"<spf>\n        <domain>example.com</domain>\n        <result>policy</result>",
    )

    assert DMARCParser.parse_bytes(legacy_pass).records[0].policy_evaluated.disposition is schema.ActionDisposition.PASS
    assert (
        DMARCParser.parse_bytes(legacy_policy_result).records[0].auth_results.spf[0].result is schema.SPFResult.POLICY
    )


@pytest.mark.parametrize("auth_type", ["spf", "dkim"])
@pytest.mark.parametrize("result", [b"Fail", b"FAIL", b"fAiL"])
def test_legacy_auth_result_case_is_normalized(auth_type: str, result: bytes) -> None:
    """Accept the capitalized result seen in JCOM reports and warn callers."""
    original = f"<{auth_type}>\n        <domain>example.com</domain>\n        <result>pass</result>".encode()
    content = _replace(LEGACY_XML, original, original.replace(b"pass", result))

    report = DMARCParser.parse_bytes(gzip.compress(content))

    results = getattr(report.records[0].auth_results, auth_type)
    assert results[0].result.value == "fail"
    assert [warning.code for warning in report.warnings].count("legacy_auth_result_case") == 1


@pytest.mark.parametrize("content", [LEGACY_XML, RFC_9990_XML])
def test_unknown_auth_result_remains_rejected(content: bytes) -> None:
    """Case tolerance must not turn an unknown result into a valid result."""
    content = _replace(content, b"<result>pass</result>", b"<result>Unknown</result>")

    with pytest.raises(exceptions.FieldValueError, match="<result> field contains an invalid value"):
        DMARCParser.parse_bytes(content)


@pytest.mark.parametrize("result", [b"Fail", b"FAIL"])
def test_rfc9990_auth_result_case_remains_strict(result: bytes) -> None:
    """Keep legacy casing tolerance out of the current report format."""
    content = _replace(RFC_9990_XML, b"<result>pass</result>", b"<result>" + result + b"</result>")

    with pytest.raises(exceptions.FieldValueError, match="<result> field contains an invalid value"):
        DMARCParser.parse_bytes(content)


@pytest.mark.parametrize(
    "report_id",
    [
        b"contains whitespace",
        b"double..dot",
        b"two@at@signs",
        b"&lt;unclosed",
        b"non-ascii-\xc4\x81",
    ],
)
def test_rfc9990_invalid_report_id_is_rejected(report_id: bytes) -> None:
    """Reject Report-IDs that do not use RFC 9990's dot-atom syntax."""
    content = _replace(
        RFC_9990_XML,
        b"3v98abbp8ya9n3va8yr8oa3ya",
        report_id,
    )

    with pytest.raises(exceptions.FieldValueError) as caught:
        DMARCParser.parse_bytes(content)

    assert caught.value.code is exceptions.ParseErrorCode.INVALID_VALUE
    assert "RFC 9990 Report-ID format" in str(caught.value)


@pytest.mark.parametrize(
    "report_id",
    [b"report.example", b"report-123@example.test", b"&amp;id@example.test", b"&lt;id@example.test&gt;"],
)
def test_rfc9990_valid_report_id_is_accepted(report_id: bytes) -> None:
    """Accept the plain, at-sign, punctuation, and bracketed RFC forms."""
    content = _replace(
        RFC_9990_XML,
        b"3v98abbp8ya9n3va8yr8oa3ya",
        report_id,
    )

    report = DMARCParser.parse_bytes(content)

    assert report.report_metadata.report_id


def test_rfc9990_multiple_extension_containers_are_ignored() -> None:
    """Ignore extension containers because the package does not consume them."""
    content = _replace(
        RFC_9990_XML,
        b"  <extension>",
        b"  <extension></extension>\n  <extension>",
    )

    report = DMARCParser.parse_bytes(content)

    assert report.policy_published.domain == "example.com"


def test_unknown_and_extension_fields_are_ignored() -> None:
    """Extra fields do not make an otherwise usable report fail to parse."""
    unqualified = _replace(
        RFC_9990_XML,
        b"<vendor:reporter-region>nz</vendor:reporter-region>",
        b"<reporter-region>nz</reporter-region>",
    )
    misplaced = _replace(
        RFC_9990_XML,
        b"<extension>",
        b"<vendor:direct>not allowed</vendor:direct><extension>",
    )
    unknown_policy_field = _replace(
        LEGACY_XML,
        b"<pct>100</pct>",
        b"<pct>100</pct><anything>value</anything>",
    )

    assert DMARCParser.parse_bytes(unqualified).policy_published.domain == "example.com"
    assert DMARCParser.parse_bytes(misplaced).records[0].count == 123
    assert DMARCParser.parse_bytes(unknown_policy_field).policy_published.effective_pct == 100


def test_known_fields_out_of_schema_order_are_still_parsed() -> None:
    """Use field names rather than rejecting usable XML for its ordering."""
    reordered = _replace(RFC_9990_XML, b"  <version>1.0</version>\n", b"")
    reordered = _replace(
        reordered,
        b"  <extension>",
        b"  <version>1.0</version>\n  <extension>",
    )
    reordered = _replace(
        reordered,
        b"        <disposition>pass</disposition>\n        <dkim>pass</dkim>",
        b"        <dkim>pass</dkim>\n        <disposition>pass</disposition>",
    )

    report = DMARCParser.parse_bytes(reordered)

    assert report.version == "1.0"
    assert report.records[0].policy_evaluated.disposition is schema.ActionDisposition.PASS
    assert report.records[0].policy_evaluated.dkim is schema.DMARCResult.PASS


def test_calls_do_not_share_mutable_warning_state() -> None:
    """Return fresh mutable collections on every parser call."""
    first = DMARCParser.parse_bytes(LEGACY_XML)
    second = DMARCParser.parse_bytes(LEGACY_XML)

    first.warnings.clear()
    first.report_metadata.errors.append("caller mutation")
    assert second.warnings
    assert second.report_metadata.errors == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_input_bytes": 0},
        {"max_records": -1},
        {"max_text_bytes": True},
    ],
)
def test_invalid_limit_configuration_is_a_programming_error(kwargs) -> None:
    """Do not mislabel invalid caller configuration as malformed report content."""
    with pytest.raises(ValueError) as caught:
        ParserLimits(**kwargs)

    assert not isinstance(caught.value, exceptions.DMARCParseError)
