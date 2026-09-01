"""Parse a safe XML tree using the legacy or RFC 9990 DMARC rules."""

from __future__ import annotations

from enum import Enum
from ipaddress import ip_address
from typing import TYPE_CHECKING, TypeVar

from dmarc_report import exceptions, schema

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

    from dmarc_report.parser import ParserLimits

LEGACY_NAMESPACE = "http://dmarc.org/dmarc-xml/0.1"  # identifies legacy reports
RFC_9990_NAMESPACE = "urn:ietf:params:xml:ns:dmarc-2.0"  # identifies RFC 9990 reports
RFC_9990_VERSION = "1.0"  # the current schema requires this exact version

_MAX_TIMESTAMP = 253_402_300_799  # keeps UTC dates within year 9999
_MAX_COUNT = 2**63 - 1  # keeps aggregate counts within signed 64-bit storage
_MAX_PERCENTAGE = 100  # enforces the DMARC percentage range
_MAX_DOMAIN_LENGTH = 253  # matches the consuming application's domain field

# Preserve the specific enum type returned by the shared token helpers.  This
# affects static analysis only; it adds no runtime parsing behavior.
_EnumT = TypeVar("_EnumT", bound=Enum)


class DMARCXMLParser:
    """Parse one XML document using the appropriate DMARC rules.

    This class keeps the XML root, safety limits, detected format, namespace,
    and warnings together while one report is parsed. The section methods can
    therefore apply the same DMARC rules without passing that shared state
    through every call.
    """

    def __init__(self, root: Element, limits: ParserLimits) -> None:
        """Detect the report format and retain state needed by every section."""
        namespace, local_name = self._split_tag(root.tag)

        if local_name != "feedback":
            msg = "The XML root element must be <feedback>."
            raise exceptions.ReportStructureError(msg)

        self.root = root
        self.limits = limits
        self.namespace = namespace
        # An empty prefix tells ElementTree to apply this namespace to ordinary
        # field names such as "record". Namespace-free legacy reports use an
        # empty dictionary, so the same lookups work for both report formats.
        self.namespaces = {"": namespace} if namespace is not None else {}
        self.report_format, self.warnings = self._detect_format()

    def parse(self) -> schema.Report:
        """Detect the format, validate the root, and parse every report section."""
        # Check the required top-level structure before parsing any section.
        metadata_element = self._required_child(self.root, "report_metadata")
        policy_element = self._required_child(self.root, "policy_published")
        record_elements = self.root.findall("record", self.namespaces)
        if not record_elements:
            msg_0 = "The report must contain at least one record."
            raise exceptions.ReportStructureError(
                msg_0,
                code=exceptions.ParseErrorCode.MISSING_FIELD,
            )
        if len(record_elements) > self.limits.max_records:
            msg_1 = "The report exceeds the configured record limit."
            raise exceptions.ResourceLimitError(
                msg_1,
                code=exceptions.ParseErrorCode.RECORD_LIMIT_EXCEEDED,
            )

        version = self._parse_version()
        return schema.Report(
            report_metadata=self._parse_metadata(metadata_element),
            policy_published=self._parse_policy(policy_element),
            records=[self._parse_record(element) for element in record_elements],
            format=self.report_format,
            namespace=self.namespace,
            version=version,
            warnings=self.warnings,
        )

    def _detect_format(self) -> tuple[schema.ReportFormat, list[schema.ParserWarning]]:
        """Choose the schema rules without trusting the attachment filename.

        Most deployed reports omit a namespace and must be treated as legacy.
        Explicit legacy and RFC 9990 namespaces select their respective schemas;
        any other namespace is unsupported.
        """
        if self.namespace is None:
            warning = schema.ParserWarning(
                code="legacy_no_namespace",
                message="A namespace-free report was accepted as legacy DMARC XML.",
            )
            return schema.ReportFormat.LEGACY, [warning]

        if self.namespace == LEGACY_NAMESPACE:
            return schema.ReportFormat.LEGACY, []

        if self.namespace == RFC_9990_NAMESPACE:
            return schema.ReportFormat.RFC_9990, []

        msg = "The report uses an unsupported XML namespace."
        raise exceptions.UnsupportedReportError(msg)

    def _parse_version(self) -> str | None:
        """Validate a format-specific version and tolerate either format omitting it."""
        version_element = self._optional_child(self.root, "version")
        if version_element is None:
            if self.report_format is schema.ReportFormat.LEGACY:
                self._warn(
                    "legacy_missing_version",
                    "A legacy report without a root version was accepted.",
                )
            return None

        version = self._text(version_element).strip()
        if self.report_format is schema.ReportFormat.RFC_9990 and version != RFC_9990_VERSION:
            msg = "The report version is not supported."
            raise exceptions.UnsupportedReportError(msg)
        if self.report_format is schema.ReportFormat.LEGACY and not self._is_decimal(version):
            msg_0 = "The <version> field in a legacy report must contain a decimal value."
            raise exceptions.FieldValueError(msg_0)
        return version

    def _is_decimal(self, value: str) -> bool:
        """Return whether text uses the XML Schema decimal lexical form."""
        unsigned = value[1:] if value.startswith(("+", "-")) else value
        integer, separator, fraction = unsigned.partition(".")
        if separator and "." in fraction:
            return False
        digits = integer + fraction
        return bool(digits) and all("0" <= character <= "9" for character in digits)

    def _parse_metadata(self, element: Element) -> schema.ReportMetadata:
        """Parse reporter identity, report period, and generator diagnostics."""
        if self.report_format is schema.ReportFormat.RFC_9990:
            # RFC 9990 allows zero or one <error>, _optional_text raises an error if multiple are found.
            error = self._optional_text(element, "error")
            # Save as a list to be consistent with legacy reports.
            errors = [] if error is None else [error]
        else:
            # The legacy format permits multiple <error> elements.
            errors = [self._text(error) for error in element.findall("error", self.namespaces)]

        date_element = self._required_child(element, "date_range")
        begin = self._required_integer(date_element, "begin")
        end = self._required_integer(date_element, "end")

        if not 0 <= begin <= _MAX_TIMESTAMP:
            msg_0 = "The report start timestamp is out of range."
            raise exceptions.FieldValueError(msg_0)
        if not 0 <= end <= _MAX_TIMESTAMP:
            msg_1 = "The report end timestamp is out of range."
            raise exceptions.FieldValueError(msg_1)
        if end < begin:
            msg_2 = "The report period ends before it begins."
            raise exceptions.FieldValueError(msg_2)

        return schema.ReportMetadata(
            org_name=self._required_text(element, "org_name"),
            email=self._required_text(element, "email"),
            extra_contact_info=self._optional_text(element, "extra_contact_info"),
            report_id=self._parse_report_id(element),
            date_range=schema.DateRange(begin=begin, end=end),
            errors=errors,
            generator=self._optional_text(element, "generator"),
        )

    def _parse_report_id(self, element: Element) -> str:
        """Read Report-ID and enforce the RFC 9990 dot-atom form when current.

        Legacy generators use a wide variety of identifiers, so their non-empty
        text remains untouched. RFC 9990 defines a dot-atom value, optionally
        containing an ``@`` and optionally enclosed in angle brackets.
        """
        report_id = self._required_text(element, "report_id")
        if self.report_format is schema.ReportFormat.RFC_9990 and not self._is_valid_report_id(report_id):
            msg = "The <report_id> field does not use the RFC 9990 Report-ID format."
            raise exceptions.FieldValueError(msg)
        return report_id

    def _is_valid_report_id(self, value: str) -> bool:
        """Return whether a value has RFC 9990's simple Report-ID structure."""
        if value.startswith("<") and value.endswith(">"):
            value = value[1:-1]
        elif value.startswith("<") or value.endswith(">"):
            return False

        if value.count("@") > 1:
            return False
        return all(self._is_dot_atom(part) for part in value.split("@"))

    def _is_dot_atom(self, value: str) -> bool:
        """Validate RFC 5322 dot-atom text without a regular expression."""
        report_id_symbols = frozenset("!#$%&'*+-/=?^_`{|}~")  # RFC 5322 atext punctuation

        atoms = value.split(".")
        return bool(value) and all(
            atom
            and all(
                character.isascii() and (character.isalnum() or character in report_id_symbols) for character in atom
            )
            for atom in atoms
        )

    def _parse_policy(self, element: Element) -> schema.PolicyPublished:
        """Parse source policy values while leaving standard defaults explicit."""
        published_policy = self._required_enum(element, "p", schema.PublishedPolicy)

        # A missing sp inherits p. Known legacy reports also send an empty sp,
        # but RFC 9990 requires a valid policy whenever the element is present.
        sp_text = self._optional_text(element, "sp")
        if sp_text is None:
            subdomain_policy = None
        elif not sp_text.strip():
            if self.report_format is schema.ReportFormat.RFC_9990:
                msg = "The <sp> field contains an invalid value."
                raise exceptions.FieldValueError(msg)
            subdomain_policy = None
        else:
            subdomain_policy = self._enum_value(
                sp_text,
                schema.PublishedPolicy,
                "sp",
            )

        # pct belongs only to the legacy format.  The dataclass preserves an
        # omitted value as None; callers can request the standard default through
        # PolicyPublished.effective_pct.
        percentage: int | None = None
        if self.report_format is schema.ReportFormat.LEGACY:
            percentage_text = self._optional_text(element, "pct")
            if percentage_text is None:
                self._warn("legacy_missing_pct", "A missing legacy <pct> value defaults to 100.")
            else:
                percentage = self._parse_integer(percentage_text, "pct")
                if not 0 <= percentage <= _MAX_PERCENTAGE:
                    msg_0 = "The pct value must be between 0 and 100."
                    raise exceptions.FieldValueError(msg_0)

        nonexistent_policy = self._optional_enum(element, "np", schema.PublishedPolicy)
        if self.report_format is schema.ReportFormat.LEGACY and nonexistent_policy is not None:
            # Google emits np in otherwise legacy-shaped reports.  Retain the
            # useful policy while making the producer extension visible.
            self._warn(
                "legacy_np_extension",
                "A legacy report's <np> policy extension was retained.",
            )

        return schema.PolicyPublished(
            domain=self._required_domain(element, "domain"),
            p=published_policy,
            sp=subdomain_policy,
            pct=percentage,
            adkim=self._optional_enum(element, "adkim", schema.AlignmentMode),
            aspf=self._optional_enum(element, "aspf", schema.AlignmentMode),
            fo=self._optional_text(element, "fo"),
            np=nonexistent_policy,
            testing=self._optional_enum(element, "testing", schema.TestingMode),
            discovery_method=self._optional_enum(
                element,
                "discovery_method",
                schema.DiscoveryMethod,
            ),
            report_format=self.report_format,
        )

    def _parse_record(self, element: Element) -> schema.Record:
        """Parse one aggregate row and its message identifiers/authentication data."""
        # Find every required section before parsing the record's contents.
        row = self._required_child(element, "row")
        identifiers = self._required_child(element, "identifiers")
        auth_results = self._required_child(element, "auth_results")

        source_ip_text = self._required_text(row, "source_ip")
        try:
            source_ip = str(ip_address(source_ip_text))
        except ValueError as error:
            msg = "The <source_ip> field in <row> is not a valid IP address."
            raise exceptions.FieldValueError(msg) from error

        count = self._required_integer(row, "count")
        if not 1 <= count <= _MAX_COUNT:
            msg_0 = "The <count> field in <row> must be a positive 64-bit integer."
            raise exceptions.FieldValueError(msg_0)

        evaluated = self._required_child(row, "policy_evaluated")
        return schema.Record(
            source_ip=source_ip,
            count=count,
            policy_evaluated=self._parse_policy_evaluated(evaluated),
            identifiers=self._parse_identifiers(identifiers),
            auth_results=self._parse_auth_results(auth_results),
        )

    def _parse_policy_evaluated(self, element: Element) -> schema.PolicyEvaluated:
        """Parse the receiver's applied action and DMARC alignment results."""
        reasons = [self._parse_reason(reason) for reason in element.findall("reason", self.namespaces)]
        return schema.PolicyEvaluated(
            disposition=self._required_enum(element, "disposition", schema.ActionDisposition),
            dkim=self._required_enum(element, "dkim", schema.DMARCResult),
            spf=self._required_enum(element, "spf", schema.DMARCResult),
            reasons=reasons,
        )

    def _parse_reason(self, element: Element) -> schema.PolicyOverrideReason:
        """Parse one standards-defined reason for overriding the published policy."""
        reason_type = self._required_enum(element, "type", schema.PolicyOverrideType)
        if self.report_format is schema.ReportFormat.RFC_9990 and reason_type in {
            schema.PolicyOverrideType.FORWARDED,
            schema.PolicyOverrideType.SAMPLED_OUT,
        }:
            msg = "The <type> field contains a legacy policy override value in an RFC 9990 report."
            raise exceptions.FieldValueError(msg)
        return schema.PolicyOverrideReason(
            type=reason_type,
            comment=self._optional_text(element, "comment"),
        )

    def _parse_identifiers(self, element: Element) -> schema.Identifier:
        """Parse the domains used to identify and evaluate the message."""
        return schema.Identifier(
            header_from=self._required_domain(element, "header_from"),
            envelope_from=self._optional_domain(element, "envelope_from"),
            envelope_to=self._optional_domain(element, "envelope_to"),
        )

    def _parse_auth_results(self, element: Element) -> schema.AuthResults:
        """Enforce configured result limits and parse DKIM and SPF details."""
        dkim_elements = element.findall("dkim", self.namespaces)
        spf_elements = element.findall("spf", self.namespaces)

        if len(dkim_elements) > self.limits.max_dkim_results_per_record:
            msg = "The record exceeds the configured DKIM result limit."
            raise exceptions.ResourceLimitError(
                msg,
                code=exceptions.ParseErrorCode.AUTH_RESULT_LIMIT_EXCEEDED,
            )
        if self.report_format is schema.ReportFormat.RFC_9990 and len(spf_elements) > 1:
            msg_0 = "The <auth_results> field in an RFC 9990 report must not contain multiple <spf> results."
            raise exceptions.ReportStructureError(msg_0)
        if len(spf_elements) > self.limits.max_spf_results_per_record:
            msg_1 = "The record exceeds the configured SPF result limit."
            raise exceptions.ResourceLimitError(
                msg_1,
                code=exceptions.ParseErrorCode.AUTH_RESULT_LIMIT_EXCEEDED,
            )
        return schema.AuthResults(
            dkim=[self._parse_dkim_result(result) for result in dkim_elements],
            spf=[self._parse_spf_result(result) for result in spf_elements],
        )

    def _parse_dkim_result(self, element: Element) -> schema.DKIMAuthResult:
        """Parse one underlying DKIM authentication result."""
        if self.report_format is schema.ReportFormat.RFC_9990:
            # The element is required in RFC 9990. An explicitly blank string
            # still satisfies the XML shape but carries no useful selector.
            selector_text = self._text(self._required_child(element, "selector"))
        else:
            selector_text = self._optional_text(element, "selector")
        selector = None if selector_text is None or not selector_text.strip() else selector_text

        return schema.DKIMAuthResult(
            domain=self._required_domain(element, "domain"),
            selector=selector,
            result=self._required_enum(element, "result", schema.DKIMResult),
            human_result=self._optional_text(element, "human_result"),
        )

    def _parse_spf_result(self, element: Element) -> schema.SPFAuthResult:
        """Parse one underlying SPF authentication result."""
        scope = self._optional_enum(element, "scope", schema.SPFScope)
        if (
            self.report_format is schema.ReportFormat.RFC_9990
            and scope is not None
            and scope is not schema.SPFScope.MFROM
        ):
            msg = "The <scope> field in an RFC 9990 report must be 'mfrom'."
            raise exceptions.FieldValueError(msg)
        return schema.SPFAuthResult(
            domain=self._required_domain(element, "domain"),
            scope=scope,
            result=self._required_enum(element, "result", schema.SPFResult),
            human_result=self._optional_text(element, "human_result"),
        )

    # Value parsing -----------------------------------------------------------
    #
    # These helpers read and validate machine-readable DMARC values.

    def _required_enum(
        self,
        parent: Element,
        name: str,
        enum_type: type[_EnumT],
    ) -> _EnumT:
        """Read a required field and convert its exact text to the requested enum."""
        return self._enum_value(self._required_text(parent, name), enum_type, name)

    def _optional_enum(
        self,
        parent: Element,
        name: str,
        enum_type: type[_EnumT],
    ) -> _EnumT | None:
        """Convert an optional token without inventing a source value."""
        value = self._optional_text(parent, name)
        return None if value is None else self._enum_value(value, enum_type, name)

    def _enum_value(self, value: str, enum_type: type[_EnumT], field_name: str) -> _EnumT:
        """Convert a case-sensitive XML value without exposing bad input in errors."""
        try:
            return enum_type(value)
        except ValueError as error:
            msg = f"The <{field_name}> field contains an invalid value."
            raise exceptions.FieldValueError(msg) from error

    def _required_integer(self, parent: Element, name: str) -> int:
        """Read a required child field and return its value as an integer."""
        value = self._required_text(parent, name)
        return self._parse_integer(value, name)

    def _parse_integer(self, value: str, field_name: str) -> int:
        """Parse the ASCII decimal form required for a named DMARC field."""
        normalized = value.strip()
        digits = normalized[1:] if normalized.startswith(("+", "-")) else normalized
        if not digits or any(character < "0" or character > "9" for character in digits):
            msg = f"The <{field_name}> field must contain an integer."
            raise exceptions.FieldValueError(msg)
        try:
            return int(normalized)
        except ValueError as error:
            msg_0 = f"The integer in <{field_name}> is too large."
            raise exceptions.FieldValueError(msg_0) from error

    def _required_domain(self, parent: Element, name: str) -> str:
        """Read a required domain and apply the parser's basic safeguards."""
        value = self._required_text(parent, name).strip()
        self._validate_domain(value, name)
        return value

    def _optional_domain(self, parent: Element, name: str) -> str | None:
        """Read an optional domain, preserving absence and an empty envelope."""
        value = self._optional_text(parent, name)
        if value is None:
            return value
        value = value.strip()
        if not value:
            return ""
        self._validate_domain(value, name)
        return value

    def _validate_domain(self, value: str, field_name: str) -> None:
        """Apply only the domain checks needed by this package and its consumer.

        Detailed DNS and IDNA validation belongs to the application using the
        report. The package only enforces its 253-character storage contract and
        rejects an IP address where the report promises a domain.

        Args:
            value: The domain text read from the report.
            field_name: The XML field name used in any error message.

        Raises:
            FieldValueError: If the value is too long, empty after a trailing
                root dot is removed, or an IP address.
        """
        domain = value.removesuffix(".")
        if not domain:
            msg = f"The <{field_name}> domain must not be empty."
            raise exceptions.FieldValueError(msg)
        if len(value) > _MAX_DOMAIN_LENGTH:
            msg_0 = f"The <{field_name}> domain exceeds 253 characters."
            raise exceptions.FieldValueError(msg_0)

        # An IP literal is valid text, but DMARC domain fields specifically require
        # DNS names.  Source IP addresses are parsed separately in _parse_record.
        try:
            ip_address(domain)
        except ValueError:
            pass
        else:
            msg_1 = f"The <{field_name}> domain must not be an IP address."
            raise exceptions.FieldValueError(msg_1)

    def _split_tag(self, tag: str) -> tuple[str | None, str]:
        """Separate a tag so both deployed legacy and namespaced reports work.

        Most current producers omit an XML namespace, while RFC 9990 and some
        legacy reports include one. For example, ElementTree stores this:

        `<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">`

        as `{urn:ietf:params:xml:ns:dmarc-2.0}feedback`.

        This method returns it as
        `("urn:ietf:params:xml:ns:dmarc-2.0", "feedback")`.

        Format detection and known-field lookups need the namespace and local name independently.
        """
        if tag.startswith("{"):
            namespace, separator, local_name = tag[1:].partition("}")
            if separator:
                return namespace, local_name
        return None, tag

    def _element_name(self, element: Element) -> str:
        """Return an element's local name for use in an error message."""
        _, local_name = self._split_tag(element.tag)
        return local_name

    # XML field access ------------------------------------------------------
    #
    # These methods keep repeated ElementTree details out of the DMARC section
    # parsers. They all use this report's namespace, limits, and warning list.

    def _warn(self, code: str, message: str) -> None:
        """Record a tolerated producer deviation so it is not silent."""
        self.warnings.append(schema.ParserWarning(code=code, message=message))

    def _required_child(self, parent: Element, name: str) -> Element:
        """Return a required direct child after checking its cardinality.

        Args:
            parent: The XML element expected to contain the field.
            name: The required child field name.

        Returns:
            The single matching child element.

        Raises:
            ReportStructureError: If the field is missing or appears more than
                once.
        """
        children = parent.findall(name, self.namespaces)
        parent_name = self._element_name(parent)
        if not children:
            msg = f"The required <{name}> field is missing from <{parent_name}>."
            raise exceptions.ReportStructureError(
                msg,
                code=exceptions.ParseErrorCode.MISSING_FIELD,
            )
        if len(children) > 1:
            msg = f"The <{name}> field appears more than once in <{parent_name}>."
            raise exceptions.ReportStructureError(msg)
        return children[0]

    def _optional_child(self, parent: Element, name: str) -> Element | None:
        """Return an optional direct child after checking for duplicates.

        Args:
            parent: The XML element that may contain the field.
            name: The optional child field name.

        Returns:
            The matching child, or ``None`` when the field is absent.

        Raises:
            ReportStructureError: If the optional field appears more than once.
        """
        children = parent.findall(name, self.namespaces)
        if len(children) > 1:
            parent_name = self._element_name(parent)
            msg = f"The <{name}> field appears more than once in <{parent_name}>."
            raise exceptions.ReportStructureError(msg)
        return children[0] if children else None

    def _required_text(self, parent: Element, name: str) -> str:
        """Read a required field whose text must not be empty or oversized.

        Args:
            parent: The XML element expected to contain the field.
            name: The required child field name.

        Returns:
            The field text exactly as reported.

        Raises:
            ReportStructureError: If the child is missing or duplicated.
            FieldValueError: If the child contains only blank text.
            ResourceLimitError: If the text exceeds the configured limit.
        """
        value = self._text(self._required_child(parent, name))
        if not value.strip():
            parent_name = self._element_name(parent)
            msg = f"The required <{name}> field in <{parent_name}> must not be empty."
            raise exceptions.FieldValueError(
                msg,
                code=exceptions.ParseErrorCode.MISSING_FIELD,
            )
        return value

    def _optional_text(self, parent: Element, name: str) -> str | None:
        """Return None for a missing field but preserve an explicitly empty one."""
        child = self._optional_child(parent, name)
        return None if child is None else self._text(child)

    def _text(self, element: Element) -> str:
        """Return element text after enforcing the configured byte limit.

        Args:
            element: The XML field whose direct text will be read.

        Returns:
            The text exactly as reported, or an empty string when there is no
            text.

        Raises:
            ResourceLimitError: If the UTF-8 text exceeds ``max_text_bytes``.
        """
        value = element.text or ""
        if len(value.encode("utf-8")) > self.limits.max_text_bytes:
            element_name = self._element_name(element)
            msg = f"The <{element_name}> field exceeds the configured text size limit."
            raise exceptions.ResourceLimitError(
                msg,
                code=exceptions.ParseErrorCode.TEXT_LIMIT_EXCEEDED,
            )
        return value
