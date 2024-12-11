"""Report Schema for DMARC Aggregate Reports.

XML Schema: https://dmarc.org/dmarc-xml/0.1/rua.xsd
Saved to this repository as `dmarc-xml_0.1_rua.xsd`.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel
from pydantic.networks import IPvAnyAddress


class DateRangeType(BaseModel):
    """The time range in UTC covered by messages in this report, specified in seconds since epoch.

    ```xml
    <!-- The time range in UTC covered by messages in this report, specified in seconds since epoch. -->
    <xs:complexType name="DateRangeType">
    <xs:all>
        <xs:element name="begin" type="xs:integer"/>
        <xs:element name="end" type="xs:integer"/>
    </xs:all>
    </xs:complexType>
    ```
    """

    begin: datetime
    end: datetime

    def __str__(self) -> str:
        """Return formatted date range string."""
        return f"{self.format_timestamp(self.begin)} to {self.format_timestamp(self.end)}"

    @staticmethod
    def format_timestamp(date_object: int) -> str:
        """Convert UTC Unix timestamp to formatted UTC date string."""
        return date_object.strftime("%Y-%m-%d %H:%M:%S UTC")


class ReportMetadataType(BaseModel):
    """Report generator metadata.

    ```xml
    <!-- Report generator metadata -->
    <xs:complexType name="ReportMetadataType">
    <xs:sequence>
        <xs:element name="org_name" type="xs:string"/>
        <xs:element name="email" type="xs:string"/>
        <xs:element name="extra_contact_info" type="xs:string" minOccurs="0"/>
        <xs:element name="report_id" type="xs:string"/>
        <xs:element name="date_range" type="DateRangeType"/>
        <xs:element name="error" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    ```
    """

    org_name: str
    email: str
    report_id: str
    date_range: DateRangeType
    extra_contact_info: Optional[str] = None
    errors: Optional[list[str]] = None


class AlignmentType(str, Enum):
    """Alignment mode (relaxed or strict) for DKIM and SPF.

    ```xml
    <!-- Alignment mode (relaxed or strict) for DKIM and SPF. -->
    <xs:simpleType name="AlignmentType">
    <xs:restriction base="xs:string">
        <xs:enumeration value="r"/>
        <xs:enumeration value="s"/>
    </xs:restriction>
    </xs:simpleType>
    ```
    """

    RELAXED = "r"
    STRICT = "s"


class DispositionType(str, Enum):
    """The policy actions specified by p and sp in the DMARC record.

    ```xml
    <!-- The policy actions specified by p and sp in the DMARC record. -->
    <xs:simpleType name="DispositionType">
    <xs:restriction base="xs:string">
        <xs:enumeration value="none"/>
        <xs:enumeration value="quarantine"/>
        <xs:enumeration value="reject"/>
    </xs:restriction>
    </xs:simpleType>
    ```
    """

    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class PolicyPublishedType(BaseModel):
    """The DMARC policy that applied to the messages in this report.

    ```xml
    <!-- The DMARC policy that applied to the messages in this report. -->
    <xs:complexType name="PolicyPublishedType">
    <xs:all>
        <!-- The domain at which the DMARC record was found. -->
        <xs:element name="domain" type="xs:string"/>
        <!-- The DKIM alignment mode. -->
        <xs:element name="adkim" type="AlignmentType"/>
        <!-- The SPF alignment mode. -->
        <xs:element name="aspf" type="AlignmentType"/>
        <!-- The policy to apply to messages from the domain. -->
        <xs:element name="p" type="DispositionType"/>
        <!-- The policy to apply to messages from subdomains. -->
        <xs:element name="sp" type="DispositionType"/>
        <!-- The percent of messages to which policy applies. -->
        <xs:element name="pct" type="xs:integer"/>
    </xs:all>
    </xs:complexType>
    ```
    """

    domain: str
    adkim: AlignmentType
    aspf: AlignmentType
    p: DispositionType
    sp: DispositionType
    pct: int


class DMARCResultType(str, Enum):
    """The DMARC-aligned authentication result.

    ```xml
    <!-- The DMARC-aligned authentication result. -->
    <xs:simpleType name="DMARCResultType">
    <xs:restriction base="xs:string">
        <xs:enumeration value="pass"/>
        <xs:enumeration value="fail"/>
    </xs:restriction>
    </xs:simpleType>
    ```
    """

    PASS = "pass"  # noqa: S105
    FAIL = "fail"


class PolicyOverrideTyope(str, Enum):
    """Reasons that may affect DMARC disposition or execution thereof.

    ```xml
    <!-- Reasons that may affect DMARC disposition or execution thereof. -->
    <!-- ==============================================================
    Descriptions of the PolicyOverrideTypes:

    forwarded:  Message was relayed via a known forwarder, or local
    heuristics identified the message as likely having been forwarded.
    There is no expectation that authentication would pass.

    local_policy:  The Mail Receiver's local policy exempted the message
    from being subjected to the Domain Owner's requested policy
    action.

    mailing_list:  Local heuristics determined that the message arrived
    via a mailing list, and thus authentication of the original
    message was not expected to succeed.

    other:  Some policy exception not covered by the other entries in
    this list occurred.  Additional detail can be found in the
    PolicyOverrideReason's "comment" field.

    sampled_out:  Message was exempted from application of policy by the
    "pct" setting in the DMARC policy record.

    trusted_forwarder:  Message authentication failure was anticipated by
    other evidence linking the message to a locally-maintained list of
    known and trusted forwarders.
    ============================================================== -->
    ```
    """

    FORWARDED = "forwarded"
    SAMPLED_OUT = "sampled_out"
    TRUSTED_FORWARDER = "trusted_forwarder"
    MAILING_LIST = "mailing_list"
    LOCAL_POLICY = "local_policy"
    OTHER = "other"


class PolicyOverrideReason(BaseModel):
    """How do we allow report generators to include new classes of override reasons.

    How do we allow report generators to include new classes of override reasons if they want to be more specific
    than "other"?

    ```xml
    <!-- How do we allow report generators to include new classes of override reasons if they want to be more specific
        than "other"? -->
    <xs:complexType name="PolicyOverrideReason">
    <xs:all>
        <xs:element name="type" type="PolicyOverrideType"/>
        <xs:element name="comment" type="xs:string" minOccurs="0"/>
    </xs:all>
    </xs:complexType>
    ```
    """

    type: PolicyOverrideTyope
    comment: Optional["str"] = None


class PolicyEvaluatedType(BaseModel):
    """Taking into account everything else in the record, the results of applying DMARC.

    The PolicyEvaluatedType object corresponds to the <policy_evaluated> element in the <record> element of DMARC XML
    report.

    ```xml
    <!-- Taking into account everything else in the record, the results of applying DMARC. -->
    <xs:complexType name="PolicyEvaluatedType">
    <xs:sequence>
        <xs:element name="disposition" type="DispositionType"/>
        <xs:element name="dkim" type="DMARCResultType"/>
        <xs:element name="spf" type="DMARCResultType"/>
        <xs:element name="reason" type="PolicyOverrideReason" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    ```
    """

    disposition: DispositionType
    dkim: DMARCResultType
    spf: DMARCResultType
    reason: Optional[list[PolicyOverrideReason]] = None


class RowType(BaseModel):
    """RowType.

    ```xml
    <xs:complexType name="RowType">
    <xs:all>
        <!-- The connecting IP. -->
        <xs:element name="source_ip" type="IPAddress"/>
        <!-- The number of matching messages -->
        <xs:element name="count" type="xs:integer"/>
        <!-- The DMARC disposition applying to matching messages. -->
        <xs:element name="policy_evaluated" type="PolicyEvaluatedType" minOccurs="0"/>
    </xs:all>
    </xs:complexType>
    ```
    """

    source_ip: IPvAnyAddress
    count: int
    policy_evaluated: PolicyEvaluatedType


class IdentifierType(BaseModel):
    """IdentifierType.

    ```xml
    <xs:complexType name="IdentifierType">
    <xs:all>
        <!-- The envelope recipient domain. -->
        <xs:element name="envelope_to" type="xs:string" minOccurs="0"/>
        <!-- The payload From domain. -->
        <xs:element name="header_from" type="xs:string" minOccurs="1"/>
    </xs:all>
    </xs:complexType>
    ```
    """

    header_from: str
    envelope_to: Optional[str] = None


class DKIMResultType(Enum):
    """DKIM verification result, according to RFC 5451 Section 2.4.1.

    ```xml
    <!-- DKIM verification result, according to RFC 5451 Section 2.4.1. -->
    <xs:simpleType name="DKIMResultType">
    <xs:restriction base="xs:string">
        <xs:enumeration value="none"/>
        <xs:enumeration value="pass"/>
        <xs:enumeration value="fail"/>
        <xs:enumeration value="policy"/>
        <xs:enumeration value="neutral"/>
        <xs:enumeration value="temperror"/>
        <xs:enumeration value="permerror"/>
    </xs:restriction>
    </xs:simpleType>
    ```
    """

    NONE = "none"
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    POLICY = "policy"
    NEUTRAL = "neutral"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class DKIMAuthResultType(BaseModel):
    """DKIMAuthResultType.

    ```xml
    <xs:complexType name="DKIMAuthResultType">
    <xs:all>
        <!-- The d= parameter in the signature -->
        <xs:element name="domain" type="xs:string" minOccurs="1"/>
        <!-- The "s=" parameter in the signature. -->
        <xs:element name="selector" type="xs:string" minOccurs="0"/>
        <!-- The DKIM verification result -->
        <xs:element name="result" type="DKIMResultType" minOccurs="1"/>
        <!-- Any extra information (e.g., from Authentication-Results -->
        <xs:element name="human_result" type="xs:string" minOccurs="0"/>
    </xs:all>
    </xs:complexType>
    ```
    """

    domain: str
    result: DKIMResultType
    selector: Optional[str] = None
    human_result: Optional[str] = None


class SPFResultType(Enum):
    """SPF result.

    ```xml
    <!-- SPF result -->
    <xs:simpleType name="SPFResultType">
    <xs:restriction base="xs:string">
        <xs:enumeration value="none"/>
        <xs:enumeration value="neutral"/>
        <xs:enumeration value="pass"/>
        <xs:enumeration value="fail"/>
        <xs:enumeration value="softfail"/>
        <!-- "TempError" commonly implemented as "unknown" -->
        <xs:enumeration value="temperror"/>
        <!-- "PermError" commonly implemented as "error" -->
        <xs:enumeration value="permerror"/>
    </xs:restriction>
    </xs:simpleType>
    ```
    """

    NONE = "none"
    NEUTRAL = "neutral"
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    SOFTFAIL = "softfail"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class SPFAuthResult(BaseModel):
    """SPFAuthResultType.

    ```xml
    <xs:complexType name="SPFAuthResultType">
    <xs:all>
        <!-- The envelope From domain. -->
        <xs:element name="domain" type="xs:string" minOccurs="1"/>
        <!-- The SPF verification result -->
        <xs:element name="result" type="SPFResultType" minOccurs="1"/>
    </xs:all>
    </xs:complexType>
    ```
    """

    domain: str
    result: SPFResultType


class AuthResultType(BaseModel):
    """This element contains DKIM and SPF results, uninterpreted with respect to DMARC.

    ```xml
    <!-- This element contains DKIM and SPF results, uninterpreted with respect to DMARC. -->
    <xs:complexType name="AuthResultType">
    <xs:sequence>
        <!-- There may be no DKIM signatures, or multiple DKIM signatures. -->
        <xs:element name="dkim" type="DKIMAuthResultType" minOccurs="0" maxOccurs="unbounded"/>
        <!-- There will always be at least one SPF result. -->
        <xs:element name="spf" type="SPFAuthResultType" minOccurs="1" maxOccurs="unbounded"/>
    </xs:sequence>
    </xs:complexType>
    ```
    """

    spf: list[SPFAuthResult]
    dkim: Optional[list[DKIMAuthResultType]]


class RecordType(BaseModel):
    """This element contains all the authentication results.

    This element contains all the authentication results used to evaluate the DMARC disposition for the given set of
    messages.

    ```xml
    <!-- This element contains all the authentication results used to evaluate the DMARC disposition for the given set
    of messages. -->
    <xs:complexType name="RecordType">
    <xs:sequence>
        <xs:element name="row" type="RowType"/>
        <xs:element name="identifiers" type="IdentifierType"/>
        <xs:element name="auth_results" type="AuthResultType"/>
    </xs:sequence>
    </xs:complexType>
    ```
    """

    row: RowType
    identifiers: IdentifierType
    auth_results: AuthResultType


class Feedback(BaseModel):
    """Parent.

    ```xml
    <!-- Parent -->
    <xs:element name="feedback">
    <xs:complexType>
        <xs:sequence>
        <xs:element name="report_metadata" type="ReportMetadataType"/>
        <xs:element name="policy_published" type="PolicyPublishedType"/>
        <xs:element name="record" type="RecordType" maxOccurs="unbounded"/>
        </xs:sequence>
    </xs:complexType>
    </xs:element>
    </xs:schema>
    ```
    """

    report_metadata: ReportMetadataType
    policy_published: PolicyPublishedType
    records: list[RecordType]
