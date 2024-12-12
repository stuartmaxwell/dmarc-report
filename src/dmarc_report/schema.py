"""Parse DMARC XML reports and display the results using Rich tables and panels."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import ClassVar, Optional


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

    @property
    def summary_stats(self) -> dict:
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
