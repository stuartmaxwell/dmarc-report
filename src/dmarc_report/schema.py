"""Typed schema returned by the DMARC aggregate report parser."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class PublishedPolicy(str, Enum):
    """A policy published by a domain owner."""

    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class ActionDisposition(str, Enum):
    """The action a receiver applied to a group of messages."""

    NONE = "none"
    PASS = "pass"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class DMARCResult(str, Enum):
    """A DKIM or SPF DMARC identifier-alignment result."""

    PASS = "pass"
    FAIL = "fail"


class DKIMResult(str, Enum):
    """An underlying DKIM authentication result."""

    NONE = "none"
    PASS = "pass"
    FAIL = "fail"
    POLICY = "policy"
    NEUTRAL = "neutral"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class SPFResult(str, Enum):
    """An underlying SPF authentication result."""

    NONE = "none"
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    POLICY = "policy"
    NEUTRAL = "neutral"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"


class AlignmentMode(str, Enum):
    """A DKIM or SPF identifier-alignment mode."""

    RELAXED = "r"
    STRICT = "s"


class SPFScope(str, Enum):
    """The identity used for an SPF authentication result."""

    MFROM = "mfrom"
    HELO = "helo"


class PolicyOverrideType(str, Enum):
    """A standards-defined reason for overriding the published policy."""

    LOCAL_POLICY = "local_policy"
    MAILING_LIST = "mailing_list"
    OTHER = "other"
    POLICY_TEST_MODE = "policy_test_mode"
    TRUSTED_FORWARDER = "trusted_forwarder"
    FORWARDED = "forwarded"
    SAMPLED_OUT = "sampled_out"


class DiscoveryMethod(str, Enum):
    """The method used to discover the applicable DMARC policy."""

    PSL = "psl"
    TREEWALK = "treewalk"


class TestingMode(str, Enum):
    """Whether the published policy requested testing mode."""

    NO = "n"
    YES = "y"


class ReportFormat(str, Enum):
    """The recognized aggregate report format family."""

    LEGACY = "legacy"
    RFC_9990 = "rfc_9990"


@dataclass
class ParserWarning:
    """A non-fatal, structured compatibility warning."""

    code: str
    message: str


@dataclass
class DateRange:
    """The reporting period as integer Unix timestamps."""

    begin: int
    end: int

    @property
    def begin_datetime(self) -> datetime:
        """Return the beginning of the reporting period as a UTC datetime."""
        return datetime.fromtimestamp(self.begin, tz=timezone.utc)

    @property
    def end_datetime(self) -> datetime:
        """Return the end of the reporting period as a UTC datetime."""
        return datetime.fromtimestamp(self.end, tz=timezone.utc)

    def __str__(self) -> str:
        """Return the reporting period formatted in UTC."""
        date_format = "%Y-%m-%d %H:%M:%S UTC"
        begin = self.begin_datetime.strftime(date_format)
        end = self.end_datetime.strftime(date_format)
        return f"{begin} to {end}"


@dataclass
class ReportMetadata:
    """Metadata supplied by the report generator."""

    org_name: str
    email: str
    report_id: str
    date_range: DateRange
    extra_contact_info: str | None = None
    errors: list[str] = field(default_factory=list)
    generator: str | None = None


@dataclass
class PolicyPublished:
    """Published policy values, with absent optional fields kept as ``None``."""

    domain: str
    p: PublishedPolicy
    sp: PublishedPolicy | None = None
    pct: int | None = None
    adkim: AlignmentMode | None = None
    aspf: AlignmentMode | None = None
    fo: str | None = None
    np: PublishedPolicy | None = None
    testing: TestingMode | None = None
    discovery_method: DiscoveryMethod | None = None
    report_format: ReportFormat = ReportFormat.LEGACY

    @property
    def effective_sp(self) -> PublishedPolicy:
        """Return the subdomain policy after the format-defined default."""
        return self.sp or self.p

    @property
    def effective_np(self) -> PublishedPolicy | None:
        """Return the reported legacy extension or the RFC 9990 effective policy."""
        if self.report_format is ReportFormat.LEGACY:
            return self.np
        return self.np or self.sp or self.p

    @property
    def effective_pct(self) -> int | None:
        """Return the legacy sampling percentage, including its default."""
        if self.report_format is ReportFormat.RFC_9990:
            return None
        return 100 if self.pct is None else self.pct

    @property
    def effective_adkim(self) -> AlignmentMode:
        """Return DKIM alignment mode after its standard default."""
        return self.adkim or AlignmentMode.RELAXED

    @property
    def effective_aspf(self) -> AlignmentMode:
        """Return SPF alignment mode after its standard default."""
        return self.aspf or AlignmentMode.RELAXED

    @property
    def effective_testing(self) -> TestingMode | None:
        """Return RFC 9990 testing mode after its standard default."""
        if self.report_format is ReportFormat.LEGACY:
            return None
        return self.testing or TestingMode.NO

    @property
    def effective_fo(self) -> str:
        """Return failure-reporting options after the standard default."""
        return self.fo or "0"


@dataclass
class PolicyOverrideReason:
    """A typed reason for overriding the published policy."""

    type: PolicyOverrideType
    comment: str | None = None


@dataclass
class PolicyEvaluated:
    """DMARC policy results applied to a group of messages."""

    disposition: ActionDisposition
    dkim: DMARCResult
    spf: DMARCResult
    reasons: list[PolicyOverrideReason] = field(default_factory=list)


@dataclass
class Identifier:
    """Message header and envelope domains used during evaluation."""

    header_from: str
    envelope_from: str | None = None
    envelope_to: str | None = None


@dataclass
class DKIMAuthResult:
    """An underlying DKIM authentication result."""

    domain: str
    result: DKIMResult
    selector: str | None = None
    human_result: str | None = None


@dataclass
class SPFAuthResult:
    """An underlying SPF authentication result."""

    domain: str
    result: SPFResult
    scope: SPFScope | None = None
    human_result: str | None = None


@dataclass
class AuthResults:
    """Underlying DKIM and SPF authentication results."""

    dkim: list[DKIMAuthResult] = field(default_factory=list)
    spf: list[SPFAuthResult] = field(default_factory=list)


@dataclass
class Record:
    """One aggregate group of messages and its authentication results."""

    source_ip: str
    count: int
    policy_evaluated: PolicyEvaluated
    identifiers: Identifier
    auth_results: AuthResults


@dataclass
class Report:
    """A parsed DMARC aggregate report."""

    report_metadata: ReportMetadata
    policy_published: PolicyPublished
    records: list[Record]
    format: ReportFormat = ReportFormat.LEGACY
    namespace: str | None = None
    version: str | None = None
    warnings: list[ParserWarning] = field(default_factory=list)

    @property
    def summary_stats(self) -> dict[str, object]:
        """Generate summary statistics for the report."""
        total_messages = sum(record.count for record in self.records)
        dkim_pass = sum(record.count for record in self.records if record.policy_evaluated.dkim is DMARCResult.PASS)
        spf_pass = sum(record.count for record in self.records if record.policy_evaluated.spf is DMARCResult.PASS)
        dmarc_pass = sum(
            record.count
            for record in self.records
            if DMARCResult.PASS in (record.policy_evaluated.dkim, record.policy_evaluated.spf)
        )

        dispositions: dict[str, int] = {}
        for record in self.records:
            disposition = record.policy_evaluated.disposition.value
            dispositions[disposition] = dispositions.get(disposition, 0) + record.count

        return {
            "total_messages": total_messages,
            "unique_sources": len({record.source_ip for record in self.records}),
            "dmarc_pass_rate": dmarc_pass / total_messages if total_messages else 0,
            "dkim_pass_rate": dkim_pass / total_messages if total_messages else 0,
            "spf_pass_rate": spf_pass / total_messages if total_messages else 0,
            "dispositions": dispositions,
        }
