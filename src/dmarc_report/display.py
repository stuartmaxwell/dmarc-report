"""Render parsed DMARC aggregate reports with Rich."""

from enum import Enum

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dmarc_report import schema


def display_console(
    dmarc_report: schema.Report,
    *,
    verbose: bool = False,
    console: Console | None = None,
) -> None:
    """Display a parsed report, including parser warnings when requested."""
    sections = [
        _metadata_table(dmarc_report),
        _policy_table(dmarc_report),
        _summary_table(dmarc_report),
        _records_table(dmarc_report),
    ]
    if verbose and dmarc_report.warnings:
        sections.append(_warnings_table(dmarc_report.warnings))

    report_panel = Panel(
        Group(*sections),
        title=f"DMARC Report for {dmarc_report.policy_published.domain}",
        expand=False,
        box=box.ROUNDED,
    )
    output_console = console if console is not None else Console()
    output_console.print(report_panel)


def _details_table(title: str) -> Table:
    """Create a consistent two-column details table."""
    table = Table(title=title, box=box.ROUNDED, show_header=False, min_width=80, expand=True)
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value", width=52)
    return table


def _metadata_table(dmarc_report: schema.Report) -> Table:
    """Render report format and generator metadata."""
    metadata = dmarc_report.report_metadata
    table = _details_table("DMARC Report Metadata")
    format_name = "RFC 9990" if dmarc_report.format is schema.ReportFormat.RFC_9990 else "Legacy"
    table.add_row("Format", format_name)
    table.add_row("Namespace", dmarc_report.namespace or "not reported")
    table.add_row("Version", dmarc_report.version or "not reported")
    table.add_row("Organization", metadata.org_name)
    table.add_row("Contact", metadata.email)
    if metadata.extra_contact_info is not None:
        table.add_row("Extra contact", metadata.extra_contact_info or "empty")
    table.add_row("Report ID", metadata.report_id)
    table.add_row("Date range", str(metadata.date_range))
    if metadata.generator is not None:
        table.add_row("Generator", metadata.generator or "empty")
    if metadata.errors:
        table.add_row("Reported errors", "\n".join(f"• {error}" for error in metadata.errors))
    return table


def _policy_table(dmarc_report: schema.Report) -> Table:
    """Render published policy source values and effective defaults."""
    policy = dmarc_report.policy_published
    table = _details_table("DMARC Policy Details")
    table.add_row("Domain", policy.domain)
    table.add_row("Policy (p)", policy.p.value)
    table.add_row("Subdomain (sp)", _enum_with_default(policy.sp, policy.effective_sp))
    if dmarc_report.format is schema.ReportFormat.RFC_9990 or policy.np is not None:
        table.add_row("Nonexistent (np)", _enum_with_default(policy.np, policy.effective_np))
    if dmarc_report.format is schema.ReportFormat.LEGACY:
        percentage = policy.pct if policy.pct is not None else policy.effective_pct
        suffix = "" if policy.pct is not None else " (default)"
        table.add_row("Sampling (pct)", f"{percentage}%{suffix}")
    table.add_row("DKIM alignment", _enum_with_default(policy.adkim, policy.effective_adkim))
    table.add_row("SPF alignment", _enum_with_default(policy.aspf, policy.effective_aspf))
    if policy.fo is not None:
        table.add_row("Failure options (fo)", policy.fo or "empty")
    if dmarc_report.format is schema.ReportFormat.RFC_9990:
        table.add_row("Testing (t)", _enum_with_default(policy.testing, policy.effective_testing))
    if policy.discovery_method is not None:
        table.add_row("Discovery method", policy.discovery_method.value)
    return table


def _enum_with_default(source: Enum | None, effective: Enum | None) -> str:
    """Format an enum source value while making applied defaults explicit."""
    if source is not None:
        return str(source.value)
    if effective is not None:
        return f"{effective.value} (default)"
    return "not reported"


def _summary_table(dmarc_report: schema.Report) -> Table:
    """Render aggregate report summary statistics."""
    stats = dmarc_report.summary_stats
    dmarc_pass_rate = float(stats["dmarc_pass_rate"])
    table = _details_table("Summary")
    table.add_row("Total messages", str(stats["total_messages"]))
    table.add_row("Unique sources", str(stats["unique_sources"]))
    pass_rate_style = "bold green" if dmarc_pass_rate >= 1 else ""
    table.add_row("DMARC pass rate", Text(f"{dmarc_pass_rate:.1%}", style=pass_rate_style))
    table.add_row("DKIM aligned", f"{float(stats['dkim_pass_rate']):.1%}")
    table.add_row("SPF aligned", f"{float(stats['spf_pass_rate']):.1%}")
    return table


def _records_table(dmarc_report: schema.Report) -> Table:
    """Render evaluated policy and authentication results for every record."""
    table = Table(title="Message Records", box=box.ROUNDED, min_width=80, expand=True)
    table.add_column("Source IP", style="cyan")
    table.add_column("Count", style="magenta", justify="right")
    table.add_column("Disposition")
    table.add_column("DKIM")
    table.add_column("SPF")
    table.add_column("Authentication results and overrides")

    records = sorted(dmarc_report.records, key=lambda record: (-record.count, record.source_ip))
    for record in records:
        table.add_row(
            record.source_ip,
            str(record.count),
            Text(
                record.policy_evaluated.disposition.value,
                style=_result_style(record.policy_evaluated.disposition.value),
            ),
            Text(record.policy_evaluated.dkim.value, style=_result_style(record.policy_evaluated.dkim.value)),
            Text(record.policy_evaluated.spf.value, style=_result_style(record.policy_evaluated.spf.value)),
            _authentication_details(record),
        )
    return table


def _authentication_details(record: schema.Record) -> Text:
    """Render underlying authentication results and policy overrides."""
    details = Text()
    for result in record.auth_results.dkim:
        parts = [result.domain]
        if result.selector is not None:
            parts.append(f"selector={result.selector or 'empty'}")
        _append_result(details, "DKIM", result.result.value, parts, result.human_result)

    for result in record.auth_results.spf:
        parts = [result.domain]
        if result.scope is not None:
            parts.append(f"scope={result.scope.value}")
        _append_result(details, "SPF", result.result.value, parts, result.human_result)

    for reason in record.policy_evaluated.reasons:
        _start_line(details)
        details.append("Override ", style="yellow")
        details.append(reason.type.value)
        if reason.comment:
            details.append(f": {reason.comment}")

    if not details:
        details.append("none reported", style="dim")
    return details


def _append_result(details: Text, label: str, result: str, parts: list[str], human_result: str | None) -> None:
    """Append one compact authentication-result line."""
    _start_line(details)
    details.append(f"{label} ", style="cyan")
    details.append(result, style=_result_style(result))
    details.append(f" {' '.join(parts)}")
    if human_result:
        details.append(f" — {human_result}", style="dim")


def _start_line(text: Text) -> None:
    """Start another line unless the Rich text object is empty."""
    if text:
        text.append("\n")


def _result_style(result: str) -> str:
    """Return a restrained status style for a result token."""
    if result == "pass":
        return "green"
    if result in {"fail", "permerror", "reject"}:
        return "bold red"
    if result in {"neutral", "policy", "softfail", "temperror", "quarantine"}:
        return "yellow"
    return ""


def _warnings_table(warnings: list[schema.ParserWarning]) -> Table:
    """Render tolerated parser deviations so they are not silent."""
    table = Table(title="Parser Warnings", box=box.ROUNDED, min_width=80, expand=True)
    table.add_column("Code", style="yellow", width=34)
    table.add_column("Details")
    for warning in warnings:
        table.add_row(warning.code, warning.message)
    return table
