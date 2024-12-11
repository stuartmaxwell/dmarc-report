"""User interface for displaying DMARC reports."""

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table

from dmarc_report.schema import Feedback as DMARCSchema


def get_summary_stats(dmarc_report: DMARCSchema) -> dict:
    """Generate summary statistics for the report."""
    total_messages = sum(record.count for record in dmarc_report.records)

    # Calculate pass rates
    dkim_pass = sum(record.count for record in dmarc_report.records if record.policy_evaluated.dkim == "pass")
    spf_pass = sum(record.count for record in dmarc_report.records if record.policy_evaluated.spf == "pass")

    # Count dispositions
    dispositions = {}
    for record in dmarc_report.records:
        disp = record.policy_evaluated.disposition.value
        dispositions[disp] = dispositions.get(disp, 0) + record.count

    return {
        "total_messages": total_messages,
        "unique_sources": len({record.source_ip for record in dmarc_report.records}),
        "dkim_pass_rate": dkim_pass / total_messages if total_messages > 0 else 0,
        "spf_pass_rate": spf_pass / total_messages if total_messages > 0 else 0,
        "dispositions": dispositions,
        "report_period": str(dmarc_report.report_metadata.date_range),
    }


def display_rich_console(dmarc_report: DMARCSchema) -> None:
    """Display the DMARC report using Rich tables and panels."""
    # Create the tables
    metadata_table = Table(
        title="DMARC Report Metadata",
        box=box.ROUNDED,
        show_header=False,
        min_width=80,
        expand=True,
    )
    metadata_table.add_column("Field", style="cyan", width=20)
    metadata_table.add_column("Value", style="green", width=52)

    policy_table = Table(
        title="DMARC Policy Details",
        box=box.ROUNDED,
        show_header=False,
        min_width=80,
        expand=True,
    )
    policy_table.add_column("Setting", style="cyan", width=20)
    policy_table.add_column("Value", style="green", width=52)

    stats_table = Table(
        title="Summary",
        box=box.ROUNDED,
        show_header=False,
        min_width=80,
        expand=True,
    )
    stats_table.add_column("Metric", style="cyan", width=20)
    stats_table.add_column("Value", style="green", width=52)

    records_table = Table(
        title="Message Records",
        box=box.ROUNDED,
        min_width=80,
        expand=True,
    )
    records_table.add_column("Source IP", style="cyan")
    records_table.add_column("Count", style="magenta")
    records_table.add_column("DKIM", style="yellow")
    records_table.add_column("SPF", style="yellow")
    records_table.add_column("Auth Results", style="green")

    # Rich Layout
    panel_group = Group(
        policy_table,
        metadata_table,
        stats_table,
        records_table,
    )
    report = Panel(
        panel_group,
        title=f"DMARC Report for {dmarc_report.policy_published.domain}",
        expand=False,
        box=box.ROUNDED,
    )

    # Populate the summary statistics table
    stats = get_summary_stats()
    stats_table.add_row("Total Messages", str(stats["total_messages"]))
    stats_table.add_row("Unique Sources", str(stats["unique_sources"]))
    stats_table.add_row("DKIM Pass Rate", f"{stats['dkim_pass_rate']:.1%}")
    stats_table.add_row("SPF Pass Rate", f"{stats['spf_pass_rate']:.1%}")

    # Populate the Report Metadata table
    metadata_table.add_row("Org name", dmarc_report.report_metadata.org_name)
    metadata_table.add_row("Email", dmarc_report.report_metadata.email)
    metadata_table.add_row("Extra contact info", dmarc_report.report_metadata.extra_contact_info)
    metadata_table.add_row("Report ID", dmarc_report.report_metadata.report_id)
    metadata_table.add_row("Date range", str(dmarc_report.report_metadata.date_range))

    # Populate the policy table
    policy_table.add_row("Domain", dmarc_report.policy_published.domain)
    policy_table.add_row("DKIM Alignment", dmarc_report.policy_published.adkim.value)
    policy_table.add_row("SPF Alignment", dmarc_report.policy_published.aspf.value)
    policy_table.add_row("Policy", dmarc_report.policy_published.p.value)
    policy_table.add_row("Subdomain Policy", dmarc_report.policy_published.sp.value)
    policy_table.add_row("Percent", f"{dmarc_report.policy_published.pct!s}%")
    if dmarc_report.policy_published.fo:
        policy_table.add_row("Failure Options", dmarc_report.policy_published.fo)

    # Populate the records table
    for record in dmarc_report.records:
        dkim_auth_results_str = "\n".join(
            f"dkim: {ar_d.domain} ({ar_d.result.value})" for ar_d in record.auth_results.dkim
        )
        spf_auth_results_str = "\n".join(
            f"spf: {ar_s.domain} ({ar_s.result.value})" for ar_s in record.auth_results.spf
        )
        records_table.add_row(
            record.source_ip,
            str(record.count),
            record.policy_evaluated.dkim.value,
            record.policy_evaluated.spf.value,
            dkim_auth_results_str + "\n" + spf_auth_results_str,
        )

    console = Console()
    console.print(report)
