"""Parse DMARC XML reports and display the results using Rich tables and panels."""

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dmarc_report.schema import Report


def display_console(dmarc_report: Report) -> None:  # noqa: PLR0915
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
    metadata_table.add_column("Value", width=52)

    policy_table = Table(
        title="DMARC Policy Details",
        box=box.ROUNDED,
        show_header=False,
        min_width=80,
        expand=True,
    )
    policy_table.add_column("Setting", style="cyan", width=20)
    policy_table.add_column("Value", width=52)

    stats_table = Table(
        title="Summary",
        box=box.ROUNDED,
        show_header=False,
        min_width=80,
        expand=True,
    )
    stats_table.add_column("Metric", style="cyan", width=20)
    stats_table.add_column("Value", width=52)

    records_table = Table(
        title="Message Records",
        box=box.ROUNDED,
        min_width=80,
        expand=True,
    )
    records_table.add_column("Source IP", style="cyan")
    records_table.add_column("Count", style="magenta")
    records_table.add_column("DKIM")
    records_table.add_column("SPF")
    records_table.add_column("Auth Results")

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
    stats = dmarc_report.summary_stats
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

    # Sort by count field descending, and by source_ip field ascending
    records = sorted(dmarc_report.records, key=lambda record: (-record.count, record.source_ip))

    for record in records:
        auth_results = Text()
        for ar_d in record.auth_results.dkim:
            auth_results.append("dkim: ", style="cyan")
            auth_results.append(ar_d.domain)
            auth_results.append(" ")
            auth_results.append(
                ar_d.result.value,
                style=f"{'green' if ar_d.result.value == 'pass' else 'bold red'}",
            )
            auth_results.append("\n")

        for ar_d in record.auth_results.spf:
            auth_results.append("spf: ", style="cyan")
            auth_results.append(ar_d.domain)
            auth_results.append(" ")
            auth_results.append(
                ar_d.result.value,
                style=f"{'green' if ar_d.result.value == 'pass' else 'bold red'}",
            )
            auth_results.append("\n")

        dkim_style = "green" if record.policy_evaluated.dkim.value == "pass" else "bold red"
        spf_style = "green" if record.policy_evaluated.spf.value == "pass" else "bold red"

        records_table.add_row(
            record.source_ip,
            str(record.count),
            Text(record.policy_evaluated.dkim.value, style=dkim_style),
            Text(record.policy_evaluated.spf.value, style=spf_style),
            auth_results,
        )

    console = Console()
    console.print(report)
