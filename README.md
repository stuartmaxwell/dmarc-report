# DMARC Report Tool

Displays a nicely formatted report in your terminal from a DMARC XML report.

## Installation

This works best when installed with `uv tool` or `pipx`.

```bash
# With uv:
uv tool install dmarc-report

# Or with pipx:

pipx install dmarc-report
```

You can also run the tool without installing it:

```bash
# With uvx:
uvx dmarc-report long-dmarc-report-filename.xml
```

## Usage

Run the `dmarc-report` command-line utility followed by a DMARC report file.
The DMARC report can have one of the following file extensions:

- `.xml.gz`
- `.zip`
- `.xml`

```bash
dmarc-report long-dmarc-report-filename.xml.gz
# or
dmarc-report long-dmarc-report-filename.xml
# or
dmarc-report long-dmarc-report-filename.zip
```

Note: if using a zip file, it will only parse the first xml file found in the zip file.

You'll see a nicely formatted report in your terminal:

```text
╭────────────────────────── DMARC Report for example.com ──────────────────────────╮
│                               DMARC Policy Details                               │
│ ╭───────────────────────┬──────────────────────────────────────────────────────╮ │
│ │ Domain                │ example.com                                          │ │
│ │ DKIM Alignment        │ r                                                    │ │
│ │ SPF Alignment         │ r                                                    │ │
│ │ Policy                │ quarantine                                           │ │
│ │ Subdomain Policy      │ reject                                               │ │
│ │ Percent               │ 100%                                                 │ │
│ ╰───────────────────────┴──────────────────────────────────────────────────────╯ │
│                              DMARC Report Metadata                               │
│ ╭───────────────────────┬──────────────────────────────────────────────────────╮ │
│ │ Org name              │ Google, Inc.                                         │ │
│ │ Email                 │ noreply-dmarc-support@google.com                     │ │
│ │ Extra contact info    │ https://support.google.com/a/answer/2466580          │ │
│ │ Report ID             │ 1234567890                                           │ │
│ │ Date range            │ 2020-01-01 00:00:00 UTC to 2020-01-01 23:59:59 UTC   │ │
│ ╰───────────────────────┴──────────────────────────────────────────────────────╯ │
│                                     Summary                                      │
│ ╭───────────────────────┬──────────────────────────────────────────────────────╮ │
│ │ Total Messages        │ 2                                                    │ │
│ │ Unique Sources        │ 1                                                    │ │
│ │ DKIM Pass Rate        │ 0.0%                                                 │ │
│ │ SPF Pass Rate         │ 0.0%                                                 │ │
│ ╰───────────────────────┴──────────────────────────────────────────────────────╯ │
│                                 Message Records                                  │
│ ╭─────────────────┬─────────┬────────┬────────┬────────────────────────────────╮ │
│ │ Source IP       │ Count   │ DKIM   │ SPF    │ Auth Results                   │ │
│ ├─────────────────┼─────────┼────────┼────────┼────────────────────────────────┤ │
│ │ 203.0.113.1     │ 2       │ pass   │ pass   │ dkim: example.com (pass)       │ │
│ │                 │         │        │        │ spf: example.com (pass)        │ │
│ ╰─────────────────┴─────────┴────────┴────────┴────────────────────────────────╯ │
╰──────────────────────────────────────────────────────────────────────────────────╯
```
