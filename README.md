# DMARC Report

Parse legacy and RFC 9990 DMARC aggregate reports into typed Python objects, or display a report in your terminal.

The parser accepts plain XML and gzip-compressed XML, along with ZIP archives. The type of file passed is detected from magic bytes and XML structure.

## Installation

This works best when installed with `pipx` or `uv tool`.

```bash
# With pipx:
pipx install dmarc-report

# Or with uv:
uv tool install dmarc-report
```

You can also run the tool without installing it:

```bash
# With uvx:
uvx dmarc-report long-dmarc-report-filename.xml
```

## Usage

Run the `dmarc-report` command-line utility followed by a DMARC report file.
The DMARC report will probably have one of the following file extensions:

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

You should see a nicely formatted report in your terminal:

```text
╭──────────────────────────────── DMARC Report for example.com ────────────────────────────────╮
│                              DMARC Report Metadata                                           │
│ ╭───────────────────────┬──────────────────────────────────────────────────────╮             │
│ │ Format                │ Legacy                                               │             │
│ │ Namespace             │ not reported                                         │             │
│ │ Version               │ 1.0                                                  │             │
│ │ Organization          │ Example Reporting Org                                │             │
│ │ Contact               │ dmarcreport@reporting.com                            │             │
│ │ Report ID             │ 1234567890                                           │             │
│ │ Date range            │ 2026-08-26 00:00:00 UTC to 2026-08-27 00:00:00 UTC   │             │
│ ╰───────────────────────┴──────────────────────────────────────────────────────╯             │
│                               DMARC Policy Details                                           │
│ ╭───────────────────────┬──────────────────────────────────────────────────────╮             │
│ │ Domain                │ example.com                                          │             │
│ │ Policy (p)            │ quarantine                                           │             │
│ │ Subdomain (sp)        │ quarantine                                           │             │
│ │ Sampling (pct)        │ 100%                                                 │             │
│ │ DKIM alignment        │ r                                                    │             │
│ │ SPF alignment         │ r                                                    │             │
│ │ Failure options (fo)  │ 0                                                    │             │
│ ╰───────────────────────┴──────────────────────────────────────────────────────╯             │
│                                     Summary                                                  │
│ ╭───────────────────────┬──────────────────────────────────────────────────────╮             │
│ │ Total messages        │ 2                                                    │             │
│ │ Unique sources        │ 2                                                    │             │
│ │ DMARC pass rate       │ 100.0%                                               │             │
│ │ DKIM aligned          │ 100.0%                                               │             │
│ │ SPF aligned           │ 100.0%                                               │             │
│ ╰───────────────────────┴──────────────────────────────────────────────────────╯             │
│                                           Message Records                                    │
│ ╭───────────────┬───────┬─────────────┬──────┬──────┬──────────────────────────────────────╮ │
│ │ Source IP     │ Count │ Disposition │ DKIM │ SPF  │ Authentication results and overrides │ │
│ ├───────────────┼───────┼─────────────┼──────┼──────┼──────────────────────────────────────┤ │
│ │ 192.100.20.21 │     1 │ none        │ pass │ pass │ DKIM pass example.com selector=fm1   │ │
│ │               │       │             │      │      │ SPF pass example.com scope=mfrom     │ │
│ │ 192.100.22.23 │     1 │ none        │ pass │ pass │ DKIM pass example.com selector=fm1   │ │
│ │               │       │             │      │      │ SPF pass example.com scope=mfrom     │ │
│ ╰───────────────┴───────┴─────────────┴──────┴──────┴──────────────────────────────────────╯ │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
```

Use `--verbose` (or `-v`) when running the CLI to include parser warnings in the output:

```bash
dmarc-report --verbose long-dmarc-report-filename.xml
```

This will add something like this to the end of the report:

```text
│                                       Parser Warnings                                        │
│ ╭──────────────────────────────┬───────────────────────────────────────────────────────────╮ │
│ │ Code                         │ Details                                                   │ │
│ ├──────────────────────────────┼───────────────────────────────────────────────────────────┤ │
│ │ legacy_no_namespace          │ A namespace-free report was accepted as legacy DMARC XML. │ │
│ ╰──────────────────────────────┴───────────────────────────────────────────────────────────╯ │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
```

Display the installed package version with `dmarc-report --version` or `dmarc-report -V`.

## Python API

You can integrate this package into your own Python projects:

```python
from dmarc_report import parser

# If reading bytes:
report = parser.DMARCParser.parse_bytes(attachment_bytes)
# If reading a file:
report = parser.DMARCParser.parse_file("aggregate-report.xml.gz")

print(report.format, report.namespace, report.version)
print(report.policy_published.domain)
```

The parser creates dataclasses for each report section, with helper methods and properties to access fields.
For example, to extract report information about the subdomain policy or the sampling percentage:

```python
policy = report.policy_published
print(policy.sp)  # None if it was absent
print(policy.effective_sp)  # inherits value from the <p> field
print(policy.pct)  # None in RFC 9990 and when omitted from legacy XML
print(policy.effective_pct)  # legacy default 100; None for RFC 9990
```

Full documentation may be added in the future, but for now the source code is the key resource.
The following files are where the bulk of the API logic lives:

- `parser.py` this is the main entry point to access the `DMARCParser` class and the parser limits.
- `schema.py` this module defines the data structures used by the parser, including the main `Report` class.

## Resource limits and malformed input

There are a number of limits that are configure to try to protect against bad attachments or rogue reports.
If needed, you can customise the limits with the `ParserLimits` class:

```python
from dmarc_report import parser

limits = parser.ParserLimits(
    max_input_bytes=5 * 1024 * 1024,
    max_decompressed_bytes=25 * 1024 * 1024,
    max_records=25_000,
)
report = parser.DMARCParser.parse_bytes(attachment_bytes, limits=limits)
```

Default limits are 10 MiB input, 100 MiB decompressed XML, 10 zip members, 100,000 records, 100 DKIM results per record,
10 SPF results per record, and 64 KiB per parsed text field.

All custom exceptions derive from `DMARCParseError` and expose a machine-readable `code`:

```python
from dmarc_report import exceptions, parser

try:
    report = parser.DMARCParser.parse_bytes(attachment_bytes)
except exceptions.DMARCParseError as error:
    print(error.code.value, str(error))
```

Filesystem errors from `parse_file`, invalid `ParserLimits` configuration, and unexpected package defects are not
misreported as malformed attachments.

## Issues

This package has been tested as much as possible, but email providers often have quirks in their DMARC reports which
are difficult to catch without actually seeing the reports.
Please [log issues here](https://github.com/stuartmaxwell/dmarc-report/issues) if you encounter any broken reports
or if you notice any weird/unusual output. Please include as much info as possible, and ideally include the actual
DMARC report if possible. Or you can forward me your DMARC reports to: dmarc-reports@amanzi.nz
