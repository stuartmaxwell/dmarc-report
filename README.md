# DMARC Report Tool

Displays a nicely formatted report in your terminal from a DMARC XML report.

## Installation

This works best when installed with `uvx` or `pipx`.

```bash
# With uv:
uv tool install dmarc-report

# Or with pipx:

pipx install dmarc-report
```

You can also run the tool with installing it:

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
