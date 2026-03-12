# Nessus Combiner and Vulnerability Report Generator

A Python tool to combine multiple Nessus `.nessus` scan files and generate interim vulnerability reports.

## Features

1. **Combine Multiple .nessus Files**: Merges all `.nessus` files from a directory into a single valid `.nessus` file that can be imported into security tools.

2. **Vulnerability Report Generation**: Creates aggregated reports showing:
   - All Critical, High, and Medium severity vulnerabilities
   - Affected hosts grouped by vulnerability
   - CVE identifiers and CVSS scores
   - Synopsis and solution information
   - Output formats: CSV and HTML

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

## Usage

### Basic Usage (Combine + Generate Reports)

```bash
python3 nesscomb.py
```

This will:
- Read all `.nessus` files from the `input/` directory
- Create `output/combined.nessus` - single combined file
- Generate `output/vulnerability_report.csv` - CSV report
- Generate `output/vulnerability_report.html` - HTML report

### Custom Directories

```bash
python3 nesscomb.py --input-dir /path/to/scans --output-dir /path/to/results
```

### Combine Only (No Reports)

```bash
python3 nesscomb.py --combine-only
```

### Generate Reports Only (From Existing Combined File)

```bash
python3 nesscomb.py --report-only
```

## Output Files

### 1. combined.nessus
A single valid Nessus XML file containing all scans merged together. Can be imported directly into Nessus, Tenable.sc, or other security tools.

### 2. vulnerability_report.csv
CSV format report with columns:
- Plugin ID
- Vulnerability Name
- Severity (Critical/High/Medium)
- CVSS Score
- CVE Identifiers
- Affected Hosts Count
- List of Affected Hosts
- Synopsis
- Solution

### 3. vulnerability_report.html
Beautiful HTML report with:
- Summary dashboard showing counts by severity
- Sortable table of all vulnerabilities
- Color-coded severity badges
- Responsive design for easy viewing
- Automatically opens in your browser

## Report Filtering

The vulnerability reports automatically filter to show only:
- **Critical** severity vulnerabilities
- **High** severity vulnerabilities
- **Medium** severity vulnerabilities

Low and Informational findings are excluded from the reports (but still present in the combined .nessus file).

## Example

```bash
# Place your .nessus files in the input/ directory
ls input/
# scan1.nessus  scan2.nessus  scan3.nessus

# Run the tool
python3 nesscomb.py

# Output:
# Combining .nessus files...
# Found 3 .nessus files
# Using scan1.nessus as template...
# Processing scan2.nessus...
# Processing scan3.nessus...
# Combined file created: output/combined.nessus
#
# Generating vulnerability report...
# Processed 45 hosts with 1234 vulnerability findings
# Found 23 unique medium/high/critical vulnerabilities
# CSV report created: output/vulnerability_report.csv
# HTML report created: output/vulnerability_report.html

```

## Command-Line Options

```
--input-dir DIR       Input directory with .nessus files (default: input)
--output-dir DIR      Output directory for results (default: output)
--combine-only        Only combine files, skip report generation
--report-only         Only generate reports from existing combined file
```

## How It Works

### Combining Files
1. Parses the first `.nessus` file as a template
2. Iterates through remaining files and merges all `ReportHost` elements
3. Handles duplicate hosts by merging their vulnerability findings
4. Writes a valid XML structure that maintains Nessus format compliance

### Report Generation
1. Parses all `ReportHost` and `ReportItem` elements
2. Filters for severity >= 2 (Medium, High, Critical)
3. Groups vulnerabilities by Plugin ID
4. Aggregates affected hosts for each unique vulnerability
5. Extracts CVE, CVSS, and remediation information
6. Sorts by severity and host count
7. Generates both CSV and HTML outputs

## Tips

- The HTML report is great for executive presentations and quick reviews
- The CSV report is perfect for importing into spreadsheets or other tools
- The combined `.nessus` file maintains all original scan data
- Host deduplication is automatic based on hostname/IP
- Large scans with thousands of hosts are handled efficiently

## Troubleshooting

**XML parsing error**: One or more `.nessus` files may be corrupted - check the error message for which file

**Empty report**: No Medium/High/Critical vulnerabilities found in the scans

## License

This tool is provided as-is for security assessment purposes.
