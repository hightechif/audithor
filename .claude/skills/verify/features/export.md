# Export a report

A user saves a scan as JSON (for CI), as self-contained HTML, or as a paginated PDF. Each format carries the app identity, the SHA-256, the risk score, severity counts, and every finding with its evidence and remediation.

## Sub-features

- `export-json`: the JSON has `summary.counts`, `summary.riskScore`, and `scan.schemaVersion`, with findings sorted by severity.
- `export-html`: a single HTML file with no external resources.
- `export-pdf`: an A4 PDF with a footer on every page showing the package, SHA-256 prefix, and page number.
- `export-gui`: the report toolbar's `Export` menu offers PDF, HTML, and JSON, and reveals the saved file in Finder.

## How to get to it (user POV)

- From a terminal, use `--out report.json|html|pdf`, or `--format json|html|pdf`.
- In the GUI, use the `Export` toolbar menu on an open report, then choose `Export PDF…`, `Export HTML…` or `Export JSON…`.

## Driving it with audithor-verify

Preconditions:

- `$V doctor` reports `DOCTOR OK`.
- `AUDITHOR_RUN_ID` is set.

- **JSON.** Run `$V scan TestFixtures/vulnapp.apk exp`, then `/usr/bin/python3 -I -c "import json;d=json.load(open('build/verify-evidence/$AUDITHOR_RUN_ID/exp.json'));print(d['format'],d['summary']['counts'],d['scan']['schemaVersion'])"`. It prints `audithor-report`, counts for all five severities, and `1`.
- **HTML.** Run `$V scan TestFixtures/vulnapp.apk exp-html --out-format html`, then `grep -cE '<(script|link)[^>]+(src|href)=\"http' build/verify-evidence/$AUDITHOR_RUN_ID/exp-html.html`. The count is `0` and the file contains `<h1>AudiThor Fixture</h1>`.
- **PDF.** Run `$V scan TestFixtures/vulnapp.apk exp-pdf --out-format pdf`, then `file build/verify-evidence/$AUDITHOR_RUN_ID/exp-pdf.pdf`. Expect `PDF document, … N pages` with N ≥ 5.
- **PDF layout.** Run `sips -s format png build/verify-evidence/$AUDITHOR_RUN_ID/exp-pdf.pdf --out build/verify-evidence/$AUDITHOR_RUN_ID/exp-p1.png` and read the PNG. Page 1 shows the title, Package/Version/SDK/SHA-256 lines, the risk score, a single severity-count line, and the first finding. The footer reads `AudiThor · com.audithor.fixture · … · page 1`.
- **GUI export (computer-use).** Seed with `$V scan TestFixtures/vulnapp.apk seed --save`, run `$V gui-launch`, open the history row `AudiThor Fixture`, then choose `Export` › `Export JSON…`. The save panel needs the user, so report this as user-assisted. The saved file matches the CLI JSON's finding count.

## Gotchas

- PDF rendering goes through AppKit's HTML import and Core Text, which ignore CSS grid, flex, and tables. The print variant uses plain lines on purpose. A browser-only layout fix won't show in the PDF; always check the rendered PNG.
- When reading HTML or PDF output in a browser, dark mode changes the HTML colours. PDF always uses the light palette.
- `--format` wins over the `--out` extension. `$V scan` passes `--format` explicitly.
- An unknown `--format` value (e.g. `xml`) silently produces JSON.
- Give each scan its own evidence name (`exp`, `exp-html`, `exp-pdf`). Reusing a name overwrites that scan's `.cmd.txt`, `.stdout.txt` and `.exit.txt`.
