# Scan history and report view

Every finished scan is saved locally and listed under History in the sidebar. Opening one shows the report: header (app, package, version, SHA-256), a dashboard (risk gauge, severity tiles that filter, MASVS chart), a filterable findings list with a detail pane, and the App Details and Scan Notes tabs.

## Sub-features

- `history-save`: a completed scan (GUI, or CLI with `--save`) adds a row to the history DB.
- `history-sidebar`: the History section lists saved scans with a risk badge, newest first.
- `report-dashboard`: the risk gauge and severity tiles match the report's counts.
- `report-filter`: clicking a severity tile shows only that severity; the search field filters by title, rule, CWE, or file; `Reset` clears the filters.
- `report-detail`: selecting a finding shows its description, MASVS/MASTG/CWE references, evidence, and remediation.
- `report-tabs`: App Details lists signature schemes, permissions, components, and SDKs; Scan Notes lists warnings and tool versions.
- `history-delete`: the context menu's `Delete Scan` removes the row.

## How to get to it (user POV)

- A GUI scan opens its report when it finishes.
- Click a row under History in the sidebar.
- Run `AudiThor --scan <apk> --save` in a terminal, then open the app.

## Driving it with audithor-verify

Preconditions:

- `$V doctor` reports `DOCTOR OK`.
- `AUDITHOR_RUN_ID` is set; the run's history starts empty.
- For the GUI steps, the user has approved computer-use `request_access` for `devplaceholder.FSN7ABQK.AudiThor`.

- **Save.** Run `$V scan TestFixtures/vulnapp.apk saved --save`, then `$V history`. Expect exactly one row: `com.audithor.fixture`, `1.0.0`, `riskScore` 97, `findingCount` matching `saved.json`.
- **Isolation.** Run `stat -f %m ~/Library/Application\ Support/AudiThor/history.sqlite` before and after. The value doesn't change, because the user's real history is untouched.
- **Sidebar.** Run `$V gui-launch`, then `app_screenshot`. The window has no authorized-use sheet, and History shows one `AudiThor Fixture` row.
- **Dashboard.** Click the history row. The AX labels include "Overall risk 97 of 100, Critical", "2 Critical findings", and "10 High findings".
- **Filter.** Click the tile labelled "2 Critical findings". The list shows only `TrustManager accepts all certificates` and `Signed with the Android debug certificate`, and a `Reset` button appears. Click the tile again to restore all findings.
- **Detail.** Select `TrustManager accepts all certificates`. The detail pane shows `MASVS-NETWORK-1`, `CWE-295`, and evidence `jadx/sources/com/audithor/fixture/TrustAllManager.java:13`.
- **Tabs.** Choose `App Details`. It shows the `v1` scheme marked on, `Verified by apksigner` (when `scan.tools` lists apksigner), `CN=Android Debug,O=Android,C=US`, `sha1WithRSAEncryption`, and a `rsaEncryption 1024-bit` key.
- **Delete (needs full-screen control).** Right-click the history row and choose `Delete Scan`. The row disappears and `$V history` shows one fewer row. Background control refuses context menus, so this step needs `request_full_control`; without it, report `history-delete` as unverified.
- **Proof.** Take an `app_screenshot` after each step and copy its `source:` image into `build/verify-evidence/<run-id>/gui/`.

## Gotchas

- `-acceptedAuthorizedUseNotice.v1 YES`, which `$V gui-launch` passes, does hide the authorized-use sheet. This was confirmed by screenshot on 2026-11-27.
- The detail pane doesn't follow the filter: after a tile filter, a finding that's now hidden can stay selected in the detail pane. Select a finding explicitly before checking the detail.
- Launching the GUI without `-acceptedAuthorizedUseNotice.v1 YES` in a fresh home shows the modal authorized-use sheet, which blocks everything until it's accepted.
- The sidebar reloads history only at launch, after a GUI scan, and on delete. A row added (CLI `--save`) or removed by hand while the GUI is open isn't reflected until `$V gui-stop` and `$V gui-launch`. If a removed row's report was already opened, the in-memory cache keeps showing it; otherwise clicking it shows "Scan not found".
- The computer-use grant was declined once in this project's history. If it's declined, report the GUI sub-features as unverified rather than substituting CLI proof.
