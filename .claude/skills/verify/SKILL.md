---
name: verify
description: Drive the real AudiThor macOS app (static Android APK security analyzer) to prove a change works. Primary surface is the headless CLI built into the app binary (scan an APK, check findings, exports, exit codes, saved history); the SwiftUI GUI is driven through computer-use app_* tools when a change is visual. Use after any change to the pipeline, checks, exporters, persistence, or views, before calling the work done.
---

# Verify AudiThor

AudiThor is one macOS app with two surfaces:

- **CLI (primary, fully scriptable).** The app binary runs headless with `--scan`. This exercises the whole real pipeline: apktool, jadx, the signature checks, the rule engine, scoring, export, and saving to history.
- **GUI (SwiftUI).** Drop zone, scan progress, report (dashboard, findings, detail), App Details, Compare Scans, Tool Setup, Settings. Drive it with the computer-use `app_*` tools; there is no other UI harness.

All commands go through `.claude/skills/verify/scripts/audithor-verify` (run it with no arguments for usage). Paths below are relative to the repo root. Shorthand: `V=.claude/skills/verify/scripts/audithor-verify`.

## Launch

1. Build: `$V build`. It runs the repo's `xcodebuild … -derivedDataPath build/dd` and prints the binary path. It's ready when the output shows `** BUILD SUCCEEDED **` and `binary: …`.
2. Create an isolated run: `eval "$($V new-run)"`. This exports `AUDITHOR_RUN_ID` and creates a throwaway home at `$TMPDIR/audithor-verify/<run>/home`. Every scan and GUI launch from this run sets `HOME` and `CFFIXED_USER_HOME` to that directory, so the scan-history DB, caches, jadx state, and preferences all start empty. The user's real `~/Library/Application Support/AudiThor/history.sqlite` is never touched, and parallel runs don't share state.
3. CLI: there's no server; each `$V scan …` is one complete run of the app.
4. GUI (only when the change is visual): `$V gui-launch`. This starts the binary directly against the run's home, with `-acceptedAuthorizedUseNotice.v1 YES` on the command line so the first-launch sheet is skipped. It's ready when it prints `GUI ready: pid …`. To show the first-launch sheet on purpose, launch the binary yourself without that argument.
5. Teardown: `$V cleanup` (see Cleanup).

## Doctor

Run `$V doctor` first, and again whenever something looks off. It's read-only and checks:

- whether the binary exists and is newer than every `AudiThor/**/*.swift`; `STALE` means rebuild
- the git revision, and whether the tree is dirty
- the required tools (`java`, `apktool`, `unzip`) and the optional ones (`jadx`, `apksigner`, `aapt2`)
- that the fixture APK exists
- the run's home and whether this run's GUI is alive
- any *other* AudiThor instances, which are the user's and must not be driven

It ends with `DOCTOR OK` (exit 0) or `DOCTOR FAIL` (exit 1). Tool lookup follows the app's own search order (`AudiThor/Tools/ToolLocator.swift`): Homebrew, JVM homes, and Android SDK `build-tools` under `ANDROID_HOME`, `ANDROID_SDK_ROOT` or `~/Library/Android/sdk`. A missing optional tool is a `WARN`. Without `apksigner`, signature schemes are still detected natively but not cryptographically verified. On this machine, `apksigner` and `aapt2` come from `$ANDROID_HOME/build-tools/37.0.0-rc2`, so reports show `signature.verified: true`. If `doctor` and a report's `scan.tools` ever disagree, trust the report and fix `doctor`.

## Drive

Read `features/README.md` first, then the feature file for what you changed. In short:

- **Scan:** `$V scan TestFixtures/vulnapp.apk <name> [--fail-on high] [--cve local] [--no-jadx] [--save] [--out-format json|html|pdf]`. Use a fresh `<name>` per scan, because reusing one overwrites its evidence. This writes `<name>.<fmt>` and `<name>.cmd.txt / .stdout.txt / .stderr.txt / .exit.txt` into the evidence directory and exits with the app's own exit code: 0 OK, 1 error, 2 `--fail-on` threshold hit.
- **Check findings:** `$V assert-rules <name> RULE_ID …` checks the JSON report. It prints the finding count, risk score, and package, then `OK`/`MISSING` per rule, and exits 1 if any rule is missing.
- **Check a side effect:** `$V history` lists the rows in this run's isolated history DB (read-only `sqlite3`) after a `--save` scan.
- **GUI:** use the computer-use `app_*` tools with bundle id `devplaceholder.FSN7ABQK.AudiThor`. Call `request_access` for that app first; the user has to approve it, and once declined it. Target controls by their accessibility names, which come from the views:
  - sidebar rows: `New Scan`, `Compare Scans`, `Tool Setup`, plus history rows labelled with the app name
  - the drop zone: "Drop zone for Android packages"
  - the `Choose File…` button
  - severity tiles: "`<n>` `<Severity>` findings"
  - the risk gauge: "Overall risk `<n>` of 100, `<label>`"
  - the toolbar `Export` menu
  - menus: File › Open APK… and File › Compare Scans (use `app_menu`)

  The Open panel and drag-and-drop can't be driven reliably. To get scans into the GUI, run them with `$V scan … --save` in the same run *before* `$V gui-launch`, then open them from the History sidebar. The sidebar loads history only at launch, after a GUI scan finishes, and on delete. After a CLI `--save` while the GUI is open, run `$V gui-stop` and `$V gui-launch` to see the new rows.

  Background-control limits, observed live:
  - **Esc is refused inside a sheet.** Close sheets with their `Close` button.
  - **Right-click context menus are refused** (History's `Delete Scan`). Driving them needs full-screen control (`request_full_control`), which takes over the user's screen.
  - **Clicks and AX presses work for everything else**, including tiles, segments, `app_menu`, and history rows (click by coordinate; rows have no AX title).

## Evidence

Everything goes to `build/verify-evidence/<run-id>/`. It's gitignored through `build/`, and cleanup never deletes it. A proof includes:

- the exact command (`.cmd.txt`), stdout, stderr, and exit code for every CLI action
- the report the action produced, plus a second, read-only view of it: `assert-rules` output, `$V history` for saved scans, or `sips -s format png <x>.pdf --out <x>.png` and then reading the PNG for PDF layout
- for GUI changes, an `app_screenshot` of the state before and after the action. `app_screenshot` has no `save_to_disk`, but each result names its image file (`[Image: source: …/tool-results/….jpg]`). Copy that file into `build/verify-evidence/<run-id>/gui/` with a descriptive name, and note the exact AX labels you checked.

Proof standards:

- Go through the real entry point: the app binary or the GUI. Don't call internal Swift functions or edit the DB by hand.
- Check side effects as well as output. A saved scan must appear in `$V history`; an export must exist and open (`file <path>`, page count).
- The input APK must be unchanged: `shasum -a 256` before and after any scan you claim is read-only.
- `--cve online` sends library coordinates to api.osv.dev. Don't use it unless the change is to that feature and the user agreed to network use.

## Cleanup

Run `$V cleanup`. It stops only the GUI process this run started (by its recorded pid, never by name), deletes `$TMPDIR/audithor-verify/<run>/`, and lists the evidence it kept. Run it after every attempt, including failed ones.

## Helpers

- `scripts/audithor-verify`: the only helper. Run it with no arguments for usage. Commands: `new-run`, `build`, `doctor`, `scan`, `assert-rules`, `history`, `gui-launch`, `gui-stop`, `cleanup`.
- `Scripts/build-fixture.sh` (repo): rebuilds `TestFixtures/vulnapp.apk` from `TestFixtures/vulnapp-src/` with apktool and a throwaway debug key. Rebuild it after adding a fixture case for a new rule.
