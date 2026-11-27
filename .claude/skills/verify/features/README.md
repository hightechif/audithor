# AudiThor verification map

This directory is the maintained source for verifying AudiThor's user-facing behavior. Read this index before driving the app, then use the matching feature file as the recipe.

## Baseline preconditions

- Build with `$V build`, where `V=.claude/skills/verify/scripts/audithor-verify`.
- Create an isolated run with `eval "$($V new-run)"`. Every scan and GUI launch uses the run's throwaway `HOME`, which starts with no history, caches, or preferences.
- `$V doctor` must end with `DOCTOR OK`.
- The input is `TestFixtures/vulnapp.apk`, a deliberately insecure APK that is v1-signed with a 1024-bit SHA-1 debug certificate.
- Never drive an AudiThor instance this run did not start. `doctor` lists any others.

## Driving conventions

- Run CLI actions through `$V scan`. It records the command, stdout, stderr, and exit code as evidence.
- Run GUI actions through the computer-use `app_*` tools on bundle `devplaceholder.FSN7ABQK.AudiThor`, after the user approves `request_access`. Target controls by accessibility name, not by coordinates.
- Seed GUI state with `$V scan … --save` before `$V gui-launch`. Don't drive the Open panel or drag-and-drop.
- Don't use `--cve online` unless the change is to it and the user agreed to network use.

## Proof and skip reporting

- CLI proof: the command, stdout, stderr, exit code, and the report file, plus a second read-only view (`assert-rules`, `history`, or a rendered PDF page).
- GUI proof: screenshots before and after the action, with the AX labels that were checked.
- Record the feature ID and the entry point used with every artifact.
- If computer-use access is declined, report GUI entry points as **unverified**, with the reason. Don't count a CLI proof as verifying the GUI path.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior, followed by exactly these four H2 sections, in order:

1. `Sub-features`
2. `How to get to it (user POV)`
3. `Driving it with audithor-verify`, which starts with `Preconditions:`
4. `Gotchas`

## Features

- [Scan an APK](./scan.md): headless and GUI scans, expected findings, severity counts, `--fail-on` exit codes, input left untouched.
- [Export a report](./export.md): JSON, HTML, and PDF output from the CLI and from the report's Export menu.
- [Scan history and report view](./history-report.md): saving scans, the History sidebar, the dashboard, findings filters, the detail pane, and deleting scans.
- [Compare scans](./compare.md): diffing two saved scans (new, resolved, persisting findings, and permission/SDK/metadata changes).
