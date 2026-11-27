# Compare scans

A user picks a baseline scan and a comparison scan, typically two releases of the same app, and sees new, resolved, persisting, and severity-changed findings, along with changes to permissions, SDKs, signing certificate, targetSdk, and risk score.

## Sub-features

- `compare-open`: the Compare Scans screen opens from the sidebar or with ⇧⌘D, and preselects the newest scan plus the previous scan of the same package.
- `compare-identical`: two scans of the same APK give 0 new, 0 resolved, and all findings persisting.
- `compare-changed`: a scan of a changed APK lists its new and resolved findings and its metadata deltas.
- `compare-different-package`: comparing different packages shows a warning.
- `compare-detail`: clicking a finding opens its detail in a sheet.

## How to get to it (user POV)

- The sidebar row `Compare Scans`.
- The menu item File › Compare Scans (⇧⌘D).

## Driving it with audithor-verify

Preconditions:

- `$V doctor` reports `DOCTOR OK`.
- `AUDITHOR_RUN_ID` is set.
- The computer-use `request_access` request for `devplaceholder.FSN7ABQK.AudiThor` is approved. This feature has no CLI entry point.

- **Seed identical pair.** Run `$V scan TestFixtures/vulnapp.apk a --save` and `$V scan TestFixtures/vulnapp.apk b --save`. `$V history` shows two rows.
- **Open compare.** Run `$V gui-launch`, then use `app_menu` path `["File", "Compare Scans"]`. Both pickers are preselected, and the stats read `0` New, `0` Resolved, and Persisting equal to the finding count.
- **Changed pair.** Copy `TestFixtures/vulnapp-src` to a scratch directory `$W` and run `sed -i '' 's/ android:debuggable="true"//' $W/src/AndroidManifest.xml`. Build it with `apktool b -o $W/unsigned.apk $W/src`, sign a copy with the `keytool` and `jarsigner` lines from `Scripts/build-fixture.sh`, then `$V scan $W/changed.apk c --save`. Relaunch with `$V gui-stop; $V gui-launch`, because the sidebar doesn't pick up CLI saves live. Open Compare again: it preselects `c` and the previous scan of the same package. Expect 1 Resolved, 36 Persisting, `Resolved findings (1)` containing `Application is debuggable`, and Metadata changes for `Signing cert` (each build makes a new throwaway key) and `Risk score` 97 → 96.
- **Detail sheet.** Click a finding row. A sheet opens with its MASVS/MASTG/CWE links (for the debuggable finding, `MASVS-RESILIENCE-4`, `CWE-489`). Close it with the `Close` button; Esc is refused in background control.
- **Proof.** Take an `app_screenshot` of the stats row and the findings groups, and copy each `source:` image into `build/verify-evidence/<run-id>/gui/`.

## Gotchas

- Findings match by rule plus the set of evidence files, then fall back to the rule alone. Moving code between files shows as persisting, not as new plus resolved.
- Preselection needs an earlier scan of the same package as the newest one. Otherwise Baseline stays empty and the screen shows "Choose two different scans".
- Pickers list every saved scan, not only the same package. Check the package warning when comparing across apps.
- Don't modify `TestFixtures/vulnapp-src` in place. Build changed fixtures from a copy in scratch space.
