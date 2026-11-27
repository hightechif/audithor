# Scan an APK

A user gives AudiThor an `.apk`, `.xapk`, `.apks` or `.apkm` and gets a severity-ranked list of MASVS findings with a risk score. The input file is never modified. In CI, the exit code reports whether findings reached a chosen severity.

## Sub-features

- `scan-cli`: a headless scan writes a JSON report and exits 0.
- `scan-findings`: the fixture yields the known rule IDs across the MASVS groups.
- `scan-fail-on`: `--fail-on <severity>` exits 2 when a finding is at or above that severity, and 0 otherwise.
- `scan-readonly`: the input APK's SHA-256 and mtime are unchanged after a scan.
- `scan-no-jadx`: `--no-jadx` still produces findings (code checks fall back to smali).
- `scan-gui`: the New Scan screen shows the progress stages, then opens the report.

## How to get to it (user POV)

- Run `AudiThor.app/Contents/MacOS/AudiThor --scan <apk> --out <file>` in a terminal.
- In the GUI, use the `Choose File…` button on New Scan, or File › Open APK… (⌘O).
- Drag a file onto the drop zone ("Drop zone for Android packages").

## Driving it with audithor-verify

Preconditions:

- `$V doctor` reports `DOCTOR OK` and an up-to-date binary.
- `AUDITHOR_RUN_ID` is set by `new-run`.

- **Headless scan.** Run `$V scan TestFixtures/vulnapp.apk base`. Expect `exit=0`, and a last stderr line like `Risk 97/100 — critical 2, high 10, medium 17, low 6, info 2`.
- **Expected findings.** Run `$V assert-rules base NETWORK_TRUST_ALL_CERTS SIGNATURE_DEBUG_CERT CRYPTO_ECB_MODE CRYPTO_HARDCODED_KEY MANIFEST_DEBUGGABLE MANIFEST_EXPORTED_PROVIDER NETWORK_CLEARTEXT_ALLOWED PLATFORM_WEBVIEW_JS_BRIDGE STORAGE_HARDCODED_SECRET STORAGE_LOG_SENSITIVE SIGNATURE_V1_ONLY`. Every line should read `OK`, the package should be `com.audithor.fixture`, and there should be about 37 findings.
- **Secrets masked.** Run `grep -c 'AKIAIOSFODNN7EXAMPLE' build/verify-evidence/$AUDITHOR_RUN_ID/base.json`. The count should be `0`. `grep -c 'AKIA•' …/base.json` should be at least `1`; the key appears as `AKIA` followed by 16 `•`.
- **Fail-on.** Run `$V scan TestFixtures/vulnapp.apk failon --fail-on critical`. Expect `exit=2` and `2` in `failon.exit.txt`.
- **Read-only input.** Run `shasum -a 256 TestFixtures/vulnapp.apk` and `stat -f %m TestFixtures/vulnapp.apk` before and after a scan. Both values should be identical.
- **No jadx.** Run `$V scan TestFixtures/vulnapp.apk nojadx --no-jadx`. Expect `exit=0`; the report's `warnings` include `Scanned … (0 Java, N smali)`.
- **GUI scan (computer-use).** Run `$V gui-launch`, choose `New Scan`, and start a scan through File › Open APK…. This needs the user to pick the file in the Open panel, so report it as user-assisted. The progress view lists the eight stages, then the report opens with the same risk score as the CLI.

## Gotchas

- `java` and `apktool` must be findable from a GUI-launched process. AudiThor searches Homebrew and JDK paths itself, so a working shell `PATH` doesn't prove the GUI finds them; check Tool Setup or the report's Scan Notes → Tool versions.
- `apksigner` and `aapt2` come from `$ANDROID_HOME/build-tools/37.0.0-rc2`, so `signature.verified` is `true` here. On a machine without them it is `null`, and `SIGNATURE_VERIFY_FAILED` can't fire. Check `scan.tools` in the report before asserting signature rules.
- The app picks `build-tools/37.0.0-rc2` over the stable `37.0.0`, because its numeric sort ranks the `-rc2` suffix higher.
- A GUI scan always saves to history; a CLI scan saves only with `--save`.
- Invalid `--fail-on` or `--cve` values are ignored silently: no threshold, and CVE matching off. A typo there makes a CI gate pass, so check `<name>.exit.txt` against a run you expect to fail.
- `--no-jadx` finds fewer issues by design. On the fixture it drops from 37 to 26 findings (risk 90, 1 critical), because the Java-only rules (TrustManager, hostname verifier, WebView bridge, SharedPreferences, logging…) don't run on smali. Don't assert the full rule list against a `--no-jadx` report.
- jadx is the slowest stage on real apps (minutes). The fixture takes about 4 s total.
- Line numbers in evidence come from the decoded/decompiled files, not from `TestFixtures/vulnapp-src`.
