# AudiThor

A native macOS app for **static security analysis of Android APKs**, aligned with
the OWASP **MASVS v2** and **MASTG**. Use it to audit apps you own or are
authorized to assess.

- Drag an `.apk`, `.xapk` or `.apks` onto the window, or use **File › Open APK…** (⌘O)
- Get a severity-ranked report. Every finding maps to a MASVS control, a MASTG test and a CWE, with evidence (file + line + snippet) and remediation advice
- Export to **PDF**, **HTML** or **JSON**, or run headless in CI
- Compare two scans (for example two releases) in **diff mode**

All analysis runs locally. The input APK is only read: it is never modified,
repackaged or re-signed. The one network feature, an OSV.dev CVE lookup, is
**off by default** and only sends library coordinates and versions.

---

## Requirements

| | |
|---|---|
| macOS | 13 Ventura or later |
| Xcode | 27 (the project uses the new `project.xcproj` format) |
| Swift package | [GRDB.swift](https://github.com/groue/GRDB.swift) 7.x, resolved automatically by Xcode |

### Analysis tools

AudiThor runs proven open-source CLIs instead of reimplementing their parsers.
It finds them on `PATH`, in Homebrew prefixes, in `/Library/Java/JavaVirtualMachines`,
and in Android SDK `build-tools` (`$ANDROID_HOME`, `~/Library/Android/sdk`, or the
Homebrew `android-commandlinetools` cask). **It never downloads anything itself.**
The *Tool Setup* screen shows what's missing and gives the exact commands to run.

| Tool | Needed? | Used for | Install |
|---|---|---|---|
| Java runtime | required | runs apktool, jadx, apksigner | `brew install --cask temurin` |
| apktool | required | decoding the manifest and resources | `brew install apktool` |
| unzip | required | listing APK entries and unpacking bundles | preinstalled |
| jadx | recommended | DEX → Java for source-level checks | `brew install jadx` |
| apksigner | recommended | signature verification (v1–v4) and certificates | see below |
| aapt2 | optional | cross-checking metadata (badging) | see below |
| keytool / openssl | optional | certificate details (validity, algorithm, key size) | come with the JDK / macOS |

```bash
brew install --cask temurin
```

```bash
brew install apktool jadx
```

```bash
brew install --cask android-commandlinetools
```

```bash
sdkmanager "build-tools;35.0.0"
```

Without jadx, code checks run against smali and are less precise. Without
apksigner, AudiThor still detects v1, v2 and v3 signatures by parsing the APK
Signing Block directly, but doesn't verify them cryptographically.

## Building

```bash
open AudiThor.xcodeproj
```

Pick the **AudiThor** scheme and run it (⌘R). From the command line:

```bash
xcodebuild -scheme AudiThor -configuration Release -destination 'platform=macOS' -derivedDataPath build/dd build
```

> **App Sandbox is disabled** for this target. A sandboxed app can't run
> Homebrew/JDK tools, and those tools need to write their decoded output to a
> scratch directory. AudiThor makes up for this by only reading the input file,
> writing only under `~/Library/Caches/AudiThor` and
> `~/Library/Application Support/AudiThor`, and making no network calls unless
> you opt in.

## Using it

1. On first launch, read and accept the **authorized-use notice**.
2. Open **Tool Setup** and install anything flagged as missing.
3. Drop an APK on the window. The pipeline runs in the background with a
   per-stage progress view, and you can cancel it at any time.
4. The report opens automatically:
   - **Dashboard**: overall risk score (0–100), counts per severity (click a
     tile to filter by it) and a per-MASVS-category chart
   - **Findings**: filter by severity, MASVS category or free text (rule, CWE,
     file). The detail pane shows the description, evidence, MASVS/MASTG/CWE
     links and remediation
   - **App Details**: signature schemes and certificates, permissions, every
     component with its export status, and the SDK inventory
   - **Scan Notes**: warnings, tool versions and raw apksigner output
5. **Export** from the toolbar (PDF, HTML or JSON).
6. Use **Compare Scans** (⇧⌘D) to diff two scans. It shows new, resolved,
   persisting and severity-changed findings, plus changes to permissions, SDKs
   and metadata (signing certificate, targetSdk and so on).

Settings (⌘,): jadx on/off, whether to report issues inside third-party
libraries, how many evidence items to keep per finding, whether to keep the
decompiled workspace for manual review, and the CVE matching mode.

### Headless / CI mode

The app binary doubles as a CLI:

```bash
AudiThor.app/Contents/MacOS/AudiThor --scan app-release.apk --out report.json --fail-on high
```

| Flag | Meaning |
|---|---|
| `--scan <file>` | APK / XAPK / APKS to analyse |
| `--out <file>` | output path (format inferred from `.json`, `.html` or `.pdf`); stdout if omitted |
| `--format json\|html\|pdf` | explicit output format |
| `--fail-on <severity>` | exit **2** if there's any finding at or above `critical`, `high`, `medium`, `low` or `info` |
| `--cve off\|local\|online` | CVE matching mode (default `off`) |
| `--no-jadx` | skip decompilation (faster, less precise) |
| `--save` | also store the scan in the app's history |

Exit codes: `0` OK, `1` error, `2` the `--fail-on` threshold was hit. The JSON
report contains `summary.counts`, `summary.riskScore` and the full `scan`
object, and its schema is versioned (`scan.schemaVersion`).

## What's checked

| Area | Checks | MASVS |
|---|---|---|
| Manifest | `debuggable`, `allowBackup` (including the default), minSdk/targetSdk and the legacy behaviour each level keeps, exported activities/services/receivers/providers without a permission (implicit export through intent-filters included), guards that use non-signature permissions, custom-scheme deep links, http(s) links without `autoVerify` | PLATFORM-1, STORAGE-2, CODE-1, RESILIENCE-4 |
| Permissions | dangerous and high-risk permissions, permissions requested but with no matching API usage, weak custom permissions | PRIVACY-1, PLATFORM-1 |
| Network | cleartext traffic (manifest flag, NSC base-config and domain-config, the targetSdk < 28 default), trusted user CAs, expired pin-sets, pinning present or absent, all-trusting `X509TrustManager`, always-true `HostnameVerifier`, `onReceivedSslError → proceed()`, hardcoded `http://` endpoints | NETWORK-1, NETWORK-2 |
| Storage | world-readable/writable modes, credential-like keys in SharedPreferences, external storage, secrets (cloud keys, private keys, OAuth secrets, JWTs, tokens), credential-named literals that pass an entropy check, high-entropy literals, sensitive data in logs, raw SQL concatenation | STORAGE-1, STORAGE-2, CODE-4 |
| Crypto | DES/3DES/RC2/RC4/Blowfish, ECB (including bare `"AES"`), MD5/SHA-1 digests and signatures, static IVs, hardcoded `SecretKeySpec` keys, static PBE salts, `Random` used in crypto code, seeded `SecureRandom` | CRYPTO-1, CRYPTO-2 |
| WebView | JS enabled together with `addJavascriptInterface`, JS enabled, file/universal file access, remote debugging | PLATFORM-2, RESILIENCE-4 |
| Signing | signature schemes (v1-only and the Janus risk), the Android debug certificate, verification failures, SHA-1/MD5 certificates, RSA keys under 2048 bits, validity window (expired, not yet valid, ends before 2033) | RESILIENCE-2, CRYPTO-1 |
| SDKs | inventory from `META-INF/*.version`, `pom.properties`, package namespaces and native `.so` files; known-outdated versions; optional CVE matching | CODE-3 |

Secret values are **masked** in evidence and reports (only a 4-character prefix
is kept). By default, findings inside well-known third-party namespaces
(`androidx`, `com.google`, `okhttp3` and so on) are left out because the app
owner can't fix them directly. TLS-validation checks always include library
code.

### CVE matching (opt-in)

- **Off** (default): no CVE matching. Outdated-version warnings still appear.
- **Local database**: matches against `AudiThor/Resources/library_db.json`,
  which ships with the app. Edit that file to add entries.
- **Local + OSV.dev**: also queries `api.osv.dev`. Only `group:artifact` and
  version pairs are sent; the APK, its hash, package name and findings never
  leave the machine.

Matching is by version, so a library with a backported fix or a vulnerable path
the app never reaches can still show up. Confirm before reporting.

## Project layout

```
AudiThor/
  App/          AudiThorApp (entry point and menus), AppModel (state, scan orchestration), HeadlessCLI
  Models/       Finding / Severity / MASVSCategory, ScanResult, ScanDiff
  Tools/        ToolLocator (detection and versions), ProcessRunner (async, cancellable subprocesses)
  Pipeline/     AnalysisPipeline (stage orchestration), Workspace, ManifestParser
  Checks/       RuleEngine (parallel single-pass scanner), CodeRules (rule catalog),
                ManifestChecks, NetworkConfigChecks, SignatureAnalyzer (+ APK Signing Block parser),
                LibraryDetector, VulnerabilityMatcher, SourceIndex
  Persistence/  ScanStore (GRDB / SQLite history)
  Export/       ReportExporter (JSON, self-contained HTML, Core Text PDF)
  Views/        Root/Sidebar, NewScan (drop zone), ScanProgress, Report (dashboard, findings, detail),
                AppDetails, Diff, ToolSetup, Settings, AuthorizedUse
  Resources/    library_db.json
Scripts/build-fixture.sh     rebuilds the deliberately vulnerable test APK
TestFixtures/vulnapp.apk     test APK with known issues in every MASVS group
TestFixtures/vulnapp-src/    its apktool source (manifest, resources, smali)
```

### How the pipeline works

1. **Hash and metadata**: SHA-256 is streamed, so large APKs aren't loaded into memory.
2. **Prepare input**: `.xapk`/`.apks` bundles are unzipped into the workspace and the base APK is chosen.
3. **apktool** decodes the manifest and resources, using a per-scan framework directory.
4. **jadx** decompiles DEX to Java. A partial result is accepted, and if jadx fails or times out the code checks fall back to smali.
5. **Signature**: the APK Signing Block is parsed natively, then apksigner verifies it and openssl/keytool read the certificate details.
6. **Static checks**: a single parallel pass over the sources, resources and assets. Each file is read once and every rule runs on it.
7. **SDK inventory**, outdated-version checks, and CVE matching if enabled.
8. **Scoring and saving**: the risk score is computed and the scan is saved to `~/Library/Application Support/AudiThor/history.sqlite`.

Work runs on background tasks and subprocesses. The UI only receives progress
callbacks on the main actor, and cancelling a scan terminates the running tool.

### Adding a rule

Add a `CodeRule` to `Checks/CodeRules.swift` with:

- an ID, a severity, the MASVS control, a MASTG reference and a CWE
- a cheap `prefilter` substring
- a line regex, or a whole-file closure

Rebuild the fixture with `Scripts/build-fixture.sh` if you add a matching
example to `TestFixtures/vulnapp-src`, then check the result:

```bash
build/dd/Build/Products/Debug/AudiThor.app/Contents/MacOS/AudiThor --scan TestFixtures/vulnapp.apk --out /tmp/r.json
```

## Limitations

- Static analysis only. It can't see runtime behaviour, reflection, dynamically loaded code, or most native (`.so`) logic.
- Pattern-based checks can produce false positives and false negatives. Treat findings as leads to verify.
- For bundles, only the base APK is decompiled. Split APKs are listed but not analysed.
- Obfuscated apps (R8/ProGuard) reduce the precision of namespace-based SDK detection and of the permission-usage check.
- Xcode pinned GRDB at 7.0.0 when it first resolved. Update it with *File › Packages › Update to Latest Package Versions*.

## Legal

Use AudiThor only on applications you own or have explicit written permission
to assess. Decompiling third-party software may be restricted by licence terms
or by law where you are.
