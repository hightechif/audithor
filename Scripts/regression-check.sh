#!/bin/bash
# Scans TestFixtures/vulnapp.apk and fails if an expected rule ID is missing.
# Usage: regression-check.sh [--no-build] [--update]
# Exit: 0 pass, 1 missing rule IDs, 2 inconclusive (build/scan/report problem).
set -euo pipefail
# Byte-order everywhere so sort, comm and the Python output agree in any locale.
export LC_ALL=C

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APK="$REPO/TestFixtures/vulnapp.apk"
EXPECTED="$REPO/TestFixtures/vulnapp.expected-rules.txt"
BIN="$REPO/build/dd/Build/Products/Debug/AudiThor.app/Contents/MacOS/AudiThor"
REPORT="$REPO/build/regression/vulnapp.json"

build=1 update=0
for a in "$@"; do
  case "$a" in
    --no-build) build=0 ;;
    --update) update=1 ;;
    *) echo "usage: $0 [--no-build] [--update]" >&2; exit 2 ;;
  esac
done

err() { echo "ERROR: $*" >&2; exit 2; }

if [ "$build" = 1 ]; then
  out="$(cd "$REPO" && xcodebuild -scheme AudiThor -configuration Debug -destination 'platform=macOS' \
    -derivedDataPath build/dd build 2>&1 || true)"
  echo "$out" | grep -E 'error:|\*\* BUILD' | sort -u || true
  grep -q '\*\* BUILD SUCCEEDED \*\*' <<<"$out" || err "build failed"
fi
[ -x "$BIN" ] || err "binary not found at $BIN (run without --no-build)"
[ -f "$APK" ] || err "fixture missing: $APK"

mkdir -p "$(dirname "$REPORT")"
rm -f "$REPORT"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# Isolated HOME so the app never touches the user's history or caches.
HOME="$tmp" CFFIXED_USER_HOME="$tmp" "$BIN" --scan "$APK" --out "$REPORT" --format json \
  >"$tmp/stdout" 2>"$tmp/stderr" || { cat "$tmp/stderr" >&2; err "scan exited non-zero (see above)"; }
[ -s "$REPORT" ] || err "scan produced no report at $REPORT"

actual="$(/usr/bin/python3 -I -c '
import json, sys
for r in {f["ruleID"] for f in json.load(open(sys.argv[1]))["scan"]["findings"]}:
    print(r)
' "$REPORT" | sort -u)" || err "could not parse $REPORT"
[ -n "$actual" ] || err "scan returned zero findings ($REPORT)"

if [ "$update" = 1 ]; then
  { grep '^#' "$EXPECTED"; echo "$actual"; } >"$tmp/new" && mv "$tmp/new" "$EXPECTED"
  echo "Updated $EXPECTED ($(echo "$actual" | wc -l | tr -d ' ') rule IDs)"
  exit 0
fi

expected="$(grep -vE '^[[:space:]]*(#|$)' "$EXPECTED" | sort -u)"
missing="$(comm -23 <(echo "$expected") <(echo "$actual"))"
new="$(comm -13 <(echo "$expected") <(echo "$actual"))"

if [ -n "$new" ]; then
  echo "NOTE: new rule ID(s) not in expected list (run with --update to accept):"
  echo "$new" | sed 's/^/  + /'
fi
if [ -n "$missing" ]; then
  echo "FAIL: $(echo "$missing" | wc -l | tr -d ' ') expected rule ID(s) missing:"
  echo "$missing" | sed 's/^/  - /'
  echo "Report: $REPORT"
  exit 1
fi
echo "PASS: all $(echo "$expected" | wc -l | tr -d ' ') expected rule IDs present"
echo "Report: $REPORT"
