#!/bin/sh
# Rebuilds TestFixtures/vulnapp.apk — a deliberately insecure APK used to
# regression-test AudiThor's checks. Requires apktool and a JDK (keytool, jarsigner).
# The throwaway debug key is intentionally weak (1024-bit RSA, SHA1) so the
# signature checks have something to find. Never use it for anything real.
set -eu
cd "$(dirname "$0")/../TestFixtures"
rm -f vulnapp.apk vulnapp-unsigned.apk fixture-debug.keystore
apktool b -o vulnapp-unsigned.apk vulnapp-src
keytool -genkeypair -keystore fixture-debug.keystore -storepass android -keypass android \
  -alias androiddebugkey -dname "CN=Android Debug,O=Android,C=US" \
  -keyalg RSA -keysize 1024 -sigalg SHA1withRSA -validity 3650
cp vulnapp-unsigned.apk vulnapp.apk
jarsigner -keystore fixture-debug.keystore -storepass android \
  -sigalg SHA1withRSA -digestalg SHA-256 vulnapp.apk androiddebugkey || true
rm -f vulnapp-unsigned.apk
echo "Built TestFixtures/vulnapp.apk (v1-signed with a debug certificate)"
