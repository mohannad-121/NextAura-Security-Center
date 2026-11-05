#!/usr/bin/env bash
# Verifies an externally Developer-ID-signed, notarized, and stapled package.
# It never imports certificates or reads signing credentials.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: $0 PACKAGE EXPECTED_SHA256" >&2; exit 2; }
package=$1
expected=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
actual=$(shasum -a 256 "$package" | awk '{print $1}')
[ "$actual" = "$expected" ] || { echo "package SHA-256 mismatch" >&2; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
tar -xzf "$package" -C "$stage"
binary="$stage/nextaura-agent"
[ -x "$binary" ] || { echo "package does not contain an executable nextaura-agent" >&2; exit 1; }
codesign --verify --deep --strict --verbose=2 "$binary"
spctl --assess --type execute --verbose=4 "$binary"
xcrun stapler validate "$binary"
identity=$(codesign -dv --verbose=4 "$binary" 2>&1 | awk -F= '/^Authority=/{print $2}' | paste -sd ';' -)
team_id=$(codesign -dv --verbose=4 "$binary" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2; exit}')
printf '{"schemaVersion":1,"packageSha256":"%s","developerIdAuthorities":"%s","teamIdentifier":"%s","verifiedAt":"%s"}\n' \
  "$actual" "$identity" "$team_id" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
