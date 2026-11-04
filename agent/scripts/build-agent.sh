#!/usr/bin/env bash
# Builds the NextAura agent for all supported targets into agent/dist and
# writes manifest.json + SHA256SUMS. Run from anywhere; requires Go 1.22+.
#
#   ./agent/scripts/build-agent.sh            # all targets
#   ./agent/scripts/build-agent.sh darwin-arm64
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(grep -E 'const Version' internal/config/config.go | sed -E 's/.*"([^"]+)".*/\1/')
BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TARGETS=${1:-"windows-amd64 darwin-amd64 darwin-arm64"}
mkdir -p dist
for t in $TARGETS; do
  os=${t%-*}; arch=${t#*-}
  out="dist/nextaura-agent-$t"; [ "$os" = windows ] && out="$out.exe"
  echo "building $t -> $out"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$out" ./cmd/nextaura-agent
done
( cd dist && (sha256sum nextaura-agent-* 2>/dev/null || shasum -a 256 nextaura-agent-*) > SHA256SUMS )
# Preserve any existing verified/signed flags.
if [ -f dist/manifest.json ]; then
  verified=$(sed -n 's/.*"verified": *\({[^}]*}\).*/\1/p' dist/manifest.json); signed=$(sed -n 's/.*"signed": *\({[^}]*}\).*/\1/p' dist/manifest.json)
fi
cat > dist/manifest.json <<JSON
{
  "version": "$VERSION",
  "builtAt": "$BUILT_AT",
  "verified": ${verified:-{\}},
  "signed": ${signed:-{\}}
}
JSON
echo "done. Mark a platform as tested by setting verified.<platform>=true in dist/manifest.json."
cat dist/SHA256SUMS
