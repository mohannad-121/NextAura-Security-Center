#!/usr/bin/env bash
# Builds the NextAura agent targets into agent/dist, creates complete install
# packages, and writes a hash-bound manifest + SHA256SUMS. Run from anywhere.
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
  stage=$(mktemp -d)
  if [ "$os" = windows ]; then
    cp "$out" "$stage/nextaura-agent.exe"
    cp scripts/install-service-windows.ps1 "$stage/install-agent.ps1"
    cp scripts/uninstall-agent-windows.ps1 "$stage/uninstall-agent.ps1"
    cp scripts/PACKAGE_README.txt "$stage/README.txt"
    (cd "$stage" && zip -q -r "$OLDPWD/dist/nextaura-agent-$t.zip" .)
  else
    cp "$out" "$stage/nextaura-agent"
    cp scripts/install-service-macos.sh "$stage/install-agent.sh"
    cp scripts/uninstall-agent-macos.sh "$stage/uninstall-agent.sh"
    cp scripts/com.nextaura.agent.plist "$stage/com.nextaura.agent.plist"
    cp scripts/PACKAGE_README.txt "$stage/README.txt"
    raw_tar=$(mktemp)
    tar --mode=0755 -C "$stage" -cf "$raw_tar" nextaura-agent install-agent.sh uninstall-agent.sh
    tar --mode=0644 -C "$stage" -rf "$raw_tar" com.nextaura.agent.plist README.txt
    gzip -n "$raw_tar"
    mv -f "$raw_tar.gz" "dist/nextaura-agent-$t.tar.gz"
  fi
  rm -rf "$stage"
done
node scripts/write-manifest.mjs "$VERSION" "$BUILT_AT"
echo "done. Rebuilds always clear native approvals; see docs/DEPLOYMENT.md."
cat dist/SHA256SUMS
