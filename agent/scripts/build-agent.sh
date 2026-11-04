#!/usr/bin/env bash
# Builds the NextAura agent targets into agent/dist, creates complete install
# packages, and writes manifest.json + SHA256SUMS. Run from anywhere.
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
    chmod 0755 "$stage/nextaura-agent" "$stage/install-agent.sh" "$stage/uninstall-agent.sh"
    tar -C "$stage" -czf "dist/nextaura-agent-$t.tar.gz" .
  fi
  rm -rf "$stage"
done
(
  cd dist
  : > SHA256SUMS
  find . -maxdepth 1 -type f \( -name 'nextaura-agent-*.zip' -o -name 'nextaura-agent-*.tar.gz' \) -print | sort | while IFS= read -r package; do
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$package"; else shasum -a 256 "$package"; fi
  done >> SHA256SUMS
)
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
