#!/usr/bin/env bash
# Installs the already-enrolled agent as a LaunchDaemon (runs as root so
# fdesetup/launchd state can be read). Run with sudo after enrolling.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
BIN=${1:-./nextaura-agent}
install -m 0755 "$BIN" /usr/local/bin/nextaura-agent
mkdir -p "/Library/Application Support/NextAura/Agent"
install -m 0644 "$(dirname "$0")/com.nextaura.agent.plist" /Library/LaunchDaemons/com.nextaura.agent.plist
launchctl bootout system/com.nextaura.agent 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.nextaura.agent.plist
launchctl print system/com.nextaura.agent | head -5
