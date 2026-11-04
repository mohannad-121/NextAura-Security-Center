#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Administrator authorization is required; run with sudo." >&2; exit 1; }
REMOVE_STATE=false
[ "${1:-}" = "--remove-local-state" ] && REMOVE_STATE=true
launchctl bootout system/com.nextaura.agent 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.nextaura.agent.plist
rm -f /usr/local/bin/nextaura-agent
if $REMOVE_STATE; then
  rm -rf "/Library/Application Support/NextAura/Agent"
  echo "Removed local enrollment state. Also revoke the device in the dashboard."
else
  echo "Preserved local state at /Library/Application Support/NextAura/Agent."
fi
echo "NextAura Agent daemon and binary removed."
