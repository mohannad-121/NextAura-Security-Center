#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Administrator authorization is required; run with sudo." >&2; exit 1; }

REMOVE_STATE=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --remove-local-state) REMOVE_STATE=true; shift ;;
    *) echo "usage: sudo ./uninstall-agent.sh [--remove-local-state]" >&2; exit 2 ;;
  esac
done

if launchctl print system/com.nextaura.agent >/dev/null 2>&1; then
  launchctl bootout system/com.nextaura.agent
fi
rm -f /Library/LaunchDaemons/com.nextaura.agent.plist
rm -f /usr/local/bin/nextaura-agent
if $REMOVE_STATE; then
  rm -rf "/Library/Application Support/NextAura/Agent"
  echo "Removed local enrollment state. Also revoke the device in the dashboard."
else
  echo "Preserved local state at /Library/Application Support/NextAura/Agent."
fi
echo "NextAura Agent daemon and binary removed."
