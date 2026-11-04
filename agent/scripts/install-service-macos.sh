#!/usr/bin/env bash
# Installs, enrolls, and starts the NextAura LaunchDaemon.
set -euo pipefail

usage() {
  echo "usage: sudo ./install-agent.sh --server https://security.example.com --code XXXXX-... [--binary ./nextaura-agent]" >&2
  exit 2
}

[ "$(id -u)" = 0 ] || { echo "Administrator authorization is required; run this installer with sudo." >&2; exit 1; }
SERVER_URL=""
ENROLLMENT_CODE=""
SOURCE_BINARY="$(cd "$(dirname "$0")" && pwd)/nextaura-agent"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --server) [ "$#" -ge 2 ] || usage; SERVER_URL=$2; shift 2 ;;
    --code) [ "$#" -ge 2 ] || usage; ENROLLMENT_CODE=$2; shift 2 ;;
    --binary) [ "$#" -ge 2 ] || usage; SOURCE_BINARY=$2; shift 2 ;;
    *) usage ;;
  esac
done
case "$SERVER_URL" in https://*) ;; *) echo "--server must be an https:// URL" >&2; exit 2 ;; esac
[ -n "$ENROLLMENT_CODE" ] || usage
[ -f "$SOURCE_BINARY" ] || { echo "Agent binary not found: $SOURCE_BINARY" >&2; exit 1; }
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$SCRIPT_DIR/com.nextaura.agent.plist" ] || { echo "LaunchDaemon plist is missing from this package." >&2; exit 1; }

install -m 0755 "$SOURCE_BINARY" /usr/local/bin/nextaura-agent
install -d -m 0700 "/Library/Application Support/NextAura/Agent"
echo "Enrolling this device with the authorized NextAura server..."
/usr/local/bin/nextaura-agent enroll --server "$SERVER_URL" --code "$ENROLLMENT_CODE"
chmod 0600 "/Library/Application Support/NextAura/Agent/state.json"
chown -R root:wheel "/Library/Application Support/NextAura/Agent"
install -m 0644 "$SCRIPT_DIR/com.nextaura.agent.plist" /Library/LaunchDaemons/com.nextaura.agent.plist
chown root:wheel /Library/LaunchDaemons/com.nextaura.agent.plist
launchctl bootstrap system /Library/LaunchDaemons/com.nextaura.agent.plist
launchctl print system/com.nextaura.agent | head -20
echo "NextAura Agent installed. Revoke the device in the dashboard before uninstalling it."
