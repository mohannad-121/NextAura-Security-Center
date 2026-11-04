#!/usr/bin/env bash
# Installs, enrolls, and starts the NextAura LaunchDaemon. The enrollment code
# is read from the controlling terminal without echo and sent only over stdin.
set -euo pipefail

usage() {
  echo "usage: sudo ./install-agent.sh --server https://security.example.com [--binary ./nextaura-agent]" >&2
  exit 2
}

failure_notice() {
  echo "Installation did not complete. Any protected enrollment state is preserved; correct the reported error and run this installer again." >&2
}
trap failure_notice ERR

[ "$(id -u)" = 0 ] || { echo "Administrator authorization is required; run this installer with sudo." >&2; exit 1; }
SERVER_URL=""
SOURCE_BINARY="$(cd "$(dirname "$0")" && pwd)/nextaura-agent"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --server) [ "$#" -ge 2 ] || usage; SERVER_URL=$2; shift 2 ;;
    --binary) [ "$#" -ge 2 ] || usage; SOURCE_BINARY=$2; shift 2 ;;
    *) usage ;;
  esac
done
case "$SERVER_URL" in https://*) ;; *) echo "--server must be an https:// URL" >&2; exit 2 ;; esac
[ -f "$SOURCE_BINARY" ] || { echo "Agent binary not found: $SOURCE_BINARY" >&2; exit 1; }
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$SCRIPT_DIR/com.nextaura.agent.plist" ] || { echo "LaunchDaemon plist is missing from this package." >&2; exit 1; }

STATE_DIRECTORY="/Library/Application Support/NextAura/Agent"
STATE_PATH="$STATE_DIRECTORY/state.json"
if launchctl print system/com.nextaura.agent >/dev/null 2>&1; then
  launchctl bootout system/com.nextaura.agent
fi

install -d -m 0755 /usr/local/bin
install -d -m 0700 "$STATE_DIRECTORY"
chown root:wheel "$STATE_DIRECTORY"
install -m 0755 "$SOURCE_BINARY" /usr/local/bin/nextaura-agent

if [ ! -f "$STATE_PATH" ]; then
  printf 'Enrollment code (input hidden): ' > /dev/tty
  IFS= read -r -s ENROLLMENT_CODE < /dev/tty
  printf '\n' > /dev/tty
  [ -n "$ENROLLMENT_CODE" ] || { unset ENROLLMENT_CODE; echo "Enrollment code cannot be empty." >&2; exit 2; }
  echo "Enrolling this device with the authorized NextAura server..."
  if ! printf '%s\n' "$ENROLLMENT_CODE" | /usr/local/bin/nextaura-agent enroll --server "$SERVER_URL" --code-stdin; then
    unset ENROLLMENT_CODE
    exit 1
  fi
  unset ENROLLMENT_CODE
else
  echo "Existing protected enrollment state found at $STATE_PATH; reusing it for this repair/retry."
fi

chmod 0600 "$STATE_PATH"
chown -R root:wheel "$STATE_DIRECTORY"
install -m 0644 "$SCRIPT_DIR/com.nextaura.agent.plist" /Library/LaunchDaemons/com.nextaura.agent.plist
chown root:wheel /Library/LaunchDaemons/com.nextaura.agent.plist
launchctl bootstrap system /Library/LaunchDaemons/com.nextaura.agent.plist
launchctl print system/com.nextaura.agent | head -20
trap - ERR
echo "NextAura Agent installed. Revoke the device in the dashboard before uninstalling it."
