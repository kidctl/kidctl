#!/usr/bin/env bash
# Provision a phone for kidctl over adb.
#
# Before: factory-reset the phone, go through setup WITHOUT adding any Google
# account (skip), enable Developer options + USB debugging, plug it in.
# Device owner can only be set while the phone has no account.
#
# Usage: scripts/provision.sh <device-id> <server-url> <token-file> [adb-serial]
#   device-id  : as in devices.yaml (e.g. alex-phone)
#   server-url : the server's public origin, e.g. https://kidctl.example.net
#   token-file : file holding the raw device token (from `kidctl token`)
#
# After: add the child's Google account, install and log in to the VPN app
# if you use one, then enable always_on_vpn / private_dns / no_debugging_features
# in the policy (in that order) - see docs/PROVISIONING.md (and its Play
# Protect notes, if an agent update ever stops at a dialog).
set -euo pipefail
cd "$(dirname "$0")/.."
DEV="${1:?device-id}"; URL="${2:?server-url}"; TOKF="${3:?token-file}"; SERIAL="${4:-}"
ADB="${ANDROID_HOME:-$HOME/Android/Sdk}/platform-tools/adb${SERIAL:+ -s $SERIAL}"
PKG=io.github.kidctl.agent
[ -s "$TOKF" ] || { echo "token file $TOKF missing/empty" >&2; exit 1; }

if [ ! -f "$HOME/.config/kidctl/signing.properties" ]; then
  echo "WARNING: no release keystore (~/.config/kidctl/signing.properties): the APK is signed" >&2
  echo "with this machine's debug key; future updates must use the same key." >&2
fi
(cd agent && ./gradlew -q assembleRelease)
APK=agent/app/build/outputs/apk/release/app-release.apk

accounts=$($ADB shell dumpsys account | grep -c 'Account {' || true)
if [ "$accounts" != 0 ] && ! $ADB shell dpm list-owners | grep -q $PKG; then
  echo "The phone has $accounts account(s): device owner cannot be set. Factory reset and skip accounts." >&2
  exit 1
fi
$ADB install -r -g "$APK"
$ADB shell dpm list-owners | grep -q $PKG || $ADB shell dpm set-device-owner $PKG/.AdminReceiver
$ADB shell appops set $PKG GET_USAGE_STATS allow
$ADB push "$TOKF" /data/local/tmp/kidctl.token >/dev/null
$ADB shell am broadcast -a $PKG.CONFIGURE -n $PKG/.ConfigReceiver \
  --es url "$URL" --es device_id "$DEV" --es token_file /data/local/tmp/kidctl.token
sleep 3
$ADB shell rm -f /data/local/tmp/kidctl.token
$ADB shell dpm list-owners
echo "Provisioned $DEV -> $URL. Check: MCP list_children shows it within a minute."
