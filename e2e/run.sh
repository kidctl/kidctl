#!/usr/bin/env bash
# End-to-end test on an emulator: server (local) <-> agent (device owner).
# Usage: e2e/run.sh [emulator-serial]   (emulator must be booted, no accounts)
#   KIDCTL_E2E_PORT=18086 e2e/run.sh emulator-5586   # local server port (default
#   18080; the phone-side proxy uses port+1): two runs can go side by side.
# Refuses any serial that is not a running emulator: it switches adb off, sets
# a PIN, device owner... never run it against a real phone.
# Proves: provisioning, policy fetch, app suspension, gitops edit -> unsuspend,
# lock override, usage reporting, quota and downtime notifications to the child,
# device restrictions (every setting read back by the agent: no *_failed
# event), MCP "policy up to date" per device, organization name, lock
# screen info, screen lock, Wi-Fi SSID policy, locked default apps, and the
# agent's over-the-air self-update with adb switched off by no_debugging_features;
# every MCP call goes over OAuth (e2e/oauth-login.sh), the legacy URL token is
# checked once. Then the MCP write matrix (e2e/mcp-matrix.sh): every kind of
# rule changed through the MCP write tools, committed and pushed to a local
# bare repo ($OUT/infra.git) that e2e/gitops-mirror.sh copies into the
# server's config dir (standing in for ArgoCD + the ConfigMap), checked on the
# phone (including uninstall_blocked, app_config: a fake app declaring a
# managed configuration, configured on install, and user_control_disabled: a
# fake app running a foreground service, no Stop / Force stop / Clear storage
# for it), then reverted through the MCP.
#
# The agent is the release build (release key, ~/.config/kidctl/signing.properties):
# the self-update has to install over it. A device owner installed with another
# key cannot be replaced: wipe the AVD (emulator -avd kidctl37 -wipe-data).
# The phone reaches the server at 10.0.2.2 (host loopback) through e2e/proxy.py,
# not through adb reverse, so it keeps syncing once adb is off.
set -euo pipefail
cd "$(dirname "$0")/.."
SERIAL="${1:-emulator-5584}"
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
# Emulator only: check the serial before talking to it at all, then the device.
[[ "$SERIAL" =~ ^emulator-[0-9]+$ ]] || { echo "FAIL: refusing $SERIAL: not an emulator serial (emulator-NNNN)"; exit 1; }
ADB="$SDK/platform-tools/adb -s $SERIAL"
[ "$($ADB get-state 2>/dev/null)" = device ] || { echo "FAIL: $SERIAL is not connected"; exit 1; }
[ "$($ADB shell getprop ro.kernel.qemu | tr -d '\r')" = 1 ] || { echo "FAIL: refusing $SERIAL: ro.kernel.qemu != 1 (not an emulator)"; exit 1; }
PORT="${KIDCTL_E2E_PORT:-18080}"   # server, host loopback (MCP calls from here)
PPORT=$((PORT + 1))                # e2e/proxy.py: the phone talks to 10.0.2.2:$PPORT
OUT=e2e/out; rm -rf "$OUT"; mkdir -p "$OUT/config" "$OUT/agent"
PKG=io.github.kidctl.agent
TARGET=com.android.chrome     # app we block / unblock

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; exit 1; }
# `cmd | has [grep options] pattern`: like grep -q, but reads all its input.
# Under pipefail, grep -q exits at the first match and the writer upstream dies
# of SIGPIPE, which fails the pipeline although it matched (and turns a negated
# check into a false PASS).
has() { grep "$@" >/dev/null; }
suspended() { $ADB shell dumpsys package "$1" | has 'suspended=true'; }
# The policy key stays listed after removal (value null): check the value.
camera_off() { $ADB shell dumpsys device_policy | grep -A4 'userRestriction_no_camera' | has 'mValue= *true'; }
kg_showing() { $ADB shell dumpsys window | has 'isKeyguardShowing=true'; }
awake() { $ADB shell dumpsys power | has 'mWakefulness=Awake'; }
locked() { kg_showing && ! awake; }           # lockNow: keyguard up, screen off
unlocked() { awake && ! kg_showing; }
top_activity() { $ADB shell dumpsys activity activities | grep -m1 'topResumedActivity=' || true; }
pin_unlock() { # wake up, and enter the PIN if the keyguard is up
  $ADB shell input keyevent KEYCODE_WAKEUP; sleep 1
  if kg_showing; then
    $ADB shell wm dismiss-keyguard; sleep 1
    $ADB shell input text $PIN; $ADB shell input keyevent KEYCODE_ENTER
  fi
}
force_sync() { $ADB shell am broadcast -a $PKG.CONFIGURE -n $PKG/.ConfigReceiver >/dev/null; }
resolve() { $ADB shell cmd package resolve-activity --brief "$@" | tail -1 | tr -d '\r'; }
home_app() { resolve -a android.intent.action.MAIN -c android.intent.category.HOME; }
web_app() { resolve -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d https://example.com; }
home_is() { [ "$(home_app)" = "$1" ]; }
web_is() { [ "$(web_app)" = "$1" ]; }
ppa_count() { $ADB shell dumpsys device_policy | grep -c 'persistentPreferredActivity' || true; }
wifi_connected() { $ADB shell cmd wifi status | has 'Wifi is connected'; }
wifi_dropped() { ! wifi_connected; }
ssid_allowlist_is() { $ADB shell dumpsys device_policy | has -F "mSsidAllowlist=[$1]"; }
no_ssid_policy() { ! $ADB shell dumpsys device_policy | has -E 'mSsid(Allow|Deny)list='; }
has_event() { mcp events '{"child":"tester"}' | has -E "$1"; }
org_name_is() { $ADB shell dumpsys device_policy | tr -d '\r' | has -x " *organizationName=$1"; }
no_org_name() { ! $ADB shell dumpsys device_policy | has 'organizationName='; }
# The keyguard's bottom line alternates "This device belongs to ..." and the lock screen info.
kg_text() { # kg_text <exact text>: shown now at the bottom of the (awake) keyguard
  $ADB shell input keyevent KEYCODE_WAKEUP
  $ADB shell uiautomator dump /sdcard/kidctl-kg.xml >/dev/null 2>&1 || return 1
  $ADB exec-out cat /sdcard/kidctl-kg.xml | has -F "text=\"$1\" resource-id=\"com.android.systemui:id/keyguard_indication_text_bottom\""
}
wait_for() { # wait_for <secs> <description> <command...>
  local t=$1 d=$2; shift 2
  for _ in $(seq 1 "$t"); do if "$@"; then pass "$d"; return 0; fi; sleep 1; done
  fail "$d (after ${t}s)"
}

TOKEN=$(head -c 32 /dev/urandom | xxd -p -c 64)
SHA=$(printf %s "$TOKEN" | sha256sum | cut -d' ' -f1)
# MCP over OAuth (the bearer token comes from e2e/oauth-login.sh below, valid
# 1 h, longer than this run); the legacy URL token is checked once.
MCPTOK=$(head -c 32 /dev/urandom | xxd -p -c 64)
MCPSHA=$(printf %s "$MCPTOK" | sha256sum | cut -d' ' -f1)
OWNER_PW=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
ACCESS=
mcp() { # mcp <tool> <json-args> -> text result
  curl -sf -X POST "127.0.0.1:$PORT/mcp" -H "authorization: Bearer $ACCESS" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" \
    | python3 -c 'import sys,json; r=json.load(sys.stdin); print("".join(c.get("text","") for c in r["result"]["content"]))'
}
cat > "$OUT/config/devices.yaml" <<YAML
devices:
  - {id: e2e-phone, child: tester, token_sha256: $SHA}
YAML
RESTR="no_safe_boot, no_config_date_time"
write_policy() { # $1 = blocked list (device restrictions: $RESTR)
cat > "$OUT/config/tester.yaml" <<YAML
child: tester
timezone: Europe/Brussels
always_allowed: [com.google.android.dialer]
blocked: [$1]
limits:
  - {name: general, apps: ["*"], daily: {default: 8h}}
device:
  restrictions: [$RESTR]
  lock_screen_info: "$INFO"
  organization_name: "$ORG"
  hidden: [$HIDE]
  camera_disabled: true
YAML
}
HIDE=com.google.android.deskclock
INFO="kidctl e2e"; ORG="Famille e2e"
write_policy "$TARGET"

[ -f "$HOME/.config/kidctl/signing.properties" ] || fail "no release keystore (~/.config/kidctl/signing.properties)"
cargo build -q --release
./target/release/kidctl validate "$OUT/config"
# The "infra repo" the MCP write tools push to (a local bare repo), seeded
# with the initial rules by the owner (e2e/mcp-matrix.sh).
source e2e/mcp-matrix.sh
MIRROR=
ogit init -q --bare -b main "$OUT/infra.git"
ogit clone -q "$OUT/infra.git" "$OUT/infra-owner" 2>/dev/null
mkdir -p "$OUT/infra-owner/$GITOPS_PATH" && cp "$OUT/config/"*.yaml "$OUT/infra-owner/$GITOPS_PATH/"
ogit -C "$OUT/infra-owner" add -A && ogit -C "$OUT/infra-owner" commit -qm "owner: initial rules" \
  && ogit -C "$OUT/infra-owner" push -q origin HEAD:main
OWNER_HASH=$(printf %s "$OWNER_PW" | ./target/release/kidctl hash-password)
KIDCTL_OWNER_PASSWORD_HASH=$OWNER_HASH KIDCTL_PUBLIC_URL=http://127.0.0.1:$PORT KIDCTL_STATE_DIR="$OUT/oauth" \
KIDCTL_MCP_TOKEN_SHA256=$MCPSHA \
KIDCTL_GITOPS_REMOTE="$INFRA" KIDCTL_GITOPS_PATH="$GITOPS_PATH" KIDCTL_GITOPS_DIR="$PWD/$OUT/gitops" \
KIDCTL_GITOPS_AUTHOR="kidctl e2e <e2e@kidctl.invalid>" \
  ./target/release/kidctl serve --config "$OUT/config" --db "$OUT/kidctl.db" \
  --listen 127.0.0.1:$PORT --agent-dir "$OUT/agent" >"$OUT/server.log" 2>&1 &
SRV=$!
python3 -I e2e/proxy.py "$PPORT" "$PORT" "$OUT/corrupt" >"$OUT/proxy.log" 2>&1 &
PROXY=$!
PIN=1357; PIN_SET=""
NODEBUG=0   # 1 while no_debugging_features has switched adb off
cleanup() {
  if [ "$NODEBUG" = 1 ]; then
    # Failed with adb off: withdraw the release, drop no_debugging_features and
    # bring adb back through the emulator console (works without adbd).
    echo "cleanup: restoring snapshot $SNAP (adb is off)"
    rm -f "$OUT/agent/agent.json"; RESTR="no_safe_boot, no_config_date_time"; write_policy ""; sleep 12
    $ADB emu avd snapshot load "$SNAP" || true
    $ADB emu avd snapshot delete "$SNAP" || true
  fi
  if [ -n "$PIN_SET" ]; then $ADB shell locksettings clear --old $PIN >/dev/null 2>&1 || true; fi
  kill $SRV $PROXY $MIRROR 2>/dev/null || true
}
trap cleanup EXIT
for _ in $(seq 1 20); do curl -sf localhost:$PPORT/healthz >/dev/null && break; sleep 0.5; done
curl -sf localhost:$PPORT/healthz >/dev/null || fail "server/proxy not up"
ACCESS=$(KIDCTL_OWNER_PASSWORD=$OWNER_PW e2e/oauth-login.sh "http://127.0.0.1:$PORT") \
  && pass "MCP OAuth login (discovery, register, authorize, token)" || fail "MCP OAuth login"
legacy=$(curl -sf -X POST "127.0.0.1:$PORT/mcp/t/$MCPTOK" -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}') || legacy=
has list_children <<<"$legacy" && pass "legacy MCP URL token still served" || fail "legacy MCP URL token"

# "Scan apps with Play Protect" off, as in docs/PROVISIONING.md: with it on,
# Play Protect blocks every install of this developer's APK behind a dialog,
# including adb installs once ensure_verify_apps was applied.
$ADB shell settings put global package_verifier_user_consent -1
# Release build, versionCode above whatever an earlier run left installed.
installed=$($ADB shell dumpsys package $PKG | awk -F'[= ]+' '/versionCode=/{print $3; exit}')
file_vc=$(sed -n 's/^versionCode=//p' agent/version.properties)
BASE=$(( ${installed:-0} > file_vc ? ${installed:-0} + 1 : file_vc + 1 ))
(cd agent && ./gradlew -q assembleRelease "-Pkidctl.versionCode=$BASE")
cp agent/app/build/outputs/apk/release/app-release.apk "$OUT/base.apk"
inst=$($ADB install -r -g "$OUT/base.apk" 2>&1) || fail "install of the release APK (code $BASE): $inst
(device owner signed with another key? wipe the AVD: emulator -avd kidctl37 -wipe-data)"
pass "release agent versionCode $BASE installed"
# Two code-free apps offering a home screen and a browser (default_apps steps).
FAKE=io.github.kidctl.e2efake; FAKE2=$FAKE.two
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
JAR=$(ls -d "$SDK"/platforms/android-*/android.jar | sort -V | tail -1)
# Two code-free apps with a launcher icon (the agent only enforces launchable
# apps), user-installed: approval and lock steps of the MCP write matrix.
APP1=io.github.kidctl.e2eapp.one; APP2=io.github.kidctl.e2eapp.two
for p in $FAKE $FAKE2 $APP1 $APP2; do
  m=e2e/fakeapp/AndroidManifest.xml; [[ $p == io.github.kidctl.e2eapp.* ]] && m=e2e/fakeapp/Launchable.xml
  "$BT/aapt2" link -I "$JAR" --manifest $m --rename-manifest-package $p -o "$OUT/$p.u.apk"
  "$BT/zipalign" -f 4 "$OUT/$p.u.apk" "$OUT/$p.a.apk"
  "$BT/apksigner" sign --ks "$HOME/.android/debug.keystore" --ks-pass pass:android --out "$OUT/$p.apk" "$OUT/$p.a.apk"
  $ADB install -r "$OUT/$p.apk" >/dev/null
done
# An app declaring a managed configuration (device.app_config steps of the MCP
# write matrix): built here, installed by the matrix after the policy names it.
CONF=io.github.kidctl.e2econf
"$BT/aapt2" compile --dir e2e/fakeapp/res -o "$OUT/$CONF.res.zip"
"$BT/aapt2" link -I "$JAR" --manifest e2e/fakeapp/Configurable.xml -o "$OUT/$CONF.u.apk" "$OUT/$CONF.res.zip"
"$BT/zipalign" -f 4 "$OUT/$CONF.u.apk" "$OUT/$CONF.a.apk"
"$BT/apksigner" sign --ks "$HOME/.android/debug.keystore" --ks-pass pass:android --out "$OUT/$CONF.apk" "$OUT/$CONF.a.apk"
$ADB uninstall $CONF >/dev/null 2>&1 || true
# An app running a foreground service, as a VPN app does (device.user_control_disabled
# step of the MCP write matrix: Quick Settings > Active apps offers Stop for it).
FGS=io.github.kidctl.e2efgs; FGS_LABEL="kidctl e2e fgs"
mkdir -p "$OUT/fgs"
javac -Xlint:-options --release 11 -cp "$JAR" -d "$OUT/fgs" e2e/fgsapp/src/io/github/kidctl/e2efgs/*.java
"$BT/d8" --min-api 33 --lib "$JAR" --output "$OUT/fgs" "$OUT"/fgs/io/github/kidctl/e2efgs/*.class
"$BT/aapt2" link -I "$JAR" --manifest e2e/fgsapp/AndroidManifest.xml -o "$OUT/$FGS.u.apk"
python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1], "a").write(sys.argv[2], "classes.dex")' "$OUT/$FGS.u.apk" "$OUT/fgs/classes.dex"
"$BT/zipalign" -f 4 "$OUT/$FGS.u.apk" "$OUT/$FGS.a.apk"
"$BT/apksigner" sign --ks "$HOME/.android/debug.keystore" --ks-pass pass:android --out "$OUT/$FGS.apk" "$OUT/$FGS.a.apk"
$ADB uninstall $FGS >/dev/null 2>&1 || true
if ! $ADB shell dpm list-owners | has "$PKG"; then
  $ADB shell dpm set-device-owner $PKG/.AdminReceiver
fi
$ADB shell dpm list-owners | has "$PKG" && pass "device owner set" || fail "device owner"
$ADB shell appops set $PKG GET_USAGE_STATS allow
$ADB shell am broadcast -a $PKG.CONFIGURE -n $PKG/.ConfigReceiver \
  --es url "http://10.0.2.2:$PPORT" --es device_id e2e-phone --es token "$TOKEN" | has 'configured' \
  && pass "configured over adb" || fail "configure broadcast"

wait_for 60 "$TARGET suspended by policy 'blocked'" suspended $TARGET
wait_for 30 "device synced, MCP list_children shows device_owner=true" bash -c "$(declare -f mcp); PORT=$PORT ACCESS=$ACCESS; mcp list_children '{}' | grep -q 'device_owner=true'"
mcp list_children '{}' | has "(code $BASE)" && pass "agent reports versionCode $BASE (MCP)" || fail "versionCode not reported"
$ADB shell dumpsys user | has no_safe_boot && pass "restriction no_safe_boot applied" || fail "restriction"
wait_for 30 "$HIDE hidden" bash -c "$ADB shell dumpsys package $HIDE | grep -q 'hidden=true'"
wait_for 30 "camera disabled" camera_off
# The agent reports the version it holds at its next sync: MCP says whether it
# has the one served now.
SERVED=$(mcp policy '{"child":"tester"}' | head -1 | sed 's/^version //')
mcp status '{"child":"tester"}' | has -F "policy served: version $SERVED" && pass "MCP status: policy served: version $SERVED" || fail "status: no served version"
force_sync
wait_for 60 "MCP list_children: e2e-phone policy up to date ($SERVED)" bash -c "$(declare -f mcp has); PORT=$PORT ACCESS=$ACCESS; mcp list_children '{}' | grep 'e2e-phone:' | has -F 'policy up to date ($SERVED)'"
mcp status '{"child":"tester"}' | grep '^device e2e-phone:' | has -F "policy up to date ($SERVED)" && pass "MCP status: device e2e-phone policy up to date" || fail "status: $(mcp status '{"child":"tester"}' | grep '^device')"
# Every device-policy call of the setup policy (restrictions, hidden, camera,
# lock screen info, organization name, self-protection) is read back by the
# agent: nothing reported as failed.
has_event '_failed' && fail "failure events after setup: $(mcp events '{"child":"tester"}' | grep _failed)" || pass "no *_failed event after setup (every setting read back as applied)"

# GitOps edit: unblock -> server hot-reloads (10 s) -> device syncs (60 s).
write_policy ""
wait_for 120 "$TARGET unsuspended after policy edit" bash -c "! $ADB shell dumpsys package $TARGET | grep -q 'suspended=true'"

# Invalid edit: server must keep the previous config, phone keeps working.
cp "$OUT/config/tester.yaml" "$OUT/tester.good"
echo "limits: [{name: broken" > "$OUT/config/tester.yaml"
wait_for 30 "invalid policy rejected by server" grep -q "reload rejected" "$OUT/server.log"
mcp status '{"child":"tester"}' | has "limit general" && pass "previous config still served" || fail "previous config lost"
cp "$OUT/tester.good" "$OUT/config/tester.yaml"

# Lock override: everything except always_allowed is suspended.
cat > "$OUT/config/tester.overrides.yaml" <<YAML
overrides:
  - {lock: true, until: "$(date -d '+1 hour' '+%Y-%m-%dT%H:%M')"}
YAML
wait_for 120 "$TARGET suspended by lock override" suspended $TARGET
sleep 35   # one more agent check
unlocked && pass "lock override without screen: true leaves the screen unlocked" || fail "screen locked by a plain lock override"
mcp status '{"child":"tester"}' | has 'screen locked: false' && pass "MCP status: screen locked: false" || fail "MCP screen locked"
rm "$OUT/config/tester.overrides.yaml"
wait_for 120 "$TARGET unsuspended after override removed" bash -c "! $ADB shell dumpsys package $TARGET | grep -q 'suspended=true'"

# Usage reporting: open an app for ~20 s and check the server got seconds for it.
$ADB shell monkey -p com.google.android.dialer -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
$ADB shell am start -a android.settings.SETTINGS >/dev/null
$ADB shell monkey -p $TARGET -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 25
$ADB shell input keyevent KEYCODE_HOME
$ADB shell am broadcast -a $PKG.CONFIGURE -n $PKG/.ConfigReceiver >/dev/null   # forces a sync
wait_for 60 "usage of $TARGET reported, >= 10 s (MCP usage)" bash -c "$(declare -f mcp); PORT=$PORT ACCESS=$ACCESS; mcp usage '{\"child\":\"tester\"}' | grep '$TARGET' | grep -qv ' 0h00m0[0-9]s'"
mcp usage '{"child":"tester"}'
mcp status '{"child":"tester"}'
mcp apps '{"child":"tester"}' | head -20
# Reverse: removing hidden/camera_disabled from the policy must undo them.
sed -i -e '/^  hidden:/d' -e '/^  camera_disabled:/d' "$OUT/config/tester.yaml"
wait_for 150 "$HIDE visible again after policy edit" bash -c "$ADB shell dumpsys package $HIDE | grep -q 'hidden=false'"
wait_for 30 "camera re-enabled" bash -c "! ( $(declare -f has camera_off); ADB='$ADB'; camera_off )"
# Daily quota running out while the app is in use: budget = usage so far + 40 s.
used=$(mcp usage '{"child":"tester"}' | awk -v t="$TARGET" '$0 ~ t {split($1,a,/[hms]/); print a[1]*3600+a[2]*60+a[3]}')
budget=$(( ${used:-0} + 40 ))
sed -i "s/daily: {default: 8h}/daily: {default: ${budget}s}/" "$OUT/config/tester.yaml"
grep -q "default: ${budget}s" "$OUT/config/tester.yaml" || fail "could not set budget"
sleep 15   # server reload
$ADB shell am broadcast -a $PKG.CONFIGURE -n $PKG/.ConfigReceiver >/dev/null   # force sync
sleep 5
$ADB shell monkey -p $TARGET -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
wait_for 120 "$TARGET suspended when its daily budget (${budget}s) ran out during use" suspended $TARGET
mcp status '{"child":"tester"}' | grep 'limit general'
sed -i "s/daily: {default: ${budget}s}/daily: {default: 8h}/" "$OUT/config/tester.yaml"
wait_for 120 "$TARGET unsuspended after budget raised" bash -c "! $ADB shell dumpsys package $TARGET | grep -q 'suspended=true'"

# Downtime covering now.
from=$(TZ=Europe/Brussels date -d '-1 min' +%H:%M); to=$(TZ=Europe/Brussels date -d '+30 min' +%H:%M)
sed -i "s/^always_allowed:/downtime: [{start: \"$from\", end: \"$to\"}]\nalways_allowed:/" "$OUT/config/tester.yaml"
wait_for 120 "$TARGET suspended by downtime $from-$to" suspended $TARGET
$ADB shell dumpsys package com.google.android.dialer | has 'suspended=true' && fail "always_allowed app suspended in downtime" || pass "always_allowed dialer still usable in downtime"
sed -i '/^downtime:/d' "$OUT/config/tester.yaml"
wait_for 120 "$TARGET unsuspended after downtime removed" bash -c "! $ADB shell dumpsys package $TARGET | grep -q 'suspended=true'"

# ---- Notifications (policy notify, French): quota thresholds of a small limit
# while its app is in use, each once, then a downtime notice before the window.
# Contacts gets a limit "social" of its own; general (which counts it too) has none.
NAPP=com.google.android.contacts
S=$'\xc2\xa0'   # no-break space (U+00A0 in UTF-8): "Social${S}: 50${S}% utilisé"
notifs() { $ADB shell dumpsys notification --noredact | tr -d '\r'; }
notif_title() { notifs | has -F "android.title=String ($1)"; }
# The text of the notification titled $1 (same extras block, a few lines apart).
notif_text() { notifs | grep -F -B8 -A8 "android.title=String ($1)" | grep -F 'android.text=String (' | head -1 | sed 's/.*android.text=String (\(.*\))$/\1/'; }
notified_count() { mcp events '{"child":"tester","hours":2}' | grep -cF " notified $1" || true; }
$ADB shell dumpsys package $PKG | has -E 'POST_NOTIFICATIONS: granted=true.*POLICY_FIXED' \
  && pass "POST_NOTIFICATIONS granted to the agent and fixed by policy (the child cannot revoke it)" \
  || fail "POST_NOTIFICATIONS: $($ADB shell dumpsys package $PKG | grep POST_NOTIFICATIONS)"
force_sync; sleep 5
used=$(mcp usage '{"child":"tester"}' | awk -v t="$NAPP" '$0 ~ t {split($1,a,/[hms]/); print a[1]*3600+a[2]*60+a[3]}')
NB=$(( 2 * ${used:-0} + 120 ))   # 50 % is still 60 s of use ahead
sed -i "/^limits:/a\\  - {name: social, apps: [$NAPP], daily: {default: ${NB}s}}" "$OUT/config/tester.yaml"
sed -i 's/daily: {default: 8h}}/daily: {default: 8h}, notify_at: []}/' "$OUT/config/tester.yaml"
echo "notify: {quota_at: [50, 80, 95], before_downtime: 5m, locale: fr}" >> "$OUT/config/tester.yaml"
./target/release/kidctl validate "$OUT/config" >/dev/null || fail "notify policy invalid"
sleep 12; force_sync
wait_for 60 "MCP status shows notify thresholds for social, none for general" bash -c "$(declare -f mcp); PORT=$PORT ACCESS=$ACCESS; s=\$(mcp status '{\"child\":\"tester\"}'); grep -q 'notifications: on (fr)' <<<\"\$s\" && grep 'limit social' <<<\"\$s\" | grep -q 'notify at 50% 80% 95%, reached today: none' && grep 'limit general' <<<\"\$s\" | grep -q 'notify: none'"
OFF_TIMEOUT=$($ADB shell settings get system screen_off_timeout | tr -d '\r')
$ADB shell settings put system screen_off_timeout 600000   # the app stays in use ~2 min
# Contacts asks for notifications at first launch: that dialog (permission
# controller) would be the app in front instead of Contacts.
$ADB shell pm grant $NAPP android.permission.POST_NOTIFICATIONS
$ADB shell input keyevent KEYCODE_WAKEUP
$ADB shell monkey -p $NAPP -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 3; top_activity | has $NAPP && pass "$NAPP in front" || fail "$NAPP not in front: $(top_activity)"
for lvl in 50 80 95; do
  wait_for 90 "notification 'Social${S}: ${lvl}${S}% utilisé' (dumpsys notification)" notif_title "Social${S}: ${lvl}${S}% utilisé"
  txt=$(notif_text "Social${S}: ${lvl}${S}% utilisé")
  [[ "$txt" =~ ^(Il\ reste|Plus\ que)\ .*aujourd’hui\.$ ]] && pass "  text: $txt" || fail "notification text: '$txt'"
done
wait_for 90 "$NAPP suspended when 'social' (${NB}s) ran out" suspended $NAPP
notifs | has -F "NotificationChannel{mId='screen_time', mName=Temps d’écran, mDescription=, mImportance=3" \
  && pass "channel 'Temps d’écran' (screen_time), normal importance" || fail "notification channel screen_time"
notifs | has -F 'android.title=String (General' && fail "general (notify_at: []) notified" || pass "no notification for general (notify_at: [])"
$ADB shell input keyevent KEYCODE_HOME
$ADB shell settings put system screen_off_timeout "$OFF_TIMEOUT"
sleep 35; force_sync   # one more check: nothing notified again
for lvl in 50 80 95; do
  wait_for 60 "threshold $lvl notified exactly once (MCP events)" bash -c "$(declare -f mcp notified_count); PORT=$PORT ACCESS=$ACCESS; [ \"\$(notified_count quota:social:$lvl:)\" = 1 ]"
done
mcp status '{"child":"tester"}' | grep 'limit social' | has 'reached today: 50% 80% 95%' \
  && pass "MCP status: social reached 50% 80% 95% today" || fail "MCP status reached: $(mcp status '{"child":"tester"}' | grep 'limit social')"
# Downtime with lock_screen starting in 3-4 min: notice now, once, before it starts.
dstart=$(TZ=Europe/Brussels date -d '+4 min' +%H:%M); dend=$(TZ=Europe/Brussels date -d '+5 min' +%H:%M)
sed -i "s/^always_allowed:/downtime: [{start: \"$dstart\", end: \"$dend\", lock_screen: true}]\nalways_allowed:/" "$OUT/config/tester.yaml"
sleep 12; force_sync
wait_for 60 "notification 'Pause à $dstart' before the window starts" notif_title "Pause à $dstart"
txt=$(notif_text "Pause à $dstart")
[[ "$txt" =~ ^Le\ téléphone\ se\ met\ en\ pause\ et\ l’écran\ se\ verrouille\ dans\ [1-5]${S}min\.$ ]] \
  && pass "  text: $txt" || fail "downtime notification text: '$txt'"
suspended $TARGET && fail "$TARGET suspended before the downtime starts" || pass "$TARGET still usable before the downtime starts"
sleep 35; force_sync
wait_for 60 "downtime notice posted exactly once (MCP events)" bash -c "$(declare -f mcp notified_count); PORT=$PORT ACCESS=$ACCESS; [ \"\$(notified_count downtime:$dstart:)\" = 1 ]"
mcp events '{"child":"tester","hours":2}' | grep -F ' notified ' || true
# Back to no notify (and no downtime) before the window starts.
sed -i -e '/^downtime:/d' -e '/^notify:/d' -e "/name: social, apps: \[$NAPP\]/d" -e 's/, notify_at: \[\]}/}/' "$OUT/config/tester.yaml"
sleep 12; force_sync
wait_for 60 "notify removed: MCP status says notifications: off" bash -c "$(declare -f mcp); PORT=$PORT ACCESS=$ACCESS; mcp status '{\"child\":\"tester\"}' | grep -q 'notifications: off'"
wait_for 90 "$NAPP unsuspended once its limit is gone" bash -c "! $ADB shell dumpsys package $NAPP | grep -q 'suspended=true'"
[ "$(TZ=Europe/Brussels date +%H:%M)" \< "$dstart" ] || [ "$(TZ=Europe/Brussels date +%H:%M)" \> "$dend" ] || echo "note: the downtime window was reached before its removal"

# ---- Organization name and lock screen info, as Android 17 shows them on the
# keyguard (Swipe lock screen here; the same with a PIN).
wait_for 60 "organization name applied (dumpsys device_policy organizationName=$ORG)" org_name_is "$ORG"
LS_DISABLED=$($ADB shell locksettings get-disabled | tr -d '\r')
$ADB shell locksettings set-disabled false >/dev/null
$ADB shell input keyevent KEYCODE_SLEEP; sleep 2
wait_for 60 "keyguard shows 'This device belongs to $ORG'" kg_text "This device belongs to $ORG"
wait_for 60 "keyguard shows the lock screen info '$INFO'" kg_text "$INFO"
# Removing organization_name restores Android's generic text (the agent passes null).
sed -i '/^  organization_name:/d' "$OUT/config/tester.yaml"
wait_for 150 "organization name cleared after removal (dumpsys device_policy)" no_org_name
$ADB shell input keyevent KEYCODE_SLEEP; sleep 2
wait_for 60 "keyguard back to 'This device belongs to your organization'" kg_text "This device belongs to your organization"
has_event 'lock_screen_info_failed|support_message_failed|organization_name_failed' \
  && fail "device text event: $(mcp events '{"child":"tester"}' | grep _failed)" || pass "no lock screen info / support message / organization name failure event"
$ADB shell wm dismiss-keyguard; $ADB shell locksettings set-disabled "$LS_DISABLED" >/dev/null
sed -i '/^  lock_screen_info:/a\  organization_name: "'"$ORG"'"' "$OUT/config/tester.yaml"
wait_for 150 "organization name set again" org_name_is "$ORG"

# ---- Screen lock (lockNow). A child's phone has a PIN: emergency calls then go
# through the lock screen's Emergency button, which must keep working.
$ADB shell locksettings set-pin $PIN >/dev/null; PIN_SET=1
pin_unlock
wait_for 15 "PIN set, phone unlocked" unlocked
UNTIL=$(date -d '+150 sec' --iso-8601=seconds)
cat > "$OUT/config/tester.overrides.yaml" <<YAML
overrides:
  - {lock: true, screen: true, until: "$UNTIL"}
YAML
sleep 12; force_sync   # server reload, then sync now
wait_for 60 "screen locked by lock override screen: true (keyguard up, screen off)" locked
mcp status '{"child":"tester"}' | has 'screen locked: true' && pass "MCP status: screen locked: true" || fail "MCP screen locked"
$ADB shell input keyevent KEYCODE_WAKEUP; sleep 5
awake && kg_showing && pass "woken up: lock screen stays up (not turned off again)" || fail "lock screen after wake-up"
$ADB shell am start -a com.android.phone.EmergencyDialer.DIAL >/dev/null; sleep 2
force_sync; sleep 6   # a check runs while the emergency dialer is in front
awake && top_activity | has EmergencyDialer && pass "emergency dialer stays usable over the lock screen" \
  || fail "emergency dialer: $(top_activity)"
$ADB shell input keyevent KEYCODE_BACK; sleep 1
pin_unlock
wait_for 15 "re-locked after the child unlocked with the PIN" locked
echo "waiting for the override to expire ($UNTIL)"
while [ "$(date +%s)" -le "$(date -d "$UNTIL" +%s)" ]; do sleep 2; done
pin_unlock
wait_for 15 "unlocked after expiry" unlocked
sleep 40   # more than one agent check
unlocked && pass "still unlocked 40 s after expiry" || fail "locked again after expiry"
rm "$OUT/config/tester.overrides.yaml"
# Downtime with lock_screen.
from=$(TZ=Europe/Brussels date -d '-1 min' +%H:%M); to=$(TZ=Europe/Brussels date -d '+30 min' +%H:%M)
sed -i "s/^always_allowed:/downtime: [{start: \"$from\", end: \"$to\", lock_screen: true}]\nalways_allowed:/" "$OUT/config/tester.yaml"
wait_for 120 "screen locked by downtime $from-$to with lock_screen: true" locked
pin_unlock
wait_for 15 "re-locked after unlock during lock_screen downtime" locked
sed -i '/^downtime:/d' "$OUT/config/tester.yaml"
sleep 12; force_sync; sleep 5
pin_unlock
wait_for 15 "unlocked after the downtime was removed" unlocked
sleep 40
unlocked && pass "still unlocked 40 s after the downtime was removed" || fail "locked after downtime removed"
$ADB shell locksettings clear --old $PIN >/dev/null; PIN_SET=""

# ---- Wi-Fi SSID allowlist (the emulator's network is "AndroidWifi").
wait_for 300 "Wi-Fi connected before the SSID step" wifi_connected
sed -i '/^device:/a\  wifi_ssids: {allow: [kidctl-e2e-school]}' "$OUT/config/tester.yaml"
wait_for 120 "SSID allowlist applied (dumpsys device_policy)" ssid_allowlist_is kidctl-e2e-school
wait_for 60 "AndroidWifi dropped (not in the allowlist)" wifi_dropped
sed -i '/^  wifi_ssids:/d' "$OUT/config/tester.yaml"
wait_for 120 "SSID policy cleared after removal" no_ssid_policy
wait_for 300 "Wi-Fi re-joined AndroidWifi (Android's auto-join scan)" wifi_connected

# ---- Default apps. $FAKE and $FAKE2 both offer HOME and http(s) browsing.
LAUNCHER0=$(home_app); BROWSER0=$(web_app)
echo "defaults before: HOME -> $LAUNCHER0, https -> $BROWSER0"
[ "$(ppa_count)" = 0 ] || fail "persistent preferred activities before the step"
# A package that does not handle HOME: event, nothing applied.
sed -i '/^device:/a\  default_apps: {launcher: com.google.android.deskclock}' "$OUT/config/tester.yaml"
wait_for 150 "default_app_failed event for a launcher without HOME (MCP events)" has_event 'default_app_failed launcher com.google.android.deskclock: does not handle'
[ "$(home_app)" = "$LAUNCHER0" ] && [ "$(ppa_count)" = 0 ] && pass "invalid launcher not applied: HOME still $LAUNCHER0" || fail "HOME changed: $(home_app)"
# Valid launcher and browser while Chrome holds Android's browser role.
sed -i "s|^  default_apps:.*|  default_apps: {launcher: $FAKE, browser: $FAKE}|" "$OUT/config/tester.yaml"
wait_for 150 "HOME resolves to the locked launcher $FAKE" home_is $FAKE/android.app.Activity
wait_for 60 "default_app_ineffective reported (Chrome holds the browser role)" has_event "default_app_ineffective browser $FAKE: .* https still opens com.android.chrome"
[ "$(web_app)" = "$BROWSER0" ] && pass "links still open $BROWSER0 while it holds the browser role" || fail "https -> $(web_app)"
# Hide Chrome: two browsers remain, the lock picks $FAKE (without it: the chooser).
sed -i '/^device:/a\  hidden: [com.android.chrome]' "$OUT/config/tester.yaml"
wait_for 150 "https VIEW resolves to the locked browser $FAKE once Chrome is hidden" web_is $FAKE/android.app.Activity
mcp events '{"child":"tester"}' | grep default_app || true
# Removal clears both locks.
sed -i '/^  default_apps:/d' "$OUT/config/tester.yaml"
wait_for 150 "browser lock cleared: https VIEW -> chooser ($FAKE and $FAKE2 left)" web_is android/com.android.internal.app.ResolverActivity
wait_for 30 "launcher lock cleared: HOME back to $LAUNCHER0" home_is "$LAUNCHER0"
[ "$(ppa_count)" = 0 ] && pass "no persistent preferred activity left (dumpsys device_policy)" || fail "persistent preferred activities left: $(ppa_count)"
sed -i '/^  hidden: \[com.android.chrome\]/d' "$OUT/config/tester.yaml"
wait_for 150 "https VIEW back to $BROWSER0 once Chrome is visible" web_is "$BROWSER0"

# ---- Every kind of rule through the MCP write tools (GitOps), e2e/mcp-matrix.sh.
mcp_matrix

# ---- Agent self-update with adb switched off by no_debugging_features, as on
# the real phone: observed through MCP only. A snapshot taken first brings adb
# back afterwards (emulator console, independent of adbd).
code_line() { mcp list_children '{}' | grep 'e2e-phone:'; }
reports() { code_line | has -- "$1"; }
offers() { mcp list_children '{}' | has "agent release offered: code $1 "; }
adb_off() { [ "$($ADB get-state 2>/dev/null)" != device ]; }
events_has() { mcp events '{"child":"tester","hours":2}' | has -- "$1"; }
apps_suspended() { mcp apps '{"child":"tester"}' | grep -- "$1" | has 'suspended'; }
downloads() { grep -c "agent download: version_code $1 " "$OUT/server.log" || true; }
SNAP="kidctl_e2e_$$"
$ADB emu avd snapshot save "$SNAP" | has OK && pass "snapshot $SNAP saved (restores adb at the end)" || fail "snapshot save"
# A real child's restrictions (except ensure_verify_apps, see docs/PROVISIONING.md), adb off included.
RESTR="no_factory_reset, no_safe_boot, no_config_date_time, no_add_user, no_add_private_profile, no_user_switch, no_install_unknown_sources_globally, no_control_apps, no_network_reset, no_modify_accounts, no_debugging_features"
NODEBUG=1
write_policy ""
wait_for 150 "adb switched off by no_debugging_features" adb_off
V1=$((BASE + 1)); V2=$((BASE + 2))
scripts/release-agent.sh "$OUT/agent" --version-code $V1 | tail -1
wait_for 30 "server offers versionCode $V1 (MCP)" offers $V1
wait_for 240 "agent updated itself to versionCode $V1 with adb off, still device owner (MCP)" reports "(code $V1), sdk [0-9]*, device_owner=true"
code_line
events_has "updated version_code $BASE -> $V1" && pass "agent reported its update ($BASE -> $V1)" || fail "no 'updated' event"
write_policy "$TARGET"
wait_for 180 "updated agent enforces a policy edit: $TARGET suspended (MCP apps)" apps_suspended "$TARGET"

# Negative 1: an agent.json whose sha256 does not match the APK: the server
# refuses it and keeps offering $V1; the phone stays on $V1.
scripts/release-agent.sh "$OUT/agent2" --version-code $V2 | tail -1
cp "$OUT/agent2/kidctl-agent-$V2.apk" "$OUT/agent/"
jq --arg s "$(printf wrong | sha256sum | cut -d' ' -f1)" '.sha256 = $s' "$OUT/agent2/agent.json" > "$OUT/agent/.agent.json.tmp"
mv "$OUT/agent/.agent.json.tmp" "$OUT/agent/agent.json"
wait_for 30 "server rejects a release whose APK does not match agent.json" grep -q "agent release rejected, keeping version_code $V1" "$OUT/server.log"
offers $V1 && pass "server still offers $V1" || fail "bad release offered"
sleep 75   # at least one more phone sync
reports "(code $V1), sdk" && [ "$(downloads $V2)" = 0 ] && pass "phone stays on $V1, never downloads the rejected release" || fail "rejected release reached the phone"

# Negative 2: a correct release whose bytes are corrupted on the way (proxy):
# the agent refuses the APK (sha256 mismatch), reports it, keeps running $V1,
# and backs off instead of downloading again at every sync.
touch "$OUT/corrupt"
cp "$OUT/agent2/agent.json" "$OUT/agent/.agent.json.tmp" && mv "$OUT/agent/.agent.json.tmp" "$OUT/agent/agent.json"
wait_for 30 "server offers versionCode $V2" offers $V2
wait_for 180 "agent refused the corrupted APK: agent_update_failed sha256 mismatch (MCP events)" events_has "agent_update_failed version_code $V2: sha256 mismatch"
grep -q "proxy: corrupted /api/v1/agent/$V2" "$OUT/proxy.log" && pass "the download was corrupted in transit" || fail "proxy did not corrupt the download"
sleep 130  # two more phone syncs
reports "(code $V1), sdk [0-9]*, device_owner=true" && pass "agent still runs $V1, device owner, after the refused update" || fail "after refused update: $(code_line)"
[ "$(downloads $V2)" = 1 ] && pass "no retry loop: $V2 downloaded once over two more syncs (backoff)" || fail "$V2 downloaded $(downloads $V2) times"
apps_suspended "$TARGET" && pass "policy still enforced after the refused update ($TARGET suspended)" || fail "policy no longer enforced"
mcp events '{"child":"tester","hours":2}' | grep -E 'agent_|updated' || true

# Back to adb: withdraw the release, drop no_debugging_features, load the snapshot.
rm -f "$OUT/corrupt" "$OUT/agent/agent.json"
RESTR="no_safe_boot, no_config_date_time"
write_policy ""
sleep 12   # server reload
$ADB emu avd snapshot load "$SNAP" | has OK || fail "snapshot load"
NODEBUG=0
$ADB emu avd snapshot delete "$SNAP" >/dev/null || true
wait_for 60 "adb back after the snapshot restore" bash -c "[ \"\$($ADB get-state 2>/dev/null)\" = device ]"
$ADB shell dpm list-owners | has "$PKG" && pass "device owner intact after restore" || fail "device owner lost"
echo "ALL E2E CHECKS PASSED"
