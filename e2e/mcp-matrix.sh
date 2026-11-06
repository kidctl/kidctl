# shellcheck shell=bash disable=SC2034  # PIN_SET, MIRROR: read by run.sh's cleanup
# MCP write matrix, sourced by e2e/run.sh (uses its helpers and variables:
# ADB, OUT, PORT, ACCESS, MCPTOK, TARGET, HIDE, FAKE, APP1, APP2, CONF, FGS, FGS_LABEL, PKG, PIN, wait_for,
# pass, fail, has, mcp, suspended, locked, unlocked, pin_unlock, force_sync,
# camera_off, wifi_*, ssid_allowlist_is, no_ssid_policy, home_*, org_name_is,
# kg_text, kg_showing).
#
# Every kind of rule is changed THROUGH THE MCP WRITE TOOLS, over OAuth, and
# checked on the phone, then reverted through the MCP and checked again. The
# GitOps loop is real except for ArgoCD: the server commits and pushes to a
# local bare repo ($OUT/infra.git, standing in for the infra repo on
# GitHub), and e2e/gitops-mirror.sh copies the pushed policies directory into
# the server's watched config directory every 2 s (standing in for ArgoCD +
# the ConfigMap); the server hot-reloads it and the phone syncs.
#
# Not covered on the emulator: always_on_vpn (needs a VPN app such as
# Tailscale installed and logged in; the rest of set_device is the same
# path). The other device fields that only have a Settings-side effect
# (screen_capture_disabled, auto_system_updates, location_always_on,
# permitted_*, support_message) go through the same set_device tool and are
# covered by the unit tests.

GITOPS_PATH=overlays/e2e/kidctl/policies
INFRA="$PWD/$OUT/infra.git"
MDIR="$OUT/matrix"

# Raw text of a tool's answer (no newline added); exit 1 on a tool error.
mcp_call() { # mcp_call <tool> <json-args>
  curl -sf -X POST "127.0.0.1:$PORT/mcp" -H "authorization: Bearer $ACCESS" -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" \
    | python3 -c 'import sys,json
r=json.load(sys.stdin)
if "error" in r: sys.stdout.write(r["error"]["message"]); sys.exit(1)
sys.stdout.write("".join(c.get("text","") for c in r["result"]["content"])); sys.exit(1 if r["result"].get("isError") else 0)'
}
tools_of() { # tools_of <url> [bearer]: names offered by tools/list
  local auth=(); [ -n "${2:-}" ] && auth=(-H "authorization: Bearer $2")
  curl -sf -X POST "$1" "${auth[@]}" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
    | python3 -c 'import sys,json; print(" ".join(t["name"] for t in json.load(sys.stdin)["result"]["tools"]))'
}
commits() { git --git-dir="$INFRA" rev-list --count main; }
served() { mcp policy '{"child":"tester"}' | head -1 | has -x "version $1"; }
not_suspended() { ! suspended "$1"; }
restriction_on() { $ADB shell dumpsys user | tr -d '\r' | has -x " *$1"; }
restriction_off() { ! restriction_on "$1"; }
app_hidden() { $ADB shell dumpsys package "$1" | has 'hidden=true'; }
app_visible() { $ADB shell dumpsys package "$1" | has 'hidden=false'; }
camera_on() { ! camera_off; }
dns_host_is() {
  [ "$($ADB shell settings get global private_dns_mode | tr -d '\r')" = hostname ] \
    && [ "$($ADB shell settings get global private_dns_specifier | tr -d '\r')" = "$1" ]
}
dns_automatic() { [ "$($ADB shell settings get global private_dns_mode | tr -d '\r')" = opportunistic ]; }
# The policy file as the repo has it (policy_source), into a file.
source_to() { # source_to <policy|overrides> <file>: writes the YAML, prints the revision
  local out
  # The trailing "." keeps the text's final newline from $( ) stripping.
  out=$(mcp_call policy_source "{\"child\":\"tester\",\"file\":\"$1\"}"; r=$?; printf .; exit $r) || fail "policy_source $1: $out"
  out=${out%.}
  printf '%s' "${out#*$'\n'---$'\n'}" > "$2"
  sed -n 's/^revision: //p' <<<"$out" | head -1
}
ogit() { # the owner's git (no user config)
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=owner GIT_AUTHOR_EMAIL=owner@kidctl.invalid \
    GIT_COMMITTER_NAME=owner GIT_COMMITTER_EMAIL=owner@kidctl.invalid git "$@"
}
APPLIED=0
wp_args() { # wp_args <policy|overrides> <yaml file> <base revision> [dry_run]
  python3 -c 'import sys,json
a={"child":"tester","file":sys.argv[1],"yaml":open(sys.argv[2]).read(),"base_revision":sys.argv[3]}
if len(sys.argv)>4: a["dry_run"]=True
print(json.dumps(a))' "$@"
}
# A write through the MCP: must commit; then wait until the server serves the
# version the tool announced (pushed -> mirrored -> reloaded) and sync the phone.
apply() { # apply <tool> <json-args> <what>
  local out v c
  out=$(mcp_call "$1" "$2") || fail "MCP $1 ($3): $out"
  has '^committed ' <<<"$out" || fail "MCP $1 ($3) committed nothing: $out"
  c=$(awk '/^committed/{print $2; exit}' <<<"$out")
  v=$(sed -n 's/.*policy version it will produce: \([0-9a-f]*\).*/\1/p' <<<"$out" | head -1)
  [ -n "$v" ] || fail "MCP $1: no version in: $out"
  APPLIED=$((APPLIED + 1))
  LAST_V=$v
  pass "MCP $1: $3 (commit $c, version $v)"
  wait_for 60 "server serves version $v (pushed, mirrored, reloaded)" served "$v"
  force_sync
}
# The phone got version $1 and applied it: it reports the version it holds at
# the sync after the one that brought it (MCP list_children: policy up to date).
# `synced <check...>`: the check, and on failure a forced sync every 5th call
# (the agent sends what it reported at its next sync, up to a minute later).
PH=0
synced() { "$@" || { PH=$((PH + 1)); [ $((PH % 5)) != 0 ] || force_sync; false; }; }
up_to_date() { mcp list_children '{}' | grep 'e2e-phone:' | has -F "policy up to date ($1)"; }
phone_has() { synced up_to_date "$1"; }
events_f() { mcp events '{"child":"tester","hours":2}' | has -F -- "$1"; }
events_e() { mcp events '{"child":"tester","hours":2}' | has -E -- "$1"; }
# The screen as uiautomator sees it (queries: e2e/ui.py).
ui() { $ADB shell uiautomator dump /sdcard/kidctl-ui.xml >/dev/null 2>&1 && $ADB exec-out cat /sdcard/kidctl-ui.xml; }
ui_has() { ui | python3 -I e2e/ui.py has "$1"; }
ui_tap() { # ui_tap <regex>: tap the first node whose text or content-desc matches
  local xy; xy=$(ui | python3 -I e2e/ui.py center "$1") && $ADB shell input tap $xy
}
ui_close() { # dialogs, Quick Settings and Settings closed: the home screen
  $ADB shell input keyevent KEYCODE_BACK; $ADB shell input keyevent KEYCODE_BACK
  $ADB shell cmd statusbar collapse; $ADB shell input keyevent KEYCODE_HOME
}
awake_unlocked() { $ADB shell input keyevent KEYCODE_WAKEUP; $ADB shell wm dismiss-keyguard; }
# Quick Settings > Active apps (the foreground-service task manager), opened afresh.
active_apps() {
  ui_close; awake_unlocked; $ADB shell cmd statusbar expand-settings
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do ui_tap '^[0-9]+ apps? (is|are) active$' && break; sleep 1; done
  for i in 1 2 3 4 5 6 7 8 9 10; do ui_has '^Active apps$' && return 0; sleep 1; done
  return 1
}
fgs_row_is() { active_apps && [ "$(ui | python3 -I e2e/ui.py fgs_row "$FGS_LABEL")" = "$1" ]; }
fgs_pid() { $ADB shell pidof $FGS | tr -d '\r'; }
fgs_running() { $ADB shell dumpsys activity services $FGS | has 'isForeground=true'; }
fgs_gone() { [ -z "$(fgs_pid)" ]; }
# Settings > App info of $1, opened afresh.
app_info() {
  ui_close; awake_unlocked; $ADB shell am force-stop com.android.settings
  $ADB shell am start -W -a android.settings.APPLICATION_DETAILS_SETTINGS -d "package:$1" >/dev/null
  local i; for i in 1 2 3 4 5 6 7 8 9 10; do ui_has '^Force stop$' && return 0; sleep 1; done
  return 1
}
blocked_by_policy() { ui_has '^Blocked by work policy$'; }
# The agent's device-policy list of packages without user control, sorted, ", "-separated.
user_control_list() {
  $ADB shell dumpsys device_policy | tr -d '\r' | grep -A4 'DefaultPolicyKey userControlDisabledPackages' \
    | sed -n 's/.*PackageNameSetPolicyValue { \[\(.*\)\] }.*/\1/p' | head -1 | tr ',' '\n' | sed 's/^ *//' | sort | paste -sd, | sed 's/,/, /g'
}
user_control_is() { [ "$(user_control_list)" = "$1" ]; }

mcp_matrix() {
  echo "---- MCP write matrix (GitOps through a local bare repo + mirror)"
  mkdir -p "$MDIR"
  # The owner's side: the repo gets the current rules plus an (empty)
  # overrides file: the MCP only edits existing files (in production every
  # child's overrides file must exist and be listed in the ConfigMap).
  local own="$OUT/infra-owner"
  ogit -C "$own" pull -q --ff-only origin main
  cp "$OUT/config/tester.yaml" "$OUT/config/devices.yaml" "$own/$GITOPS_PATH/"
  printf '# Temporary exceptions (MCP add_override / remove_override).\noverrides: []\n' > "$own/$GITOPS_PATH/tester.overrides.yaml"
  ogit -C "$own" add -A && ogit -C "$own" commit -qm "owner: rules before the MCP matrix" && ogit -C "$own" push -q origin HEAD:main
  e2e/gitops-mirror.sh "$INFRA" main "$GITOPS_PATH" "$OUT/config" "$OUT/infra-mirror" >"$OUT/mirror.log" 2>&1 &
  MIRROR=$!
  wait_for 30 "mirror: the repo's overrides file reached the served config" test -f "$OUT/config/tester.overrides.yaml"
  cmp -s "$OUT/config/tester.yaml" "$own/$GITOPS_PATH/tester.yaml" || fail "served config differs from the repo"

  # Tools: the write tools are offered over OAuth only.
  local t legacy
  t=$(tools_of "http://127.0.0.1:$PORT/mcp" "$ACCESS")
  for w in policy_source add_override remove_override prune_overrides approve_app block_app unblock_app set_limit set_downtime set_device write_policy validate_policy; do
    [[ " $t " == *" $w "* ]] || fail "write tool $w not offered over OAuth: $t"
  done
  pass "OAuth MCP offers the 12 GitOps tools"
  legacy=$(tools_of "http://127.0.0.1:$PORT/mcp/t/$MCPTOK")
  [[ " $legacy " != *" block_app "* && " $legacy " != *" write_policy "* ]] && pass "legacy URL token: read-only tools only" || fail "legacy token offers write tools: $legacy"

  # policy_source = the served file; dry runs and refused edits commit nothing.
  local rev0 n out
  rev0=$(source_to policy "$MDIR/orig.yaml")
  source_to overrides "$MDIR/orig.overrides.yaml" >/dev/null
  cmp -s "$MDIR/orig.yaml" "$OUT/config/tester.yaml" && pass "policy_source returns the file byte for byte (revision $rev0)" || fail "policy_source differs"
  n=$(commits)
  out=$(mcp_call block_app '{"child":"tester","package":"com.android.chrome","dry_run":true}') || fail "dry run: $out"
  has '^dry run, valid, nothing committed' <<<"$out" && has -F '+blocked: [com.android.chrome]' <<<"$out" || fail "dry run: $out"
  sed 's#Europe/Brussels#Mars/Base#' "$MDIR/orig.yaml" > "$MDIR/bad.yaml"
  out=$(mcp_call write_policy "$(wp_args policy "$MDIR/bad.yaml" "$rev0")") && fail "invalid policy committed: $out"
  has 'invalid, nothing committed' <<<"$out" && has 'Mars/Base' <<<"$out" || fail "invalid policy: $out"
  out=$(mcp_call set_device "{\"child\":\"tester\",\"field\":\"organization_name\",\"value\":\"$(printf 'x%.0s' $(seq 70))\"}") && fail "70-char organization_name committed"
  has 'max 64' <<<"$out" || fail "organization_name: $out"
  out=$(mcp_call policy_source '{"child":"devices","file":"policy"}') && fail "devices.yaml readable: $out"
  out=$(mcp_call block_app '{"child":"../tester","package":"com.android.chrome"}') && fail "path traversal accepted: $out"
  [ "$(commits)" = "$n" ] && pass "dry run, invalid policy, 70-char name, devices.yaml, ../tester: refused, nothing committed" || fail "something was committed"

  # 1. block_app / unblock_app.
  apply block_app '{"child":"tester","package":"com.android.chrome"}' "block $TARGET"
  wait_for 90 "$TARGET suspended (blocked through the MCP)" suspended $TARGET
  apply unblock_app '{"child":"tester","package":"com.android.chrome"}' "unblock $TARGET"
  wait_for 90 "$TARGET usable again (unblocked through the MCP)" not_suspended $TARGET

  # 2. approval (write_policy, the catch-all) + approve_app.
  local rev
  not_suspended $APP1 && not_suspended $APP2 || fail "$APP1/$APP2 suspended before approval was turned on"
  mcp apps '{"child":"tester"}' | has -F "$APP2" || fail "$APP2 not reported by the agent (not launchable?)"
  rev=$(source_to policy "$MDIR/cur.yaml")
  printf 'approval: true\n' >> "$MDIR/cur.yaml"
  apply write_policy "$(wp_args policy "$MDIR/cur.yaml" "$rev")" "approval: true (whole file, base revision $rev)"
  wait_for 90 "$APP2 suspended: user-installed and not approved" suspended $APP2
  apply approve_app "{\"child\":\"tester\",\"package\":\"$APP2\",\"mode\":\"approved\"}" "approve $APP2"
  wait_for 90 "$APP2 usable once approved" not_suspended $APP2
  suspended $APP1 && pass "$APP1 (not approved) still suspended" || fail "$APP1 not suspended"
  local rev_approval
  rev_approval=$(source_to policy "$MDIR/cur.yaml")
  apply write_policy "$(wp_args policy "$MDIR/orig.yaml" "$rev_approval")" "back to the original file (approval off)"
  wait_for 90 "$APP1 usable again (approval off)" not_suspended $APP1
  out=$(mcp_call write_policy "$(wp_args policy "$MDIR/cur.yaml" "$rev_approval")") && fail "stale base_revision accepted: $out"
  has 'changed since revision' <<<"$out" && pass "write_policy with a stale base_revision refused" || fail "stale revision: $out"

  # 3. always_allowed, under a lock override.
  apply approve_app '{"child":"tester","package":"com.android.chrome","mode":"always_allowed"}' "$TARGET always allowed"
  apply add_override '{"child":"tester","kind":"lock","until":"+20m","note":"mcp-lock"}' "lock for 20 min"
  wait_for 90 "$APP1 suspended by the lock override" suspended $APP1
  not_suspended $TARGET && pass "always_allowed $TARGET usable during the lock" || fail "$TARGET suspended despite always_allowed"
  mcp status '{"child":"tester"}' | has 'lock: true' && pass "MCP status: lock: true" || fail "status lock"
  apply approve_app '{"child":"tester","package":"com.android.chrome","mode":"approved"}' "$TARGET no longer always allowed"
  wait_for 90 "$TARGET suspended by the lock once not always_allowed" suspended $TARGET
  apply remove_override '{"child":"tester","match":"mcp-lock"}' "remove the lock"
  wait_for 90 "$TARGET usable after the lock was removed" not_suspended $TARGET
  wait_for 30 "$APP1 usable after the lock was removed" not_suspended $APP1

  # 4. Lock override with screen: true (PIN set, like a child's phone).
  $ADB shell locksettings set-pin $PIN >/dev/null; PIN_SET=1
  pin_unlock
  wait_for 15 "PIN set, phone unlocked" unlocked
  apply add_override '{"child":"tester","kind":"lock","screen":true,"until":"+15m","note":"mcp-screen"}' "lock with screen: true"
  wait_for 60 "screen locked by the MCP lock override (keyguard up, screen off)" locked
  apply remove_override '{"child":"tester","match":"mcp-screen"}' "remove the screen lock"
  pin_unlock
  wait_for 15 "unlocked after the override was removed" unlocked
  sleep 40
  unlocked && pass "still unlocked 40 s after the override was removed" || fail "locked again"
  $ADB shell locksettings clear --old $PIN >/dev/null; PIN_SET=""

  # 5. Downtime window, and 6. unlock override during it.
  local from to
  from=$(TZ=Europe/Brussels date -d '-1 min' +%H:%M); to=$(TZ=Europe/Brussels date -d '+40 min' +%H:%M)
  apply set_downtime "{\"child\":\"tester\",\"windows\":[{\"start\":\"$from\",\"end\":\"$to\"}]}" "downtime $from-$to"
  wait_for 90 "$TARGET suspended by the downtime" suspended $TARGET
  not_suspended com.google.android.dialer && pass "always_allowed dialer usable in downtime" || fail "dialer suspended"
  apply add_override '{"child":"tester","kind":"unlock","until":"+20m","note":"mcp-unlock"}' "unlock for 20 min"
  wait_for 90 "$TARGET usable in downtime under the unlock override" not_suspended $TARGET
  apply remove_override '{"child":"tester","match":"mcp-unlock"}' "remove the unlock"
  wait_for 90 "$TARGET suspended again (downtime, unlock removed)" suspended $TARGET
  apply set_downtime '{"child":"tester","windows":[]}' "no downtime"
  wait_for 90 "$TARGET usable (downtime removed)" not_suspended $TARGET

  # 7. Daily budget running out during use, and 8. extra time.
  local used budget
  # The budget counts every app of the "*" limit: start from what it has used.
  used=$(mcp status '{"child":"tester"}' | awk '$1 == "limit" && $2 == "general" && $3 == "used" {split($4,a,/[hms]/); print a[1]*3600+a[2]*60+a[3]; exit}')
  [ -n "$used" ] || fail "no 'limit general used' in MCP status"
  budget=$(( ${used:-0} + 40 ))
  apply set_limit "{\"child\":\"tester\",\"name\":\"general\",\"daily\":{\"default\":\"${budget}s\"}}" "general budget ${budget}s (used ${used:-0}s)"
  $ADB shell monkey -p $TARGET -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
  wait_for 150 "$TARGET suspended when the budget set through the MCP ran out" suspended $TARGET
  $ADB shell input keyevent KEYCODE_HOME
  apply add_override '{"child":"tester","kind":"extra","extra":"10m","limit":"general","until":"+30m","note":"mcp-extra"}' "10 min extra on general"
  wait_for 90 "$TARGET usable with the extra time" not_suspended $TARGET
  apply remove_override '{"child":"tester","match":"mcp-extra"}' "remove the extra time"
  wait_for 90 "$TARGET suspended again (extra time removed)" suspended $TARGET
  apply set_limit '{"child":"tester","name":"general","daily":{"default":"8h"}}' "general budget back to 8h"
  wait_for 90 "$TARGET usable (budget 8h)" not_suspended $TARGET

  # 9. Device restriction.
  restriction_off no_add_user || fail "no_add_user set before the step"
  apply set_device '{"child":"tester","field":"restrictions","value":["no_safe_boot","no_config_date_time","no_add_user"]}' "restriction no_add_user"
  wait_for 60 "restriction no_add_user applied (dumpsys user)" restriction_on no_add_user
  apply set_device '{"child":"tester","field":"restrictions","value":["no_safe_boot","no_config_date_time"]}' "restriction no_add_user removed"
  wait_for 60 "restriction no_add_user cleared" restriction_off no_add_user
  restriction_on no_safe_boot && pass "other restrictions kept (no_safe_boot)" || fail "no_safe_boot lost"

  # 10. Hidden app, 11. camera.
  apply set_device "{\"child\":\"tester\",\"field\":\"hidden\",\"value\":[\"$HIDE\"]}" "hide $HIDE"
  wait_for 60 "$HIDE hidden" app_hidden $HIDE
  apply set_device '{"child":"tester","field":"hidden","value":null}' "unhide"
  wait_for 60 "$HIDE visible again" app_visible $HIDE
  apply set_device '{"child":"tester","field":"camera_disabled","value":true}' "camera off"
  wait_for 60 "camera disabled" camera_off
  apply set_device '{"child":"tester","field":"camera_disabled","value":null}' "camera back"
  wait_for 60 "camera re-enabled" camera_on

  # 12. Wi-Fi SSID allowlist.
  wait_for 300 "Wi-Fi connected before the SSID step" wifi_connected
  apply set_device '{"child":"tester","field":"wifi_ssids","value":{"allow":["kidctl-e2e-mcp"]}}' "Wi-Fi allowlist"
  wait_for 60 "SSID allowlist applied (dumpsys device_policy)" ssid_allowlist_is kidctl-e2e-mcp
  wait_for 60 "AndroidWifi dropped (not in the allowlist)" wifi_dropped
  apply set_device '{"child":"tester","field":"wifi_ssids","value":null}' "no Wi-Fi policy"
  wait_for 60 "SSID policy cleared" no_ssid_policy
  wait_for 300 "Wi-Fi re-joined AndroidWifi" wifi_connected

  # 13. Default apps (launcher).
  local launcher0
  launcher0=$(home_app)
  apply set_device "{\"child\":\"tester\",\"field\":\"default_apps\",\"value\":{\"launcher\":\"$FAKE\"}}" "launcher $FAKE"
  wait_for 90 "HOME resolves to $FAKE" home_is $FAKE/android.app.Activity
  apply set_device '{"child":"tester","field":"default_apps","value":null}' "no locked default apps"
  wait_for 60 "HOME back to $launcher0" home_is "$launcher0"

  # 14. organization_name and 15. lock_screen_info, as the keyguard shows them.
  apply set_device '{"child":"tester","field":"organization_name","value":"Famille MCP"}' "organization name"
  wait_for 60 "organization name applied (dumpsys device_policy)" org_name_is "Famille MCP"
  apply set_device '{"child":"tester","field":"lock_screen_info","value":"Perdu ? Appeler la maison (MCP)"}' "lock screen info"
  local ls_disabled
  ls_disabled=$($ADB shell locksettings get-disabled | tr -d '\r')
  $ADB shell locksettings set-disabled false >/dev/null
  $ADB shell input keyevent KEYCODE_SLEEP; sleep 2
  wait_for 60 "keyguard shows 'This device belongs to Famille MCP'" kg_text "This device belongs to Famille MCP"
  wait_for 60 "keyguard shows the lock screen info set through the MCP" kg_text "Perdu ? Appeler la maison (MCP)"
  apply set_device '{"child":"tester","field":"organization_name","value":"Famille e2e"}' "organization name back"
  apply set_device '{"child":"tester","field":"lock_screen_info","value":"kidctl e2e"}' "lock screen info back"
  wait_for 60 "organization name back to Famille e2e" org_name_is "Famille e2e"
  $ADB shell input keyevent KEYCODE_SLEEP; sleep 2
  wait_for 60 "keyguard shows the lock screen info back to 'kidctl e2e'" kg_text "kidctl e2e"
  $ADB shell wm dismiss-keyguard; $ADB shell locksettings set-disabled "$ls_disabled" >/dev/null

  # 16. Private DNS.
  dns_host_is dns.google && fail "private DNS set before the step"
  apply set_device '{"child":"tester","field":"private_dns","value":{"mode":"host","host":"dns.google"}}' "private DNS dns.google"
  wait_for 90 "private DNS mode hostname dns.google (settings global)" dns_host_is dns.google
  apply set_device '{"child":"tester","field":"private_dns","value":null}' "private DNS removed"
  wait_for 90 "private DNS back to Automatic (opportunistic)" dns_automatic
  mcp events '{"child":"tester"}' | has private_dns_failed && fail "private_dns_failed: $(mcp events '{"child":"tester"}' | grep private_dns)" || pass "no private_dns_failed event"

  # 17. Notifications: notify: on with write_policy (the catch-all), then a
  # limit's notify_at with set_limit (replaced as a whole: order matters).
  rev=$(source_to policy "$MDIR/cur.yaml")
  printf 'notify: {locale: en}\n' >> "$MDIR/cur.yaml"
  apply write_policy "$(wp_args policy "$MDIR/cur.yaml" "$rev")" "notify: {locale: en} (whole file)"
  mcp status '{"child":"tester"}' | has -F 'notifications: on (en)' && pass "MCP status: notifications on (en)" || fail "status notify: $(mcp status '{"child":"tester"}')"
  mcp status '{"child":"tester"}' | grep 'limit general' | has -F 'notify at 50% 80% 95%' && pass "general: default thresholds" || fail "general thresholds"
  apply set_limit '{"child":"tester","name":"general","notify_at":[80,95]}' "general notify_at [80, 95]"
  mcp status '{"child":"tester"}' | grep 'limit general' | has -F 'notify at 80% 95%,' && pass "general: notify at 80% 95%" || fail "general notify_at: $(mcp status '{"child":"tester"}' | grep 'limit general')"
  # The file as committed (policy_source): the version alone cannot tell
  # [50, 80, 95] from no notify_at (same compiled policy, same version).
  source_to policy "$MDIR/cur.yaml" >/dev/null
  grep -q '^  - {name: general, .*, notify_at: \[80, 95\]}$' "$MDIR/cur.yaml" && pass "notify_at written in general's own flow mapping" || fail "notify_at text: $(grep -n notify_at "$MDIR/cur.yaml")"
  apply set_limit '{"child":"tester","name":"general","notify_at":[50,80,95]}' "general notify_at [50, 80, 95] (inserted before the kept ones)"
  source_to policy "$MDIR/cur.yaml" >/dev/null
  grep -q '^  - {name: general, .*, notify_at: \[50, 80, 95\]}$' "$MDIR/cur.yaml" && pass "thresholds kept in the given (ascending) order" || fail "notify_at order: $(grep -n notify_at "$MDIR/cur.yaml")"
  n=$(commits)
  out=$(mcp_call set_limit '{"child":"tester","name":"general","notify_at":[95,80]}') && fail "descending thresholds committed: $out"
  has 'invalid, nothing committed' <<<"$out" && has 'ascending' <<<"$out" && [ "$(commits)" = "$n" ] && pass "descending notify_at refused, nothing committed" || fail "descending: $out"
  apply set_limit '{"child":"tester","name":"general","notify_at":null}' "general notify_at removed (back to quota_at)"
  source_to policy "$MDIR/cur.yaml" >/dev/null
  grep -q 'notify_at' "$MDIR/cur.yaml" && fail "notify_at still in the file: $(grep -n notify_at "$MDIR/cur.yaml")" || pass "notify_at removed from the file"
  wait_for 30 "mirror: the served file has no notify_at either" bash -c "! grep -q notify_at '$OUT/config/tester.yaml'"
  mcp events '{"child":"tester"}' | has notify_permission_failed && fail "notify_permission_failed on the phone" || pass "no notify_permission_failed event"

  # 18. prune_overrides: an override that expired is deleted from the file.
  apply add_override '{"child":"tester","kind":"extra","extra":"5m","until":"+1m","note":"prune-me"}' "extra time ending in a minute"
  local until_t
  until_t=$(grep -o 'until: "[^"]*"' "$OUT/config/tester.overrides.yaml" | head -1 | sed 's/until: "\(.*\)"/\1/')
  while [ "$(date +%s)" -le "$(TZ=Europe/Brussels date -d "$until_t" +%s)" ]; do sleep 2; done
  out=$(mcp_call prune_overrides '{"child":"tester","dry_run":true}') || fail "prune dry run: $out"
  has 'prune 1 expired override' <<<"$out" || fail "prune dry run: $out"
  apply prune_overrides '{"child":"tester"}' "prune the expired override"
  source_to overrides "$MDIR/end.overrides.yaml" >/dev/null
  cmp -s "$MDIR/end.overrides.yaml" "$MDIR/orig.overrides.yaml" && pass "overrides file back to its original text" || fail "overrides differ: $(diff "$MDIR/orig.overrides.yaml" "$MDIR/end.overrides.yaml")"

  # 19. uninstall_blocked: once the phone confirms the version, the block is
  # in force (the agent reads it back with isUninstallBlocked).
  apply set_device "{\"child\":\"tester\",\"field\":\"uninstall_blocked\",\"value\":[\"$APP2\"]}" "uninstall of $APP2 blocked"
  wait_for 60 "phone has version $LAST_V (MCP list_children: policy up to date)" phone_has "$LAST_V"
  out=$($ADB shell pm uninstall $APP2 2>&1 | tr -d '\r') || true
  if has -F 'DELETE_FAILED_OWNER_BLOCKED' <<<"$out"; then pass "pm uninstall $APP2 refused: $out"
  else $ADB install -r "$OUT/$APP2.apk" >/dev/null; fail "uninstall of $APP2 not blocked: $out"; fi
  events_f "uninstall_block_failed" && fail "uninstall_block_failed: $(mcp events '{"child":"tester"}' | grep uninstall_block)" || pass "no uninstall_block_failed event"
  apply set_device '{"child":"tester","field":"uninstall_blocked","value":null}' "uninstall of $APP2 allowed again"
  wait_for 60 "phone has version $LAST_V" phone_has "$LAST_V"
  out=$($ADB shell pm uninstall $APP2 2>&1 | tr -d '\r') || true
  [ "$out" = Success ] && pass "pm uninstall $APP2 allowed once the block is removed" || fail "uninstall of $APP2 after unblocking: $out"
  $ADB install -r "$OUT/$APP2.apk" >/dev/null && pass "$APP2 installed again"

  # 20. app_config (managed configuration) of $CONF, an app that declares one
  # key of each type (e2e/fakeapp/res/xml/app_restrictions.xml). Named by the
  # policy before it is installed: applied on install (PACKAGE_ADDED).
  local conf_ok="Enabled=true, Features=[a, c], Level=3, Mode=\"always\", Server=\"https://hs.example.net\""
  apply set_device "{\"child\":\"tester\",\"field\":\"app_config\",\"value\":{\"$CONF\":{\"Enabled\":true,\"Level\":3,\"Server\":\"https://hs.example.net\",\"Mode\":\"always\",\"Features\":[\"a\",\"c\"]}}}" "app_config of $CONF (not installed yet)"
  wait_for 60 "phone has version $LAST_V" phone_has "$LAST_V"
  events_e "app_config_(applied|failed) $CONF" && fail "app_config event for an app not installed: $(mcp events '{"child":"tester"}' | grep app_config)" || pass "not installed: nothing applied, nothing failed"
  $ADB install -r "$OUT/$CONF.apk" >/dev/null && pass "$CONF installed"
  wait_for 60 "app_config applied on install, read back: $conf_ok (MCP events)" synced events_f "app_config_applied $CONF: $conf_ok"
  events_f "app_config_failed" && fail "app_config_failed: $(mcp events '{"child":"tester"}' | grep app_config)" || pass "no app_config_failed event"
  # Wrong keys and types: those keys are left out and reported, the rest set.
  apply set_device "{\"child\":\"tester\",\"field\":\"app_config\",\"value\":{\"$CONF\":{\"Enabled\":\"false\",\"Level\":\"high\",\"Mode\":\"sometimes\",\"Nope\":1,\"server\":\"x\"}}}" "app_config with wrong keys and types"
  wait_for 60 "only the valid key applied: Enabled=false (MCP events)" synced events_e " app_config_applied ${CONF//./\\.}: Enabled=false\$"
  for e in "$CONF Level: integer restriction expects a 32-bit integer, got a string \"high\"" \
           "$CONF Mode: choice restriction: \"sometimes\" is not one of [always, never, user-decides]" \
           "$CONF Nope: not declared by the app" \
           "$CONF server: not declared by the app (did you mean Server?)"; do
    wait_for 30 "app_config_failed $e" synced events_f "app_config_failed $e"
  done
  apply set_device '{"child":"tester","field":"app_config","value":null}' "app_config removed"
  wait_for 60 "app_config of $CONF cleared (read back empty)" synced events_f "app_config_applied $CONF: cleared"

  # 21. user_control_disabled: no Force stop / Clear storage for a listed app
  # (setUserControlDisabledPackages; the agent's own package always stays in
  # the list). $FGS runs a foreground service, as a VPN app does: Quick
  # Settings > Active apps offers a Stop button for it, which the
  # no_control_apps restriction does not take away (docs/CONTROLS.md).
  $ADB install -r -g "$OUT/$FGS.apk" >/dev/null && pass "$FGS installed"
  $ADB shell am start -W -n $FGS/.Main >/dev/null
  wait_for 30 "$FGS runs a foreground service" fgs_running
  wait_for 30 "Quick Settings > Active apps: Stop offered for $FGS_LABEL" fgs_row_is stop
  user_control_is "$PKG" && pass "user control disabled for the agent only: $(user_control_list)" || fail "user control list before: $(user_control_list)"
  ui_close
  apply set_device "{\"child\":\"tester\",\"field\":\"user_control_disabled\",\"value\":[\"$FGS\"]}" "no force stop for $FGS"
  wait_for 60 "phone has version $LAST_V" phone_has "$LAST_V"
  wait_for 30 "user control disabled for $FGS and the agent (dumpsys device_policy)" user_control_is "$PKG, $FGS"
  wait_for 30 "Active apps: no Stop button for $FGS_LABEL" fgs_row_is none
  local pid; pid=$(fgs_pid)
  app_info $FGS || fail "App info of $FGS: $(ui | python3 -I e2e/ui.py texts)"
  ui_tap '^Force stop$' || fail "no Force stop button"
  wait_for 10 "App info > Force stop of $FGS: Blocked by work policy" blocked_by_policy
  [ -n "$pid" ] && [ "$(fgs_pid)" = "$pid" ] && pass "$FGS still running (pid $pid)" || fail "$FGS pid $pid -> $(fgs_pid)"
  $ADB shell am force-stop $FGS
  [ "$(fgs_pid)" = "$pid" ] && pass "adb shell am force-stop ignored too (pid $pid)" || fail "am force-stop: pid $pid -> $(fgs_pid)"
  $ADB shell input keyevent KEYCODE_BACK
  ui_tap '^Storage & cache$' || fail "no Storage & cache entry: $(ui | python3 -I e2e/ui.py texts)"
  wait_for 10 "storage page shown" ui_has '^Clear storage$'
  ui_tap '^Clear storage$' || fail "no Clear storage button"
  wait_for 10 "App info > Clear storage of $FGS: Blocked by work policy" blocked_by_policy
  ui_close
  events_f "user_control_disabled_failed" && fail "user_control_disabled_failed: $(mcp events '{"child":"tester"}' | grep user_control)" || pass "no user_control_disabled_failed event"
  apply set_device '{"child":"tester","field":"user_control_disabled","value":null}' "force stop of $FGS allowed again"
  wait_for 60 "phone has version $LAST_V" phone_has "$LAST_V"
  wait_for 30 "user control disabled for the agent only again" user_control_is "$PKG"
  wait_for 30 "Active apps: Stop offered again for $FGS_LABEL" fgs_row_is stop
  local xy; xy=$(ui | python3 -I e2e/ui.py fgs_stop "$FGS_LABEL") && $ADB shell input tap $xy || fail "no Stop button to tap"
  wait_for 30 "$FGS stopped from Quick Settings once allowed" fgs_gone
  ui_close
  $ADB uninstall $FGS >/dev/null && pass "$FGS uninstalled"

  # Back to the original rules (write_policy), byte for byte.
  rev=$(source_to policy "$MDIR/cur.yaml")
  if ! cmp -s "$MDIR/cur.yaml" "$MDIR/orig.yaml"; then
    diff "$MDIR/orig.yaml" "$MDIR/cur.yaml" || true
    apply write_policy "$(wp_args policy "$MDIR/orig.yaml" "$rev")" "back to the original rules"
  fi
  source_to policy "$MDIR/end.yaml" >/dev/null
  cmp -s "$MDIR/end.yaml" "$MDIR/orig.yaml" && pass "policy file back to its original text" || fail "policy differs"

  # Every commit made through the MCP names the OAuth client and has the
  # configured author.
  local log mine bad
  log=$(git --git-dir="$INFRA" log --format='%an <%ae>|%s|%(trailers:key=Requested-By,valueonly,separator=%x2C)' main)
  mine=$(grep -c '|kidctl-mcp: ' <<<"$log" || true)
  bad=$(grep '|kidctl-mcp: ' <<<"$log" | grep -vc '^kidctl e2e <e2e@kidctl.invalid>|kidctl-mcp: [a-z_]* tester: .*|kidctl e2e (OAuth client [^)]*)$' || true)
  [ "$mine" = "$APPLIED" ] && [ "$bad" = 0 ] && pass "$mine MCP commits (one per write), each with the author and Requested-By: kidctl e2e (OAuth client ...)" \
    || fail "commits: $mine for $APPLIED writes, malformed: $bad
$log"
  grep '|kidctl-mcp: ' <<<"$log" | head -3

  kill $MIRROR 2>/dev/null || true; MIRROR=
  echo "---- MCP write matrix done"
}
