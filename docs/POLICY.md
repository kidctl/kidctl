# Policy reference

One directory (on Kubernetes: a directory of your GitOps repository, mounted
as a ConfigMap, see `deploy/k8s`):

| File | Content |
|---|---|
| `<child>.yaml` | the child's rules (file name = `child:`) |
| `<child>.overrides.yaml` | optional temporary exceptions |
| `devices.yaml` | phones allowed to sync, and whose they are |

Validate before pushing: `kidctl validate <dir>` (or the MCP tool `validate`).
An invalid push is rejected by the server, which keeps serving the previous
valid config (and logs `config reload rejected`).

## Changing rules by talking to Claude (MCP write tools)

When the server has GitOps writes configured (`KIDCTL_GITOPS_*`, see
[SERVER.md](SERVER.md#mcp-write-tools-gitops)), Claude connected over OAuth can change every rule. Each change is a
**git commit pushed to the infra repo**, exactly like a manual edit: the server
fetches the branch, edits `<child>.yaml` or `<child>.overrides.yaml` (nothing
else), validates the whole directory like `kidctl validate`, commits
(`kidctl-mcp: <tool> <child>: <summary>`, trailer `Requested-By: <OAuth
client>`) and pushes; phones apply it within about 2-3 minutes (ArgoCD polls
git every 60 s, then ConfigMap refresh and the phones' 1-minute sync). The answer
gives the commit, the diff, and the policy version to expect from the MCP
`policy` tool.

| Tool | Changes |
|---|---|
| `add_override` | a `lock` (optionally `screen: true`), `unlock` or `extra` entry; times local, RFC 3339, or `+30m` from now |
| `remove_override`, `prune_overrides` | one entry (by index or text), or every expired one |
| `approve_app` | puts a package in exactly one place: `approved`, `always_allowed`, `limit:<name>`, or `unlimited_outside_downtime` (approved and excluded from every `"*"` limit) |
| `block_app`, `unblock_app` | `blocked` (block also takes it out of `always_allowed`; unblock restores the rest) |
| `set_limit` | a limit's `apps`, `exclude`, `daily`, `notify_at` (or a new limit); `notify_at: null` removes it (back to `notify.quota_at`), `[]` = no notification for that limit |
| `set_downtime` | the whole `downtime` list |
| `set_device` | any `device.<field>`; `null` removes it |
| `write_policy` | the whole file, for anything else (e.g. the top-level `notify:` block, and fields added later); refused unless `base_revision` is the file's current revision (`policy_source`) |
| `policy_source`, `validate_policy` | read a file with its comments and revision; check a candidate file |

Every write tool takes `dry_run: true` (diff + validation, no commit). The
structured tools keep the file's comments and layout: only the lines that
change are touched (a new list item goes after the last one, in the list's
own style; a removed item takes its own line and trailing comment with it).
The MCP never writes `devices.yaml`, never creates a file (each child needs an
existing `<child>.overrides.yaml`, `overrides: []` when empty, listed in the
ConfigMap), and is not offered on the legacy URL token.

## `<child>.yaml`

```yaml
child: alex                      # lowercase, must match the file name
timezone: Europe/Brussels        # IANA zone: defines "today" and all clock times

downtime:                        # windows when only always_allowed apps work
  - {start: "22:00", end: "07:00"}            # may cross midnight
  - {start: "13:00", end: "14:00", days: [sat, sun]}   # days = days the window STARTS
  - {start: "23:00", end: "06:00", lock_screen: true}  # also keep the screen locked

always_allowed: [com.google.android.dialer]   # never limited, usable in downtime
blocked: [com.zhiliaoapp.musically]           # never usable

approval: true                   # user-installed apps not named anywhere below
approved: [com.duolingo]         #   stay suspended until listed (here or in a limit)

limits:                          # daily budgets; an app must have budget left in
  - name: social                 #   EVERY limit that matches it
    apps: [com.instagram.android]
    daily: {weekdays: 30m, weekend: 45m}
  - name: video
    apps: [com.netflix.mediaclient]
    daily: {fri: 2h30m, sat: 2h30m, default: 0}   # 0 = blocked that day
    notify_at: [90]              # this limit's notification thresholds ([] = none)
  - name: general
    apps: ["*"]                  # every app not always_allowed / excluded
    exclude: [com.netflix.mediaclient]
    daily: {weekdays: 1h, weekend: 1h30m}

notify: {quota_at: [50, 80, 95], before_downtime: 5m, locale: fr}   # see "Notifications"

device:                          # applied once per policy version
  restrictions: [no_factory_reset, no_safe_boot, ...]   # see CONTROLS.md
  uninstall_blocked: [com.tailscale.ipn]
  user_control_disabled: [com.tailscale.ipn]   # no Force stop / Clear storage, see CONTROLS.md
  hidden: [com.android.chrome]   # disappears from the launcher
  camera_disabled: false
  screen_capture_disabled: false
  auto_system_updates: true
  location_always_on: true
  permitted_accessibility_services: []   # [] = only system ones; omit = any
  permitted_input_methods: [com.google.android.inputmethod.latin]
  always_on_vpn: {package: com.tailscale.ipn, lockdown: true}
  private_dns: {mode: host, host: dns.example.net}    # or {mode: opportunistic}; removed: Automatic again
  lock_screen_info: "Alex's phone - call ..."
  support_message: "Managed by your parents."
  organization_name: kidctl      # "This device belongs to kidctl" (max 64 characters)
  wifi_ssids: {allow: [HomeNet, "École du Centre"]}   # or {deny: [...]}; omit = any
  default_apps:                  # locked defaults (pair with disallow_config_default_apps)
    launcher: com.google.android.apps.nexuslauncher
    browser: org.mozilla.firefox  # see "Default apps": other browsers must be hidden
  app_config:                    # managed configurations, see "App configurations"
    com.tailscale.ipn: {ForceEnabled: true, Hostname: kid-phone}
```

Durations: `1h30m`, `45m`, `2h`, `90s`, `0`. Day keys in `daily`: `mon`..`sun`,
`weekdays`, `weekend`, `default` (most specific wins); every day must end up
with a value.

## Evaluation order (per app, re-evaluated every ~30 s on the phone)

1. `blocked` → blocked
2. `always_allowed` → allowed
3. `approval` and a user-installed app named nowhere → blocked (unapproved)
4. active `unlock` override → allowed
5. active `lock` override → blocked
6. inside a downtime window → blocked
7. any matching limit with `used >= budget (+ active extra time)` → blocked
8. allowed

Usage = foreground seconds since local midnight, summed over **all the child's
phones**. A suspended app shows Android's "app paused" dialog.

Never suspended (built-in): the agent, the launcher, Settings, System UI, the
default dialer, emergency apps, Play Store (protected by Android).

## Notifications (`notify`)

The child's phone shows a notification when a daily quota is getting used up,
and a few minutes before downtime starts. **Off unless `notify:` is present**
(policies written before this feature are unchanged); `notify: {}` turns it on
with the defaults.

```yaml
notify:
  quota_at: [50, 80, 95]   # % of each limit's budget (default); integers 1..99, ascending
  before_downtime: 5m      # notice before downtime (default 5m); 0..60m, 0 = none
  locale: fr               # fr (default) or en
limits:
  - name: social
    apps: [com.instagram.android]
    daily: {weekdays: 30m, weekend: 45m}
    notify_at: [80, 95]    # this limit only (replaces quota_at); [] = no notification
```

`notify_at` is only valid with `notify:` at the top. What the child sees (French;
`en` gives the English equivalents), on the channel "Temps d’écran" (normal
importance, Settings > Notifications):

| When | Title | Text |
|---|---|---|
| a limit crosses a threshold | « Social : 80 % utilisé » | « Il reste 6 min aujourd’hui. » (from 90 %: « Plus que 2 min aujourd’hui. ») |
| 5 min before downtime | « Pause à 22:00 » | « Le téléphone se met en pause dans 5 min. » |
| same, window with `lock_screen` | « Pause à 19:00 » | « Le téléphone se met en pause et l’écran se verrouille dans 5 min. » |
| a `lock_screen` window starting inside downtime | « Verrouillage à 23:00 » | « L’écran se verrouille dans 5 min. » |

Rules (same in both evaluators, `eval::notify_step`, vectors `notify_cases`
in `spec/vectors.json`):

- **Each threshold at most once per limit and local day.** Several crossed at
  once (phone off, usage from another phone) give one notice, for the highest.
  The thresholds reset at local midnight.
- **Extra time:** when the budget grows (an `extra` override), the percentage
  drops; the thresholds above the new percentage are armed again and notify
  again when crossed, those still below stay silent. Example: social at 95 %
  of 30 min, +20 min: now 57 %, no notice; 80 % of 50 min later notifies.
- **Each limit notifies on its own** (one notification per limit, a higher
  threshold replaces the previous one): an app in a sub-limit (`social`) also
  counts in `general`, and both may notify, with their own remaining time.
  Use `notify_at: []` on a limit to silence it.
- **No duplicate in the same check:** when several limits cross a threshold
  in the same evaluation (~30 s) and they count a same app used today, only
  the one with the least time left notifies (equal: the one written first in
  the policy); the others' thresholds count as notified (they do not come
  later). Limits sharing no used app (e.g. `video` and `social`) both notify.
  Example: Instagram at 24 of 30 min (`social` 80 %) with Chrome bringing
  `general` to 54 of 60 min (90 %, i.e. its 80 %) in the same check: only
  « Social : 80 % utilisé » (6 min left in both, `social` comes first).
- No notice for a limit at budget 0 that day, nor when the limit is already
  exhausted (the app is paused, Android's dialog says so), nor while an
  `unlock`, a `lock` or a downtime window is active (limits decide nothing
  then; the notice comes afterwards if still due).
- **Downtime:** one notice per start, `before_downtime` ahead (checked when it
  falls due, else at the next check, ~30 s). None if an `unlock` override
  covers the start; when an unlock ends inside a downtime window, that end
  counts as a start (notice before the party ends).
- Quota notices disappear at midnight, downtime notices when downtime starts.

The agent saves what it notified synchronously (no repeat after a restart),
holds `POST_NOTIFICATIONS` fixed by policy (the child cannot revoke it), and
reports each notice as an event `notified` (MCP `events`); `notify_blocked` if
the child turned the channel off. MCP `status` shows per limit the thresholds
and those reached today (from the usage the server has).

## Screen lock

A `lock` override with `screen: true`, or a downtime window with
`lock_screen: true`, also locks the **screen itself** (`lockNow`), on top of
suspending apps. Whether the screen must be locked now (same rules in both
evaluators, see `spec/vectors.json`):

1. active `unlock` override → not locked
2. active `lock` override with `screen: true` → locked
3. inside a downtime window with `lock_screen: true` → locked
4. otherwise not locked

While it applies, the phone locks as soon as the rule starts (at the next
check, within ~30 s, or right after the policy arrives) and again about 1 s
after every unlock. **`always_allowed` apps do not bypass it**: they are
behind the lock screen like everything else (the default dialer included).
When the rule ends nothing is done: the child unlocks normally.

Emergency calls stay possible (Android's lock screen):

- With a **PIN, pattern or password** (recommended), the lock screen's
  *Emergency call* button works as usual: the agent never locks while the
  keyguard is showing, which includes the emergency dialer or an incoming call
  displayed over it.
- No lock is applied during a phone call (ringing, in call), so an ongoing
  call, emergency or not, is never cut off by the screen going dark; the lock
  comes after the call.
- With lock screen **Swipe or None** there is no emergency button and unlocking
  needs no secret, so after each unlock the phone stays usable for 15 s (enough
  to start an emergency call from the dialer) before it locks again. Set a PIN
  on a child's phone. Android's Emergency SOS (press power 5 times) always works.

## Lock screen texts (`lock_screen_info`, `organization_name`)

On Android 17 (checked on the API 37.2 emulator, Swipe and PIN lock screens)
the bottom line of the lock screen alternates every few seconds between
"This device belongs to <organization_name>" and `lock_screen_info`. Without
`organization_name` Android says "This device belongs to your organization"
(the same name appears in Settings and Quick Settings). `organization_name`:
1 to 64 characters, no control characters; `lock_screen_info` and
`support_message` (shown when the child taps a setting the policy disables)
are free text. Removing a field from the policy restores Android's default. A
call Android refuses is reported as an event (`lock_screen_info_failed`,
`support_message_failed`, `organization_name_failed`).

## Wi-Fi networks (`device.wifi_ssids`)

`{allow: [...]}` (only these networks can be joined) or `{deny: [...]}`
(these cannot), exactly one, non-empty, no duplicates; each SSID is at most 32
bytes in UTF-8 (`École` counts 6). Uses `setWifiSsidPolicy` (Android 13+); a
connected network that stops being allowed is dropped. Removing `wifi_ssids`
clears the policy (Android re-joins known networks at its next scan, up to a
few minutes).

**Warning: an allowlist blocks every network not listed**: school, friends,
grandparents, a hotel... The phone then only has mobile data there. Prefer a
denylist unless the phone must never join an unknown network.

## Default apps (`device.default_apps`)

`launcher` (home screen) and `browser` (http/https links), both optional,
locked with `addPersistentPreferredActivity`. The server rejects a package
name that is not valid or that is in `blocked` or `device.hidden`. On the phone
the agent first checks that the package is installed and really handles the
intent (HOME, or VIEW + BROWSABLE on http and https); if not, that entry is not
applied (that role keeps the system default) and a `default_app_failed` event
is reported (MCP `events`). It is re-checked whenever an app is installed or
removed. Removing an entry clears it; for the launcher the agent also gives
HOME back to the app that had it before.

- Add `disallow_config_default_apps` to `device.restrictions`, so the child
  cannot change default apps in Settings.
- **Browser:** for web links Android asks the holder of its *browser role*
  (Chrome by default) before any locked preference, and a device owner cannot
  change that role. So the browser lock only takes effect once the other
  browsers are out of the way: list them in `device.hidden` (e.g.
  `hidden: [com.android.chrome]`). If links still open another app after
  applying, the agent reports `default_app_ineffective` with the app that wins.
- With `approval: true`, also list the chosen apps in `approved` (or
  `always_allowed`), otherwise a user-installed browser/launcher is suspended.

## App configurations (`device.app_config`)

Managed configurations ("app restrictions"): settings an app lets its
administrator fix, which the user then cannot change in the app. The device
owner sets them with `setApplicationRestrictions`; each app declares the keys
it supports, with their types, in its manifest (`res/xml/app_restrictions.xml`).

```yaml
device:
  app_config:
    com.tailscale.ipn:                       # package -> key -> value
      ForceEnabled: true                     # bool
      UseTailscaleDNSSettings: always        # choice: one of the declared values
      ExitNodesPicker: hide
      LoginURL: https://hs.example.net       # string
      Hostname: kid-phone
      ManagedByOrganizationName: Parents
```

Values: booleans, integers (32-bit), strings, or lists of strings (for a
multi-select key). The server checks the package names, the keys (non-empty,
no control characters) and the value types; nested mappings (bundle keys) are
not supported. On the phone the agent reads what the app declares
(`RestrictionsManager.getManifestRestrictions`) and converts each value to
the declared type: `bool` (also `"true"` / `"false"`), `integer` (also a
numeric string), `string` and `hidden` (any scalar, as text), `choice` (must
be one of the declared values), `multi-select` (a list, or one value; each
declared). A key the app does not declare, or a value it cannot take, is left
out (the other keys are still set) and reported as `app_config_failed` (`<pkg>
<key>: <why>`, e.g. `not declared by the app (did you mean Hostname?)`); an
app that declares no managed configuration at all is reported too.

The configuration is set only when the app's current one differs, then read
back; an `app_config_applied` event (MCP `events`) says what the app now has
(`<pkg>: ForceEnabled=true, Hostname="kid-phone", ...`; values of keys whose
name contains key, token, secret, passw or credential are shown as
`<redacted>`). An app that is not installed yet gets its configuration when it
is installed (and it is checked again after each update of the app). Removing a package from
`app_config` (or the whole field) clears its configuration (`<pkg>: cleared`);
apps never named in the policy are left alone.

**Tailscale** (1.104): `ForceEnabled: true` is Tailscale's "always on"
system policy (the user is not meant to be able to disconnect from the app).
It is what `always_on_vpn` without lockdown lacks: Android only keeps the VPN
app running, Tailscale's own switch still turns the tunnel off (no tunnel, so
no DNS filtering, and Android does not restart it).
`UseTailscaleDNSSettings: always` keeps the DNS of the tailnet (filtering),
`ExitNodesPicker: hide` hides the exit-node choice, `LoginURL` points it at a
self-hosted control server (Headscale), `Hostname` names the device. The
exact keys and types are those the installed version declares: after a change,
check `events` for `app_config_applied` / `app_config_failed`.

## Problems reported by the agent

Every device setting is applied through Android's device-policy API and, where
Android lets the agent read it back, checked afterwards. A call that throws,
returns an error code (private DNS), returns false (`setApplicationHidden`,
`setPermittedAccessibilityServices`, `setPermittedInputMethods`,
`setPermissionGrantState`) or whose effect is not there when read back is
reported as an event (MCP `events`), once while it lasts (again if it goes
away and comes back, or after a restart of the agent): `restriction_failed`,
`uninstall_block_failed`, `hide_failed`, `vpn_failed`, `private_dns_failed`
(with Android's code: 1 host not serving DNS over TLS, 2 failure setting),
`camera_failed`, `screen_capture_failed`, `update_policy_failed`,
`location_failed`, `a11y_policy_failed`, `ime_policy_failed`,
`lock_screen_info_failed`, `support_message_failed`,
`organization_name_failed` (set only: Android gives a device owner no way to
read it back), `wifi_ssid_policy_failed`, `default_app_failed`,
`default_app_ineffective`, `app_config_failed`, `notify_permission_failed`,
`user_control_disabled_failed` (`device.user_control_disabled` and the
agent's own force-stop protection, one event per package not in force),
`suspend_failed` / `unsuspend_failed` (per package), `lock_screen_failed`,
and `device_policy_failed` for anything unexpected while applying `device:`.
A setting that failed is tried again at the next policy change or app
install/removal. MCP `list_children` and `status` also say whether each phone
has the policy version served now (`policy up to date (<version>)` or
`policy behind: has X, served Y`) and its last error.

## `<child>.overrides.yaml`

```yaml
overrides:
  - {extra: 30m, limit: video, until: "2026-10-24T23:00", note: "film"}   # one limit
  - {extra: 15m, until: "2026-10-20T21:00"}                               # every limit
  - {lock: true, until: "2026-10-20T19:00"}                               # homework
  - {lock: true, screen: true, until: "2026-10-20T21:00"}                 # screen locked too
  - {unlock: true, from: "2026-10-31T18:00", until: "2026-10-31T23:30"}   # party
```

`screen: true` is only valid with `lock: true` (see "Screen lock" above).

`from` defaults to "now". Times are local (child's timezone) or RFC 3339.
Expired entries are ignored; delete them when convenient.

## `devices.yaml`

```yaml
devices:
  - {id: alex-phone, child: alex, token_sha256: <64 hex>}
```

`kidctl token` prints a new token and its hash; the raw token goes to the phone
(`scripts/provision.sh`), only the hash goes to git.
