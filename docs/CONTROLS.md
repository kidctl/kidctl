# Controls inventory (Android 17 / API 37.2, device owner)

Source: `android.jar` of `platforms;android-37.2` (`javap` on `UserManager` and
`DevicePolicyManager`), 2026-10-17. Everything below is available to an app that
is **device owner** (provisioned with `dpm set-device-owner` on a device with no
account yet). The account (e.g. a Workspace account) is added afterwards.

Legend for the "kidctl" column: **policy** = exposed in the YAML policy today;
**built-in** = always applied by the agent; *later* = possible, not wired yet.

## 1. Time and app usage (the parental-control core)

| Control | Android API | kidctl |
|---|---|---|
| Suspend an app (greyed icon, system "app paused" dialog, notifications hidden) | `setPackagesSuspended` | **policy**: downtime, daily limits, `blocked`, lock |
| Measure foreground time per app | `UsageStatsManager.queryEvents` (needs `GET_USAGE_STATS` appop, granted at provisioning) | **built-in** |
| Daily quota per group of apps, per weekday | evaluation in the agent | **policy** `limits[].daily` |
| Downtime windows (crossing midnight) | evaluation in the agent | **policy** `downtime` |
| Always-allowed apps (bypass limits and downtime) | evaluation | **policy** `always_allowed` |
| Temporary extra time / lock / unlock with expiry | evaluation | **policy** `<child>.overrides.yaml` |
| Notify the child: quota thresholds (50/80/95 %), downtime starting soon (French or English) | `NotificationManager` (channel "Temps d’écran", normal importance); `POST_NOTIFICATIONS` fixed by `setPermissionGrantState` | **policy** `notify` + `limits[].notify_at` |
| New apps blocked until approved in git | `PACKAGE_ADDED` + `setPackagesSuspended` | **policy** `approval: true` + `approved` |
| Hide an app completely (disappears from launcher) | `setApplicationHidden` | **policy** `device.hidden` |
| Lock the screen (re-locked after each unlock while the rule applies) | `lockNow` | **policy** lock override `screen: true`, downtime `lock_screen: true` |
| Message on lock screen ("Alex's phone, call …") | `setDeviceOwnerLockScreenInfo` | **policy** `device.lock_screen_info` |
| Support message shown on blocked settings | `setShortSupportMessage` | **policy** `device.support_message` |
| "This device belongs to <name>" (lock screen, Settings) | `setOrganizationName` | **policy** `device.organization_name` |

## 2. Tamper resistance

| Control | API / restriction | kidctl |
|---|---|---|
| Agent cannot be uninstalled | `setUninstallBlocked(self)` | **built-in** |
| Agent cannot be force-stopped / data cleared | `setUserControlDisabledPackages(self)` | **built-in** (always kept in the list) |
| Other apps cannot be force-stopped / cleared (e.g. Tailscale: always-on VPN does not restart a stopped VPN app) | `setUserControlDisabledPackages` | **policy** `device.user_control_disabled` (see below) |
| Other apps cannot be uninstalled (e.g. Tailscale) | `setUninstallBlocked` | **policy** `device.uninstall_blocked` |
| No factory reset from Settings | `no_factory_reset` | **policy** `device.restrictions` |
| Reset phone needs the parent's Google account (FRP) | `setFactoryResetProtectionPolicy` | *later* (needs the parent's account id) |
| No safe mode (would bypass the agent) | `no_safe_boot` | **policy** |
| No developer options / adb | `no_debugging_features` | **policy** (set it last: it also blocks our adb) |
| No changing date/time (defeats quotas) | `no_config_date_time`, `setAutoTimePolicy` | **policy** |
| No new users / guest / private space | `no_add_user`, `no_add_private_profile`, `no_user_switch` | **policy** |
| No adding/removing accounts | `no_modify_accounts` | **policy** |
| No installs from unknown sources | `no_install_unknown_sources_globally` | **policy** |
| No uninstalling any app | `no_uninstall_apps` | **policy** |
| No "Force stop / Clear storage / Clear cache" from Settings > App info for any app | `no_control_apps` | **policy**, but NOT the Stop button of Quick Settings > Active apps (see below) |
| No network reset | `no_network_reset` | **policy** |
| No accessibility services except listed | `setPermittedAccessibilityServices` | **policy** `device.permitted_accessibility_services` |
| No keyboards except listed | `setPermittedInputMethods` | **policy** `device.permitted_input_methods` |
| Verify apps (Play Protect) forced on | `ensure_verify_apps` | **policy**, but it blocks the agent's over-the-air updates (Play Protect dialog, see PROVISIONING.md "Updating the agent") |
| No installs from unknown sources still lets the agent update itself | `no_install_unknown_sources_globally` + PackageInstaller as device owner | **built-in** (verified by `e2e/run.sh` with a real phone's restrictions) |

### Force stop: `no_control_apps` vs `device.user_control_disabled`

Measured on the API 37 emulator (Android 17), the same way `e2e/run.sh` checks it:

| Action | `no_control_apps` | `user_control_disabled: [pkg]` |
|---|---|---|
| Settings > App info > **Force stop** | blocked ("Blocked by work policy", the app keeps running) | blocked (same dialog) |
| App info > Storage & cache > **Clear storage** / **Clear cache** | blocked | blocked |
| Quick Settings > **Active apps** > **Stop** (apps running a foreground service, such as a VPN app) | **not blocked**: the Stop button is there and stops the app | no Stop button for that app |
| `adb shell am force-stop` | not blocked | ignored (the app keeps running) |

So `no_control_apps` alone leaves a VPN app such as Tailscale one tap away
from being stopped, and always-on VPN does not bring a stopped VPN app back
(seen on a real phone, without lockdown):
list it in `device.user_control_disabled`. The agent applies the list with
`setUserControlDisabledPackages` (its own package always added: the policy
cannot drop the agent's protection), reads it back, and reports
`user_control_disabled_failed` per package not in force; removed from the
policy, the buttons come back.

## 3. Network (so DNS filtering follows the phone everywhere)

| Control | API / restriction | kidctl |
|---|---|---|
| Always-on VPN with lockdown (no traffic without it) | `setAlwaysOnVpnPackage(pkg, lockdown=true)` | **policy** `device.always_on_vpn` |
| VPN app's own on/off switch locked (Tailscale `ForceEnabled: true`, DNS of the tailnet forced) | `setApplicationRestrictions` (managed configuration) | **policy** `device.app_config` (see POLICY.md "App configurations") |
| No changing VPN settings | `no_config_vpn` | **policy** |
| Force Private DNS host (e.g. AdGuard DoT) | `setGlobalPrivateDnsModeSpecifiedHost` | **policy** `device.private_dns` (removed from the policy: back to Android's default, Automatic) |
| No changing Private DNS | `disallow_config_private_dns` | **policy** |
| No tethering / hotspot | `no_config_tethering`, `no_wifi_tethering` | **policy** |
| Restrict Wi-Fi networks (SSID allow/deny list) | `setWifiSsidPolicy` | **policy** `device.wifi_ssids` |
| Recommended global HTTP proxy | `setRecommendedGlobalProxy` | *later* |
| Mobile data off for chosen apps | `setMeteredDataDisabledPackages` | *later* |

## 4. Content and privacy

| Control | API / restriction | kidctl |
|---|---|---|
| Camera off | `setCameraDisabled` | **policy** `device.camera_disabled` |
| Screenshots off | `setScreenCaptureDisabled` | **policy** `device.screen_capture_disabled` |
| Location forced on (find the phone) | `setLocationEnabled`, `no_config_location` | **policy** `device.location_always_on` + restriction `no_config_location` |
| Runtime permissions auto-grant/deny, per app | `setPermissionPolicy`, `setPermissionGrantState` | *later* |
| Settings an app lets its administrator fix (managed configurations / app restrictions, declared in the app's manifest) | `setApplicationRestrictions`, `RestrictionsManager.getManifestRestrictions` | **policy** `device.app_config` |
| Default apps locked (browser, launcher) | `addPersistentPreferredActivity`, `disallow_config_default_apps` | **policy** `device.default_apps` + restriction `disallow_config_default_apps` (browser: hide the other browsers, see POLICY.md) |
| No sharing via Bluetooth / NFC beam | `no_bluetooth_sharing`, `no_outgoing_beam` | **policy** |
| No USB file transfer | `no_usb_file_transfer` | **policy** |
| No SMS / outgoing calls (not for a phone) | `no_sms`, `no_outgoing_calls` | **policy** (not recommended) |

## 5. System

| Control | API | kidctl |
|---|---|---|
| OS updates installed automatically | `setSystemUpdatePolicy` | **policy** `device.auto_system_updates` |
| Reboot / wipe remotely | `reboot`, `wipeDevice` | not exposed (too dangerous for a gitops loop) |
| Kiosk (single-app) mode | `setLockTaskPackages` | not needed |

## Not possible on Android (any mode)

- Per-site time limits inside a browser (only per app; use AdGuard for domains).
- Limits on another device (iPad/Mac) — Apple Screen Time only.

## Interaction with Google accounts

- Device owner must be set **before** any account is added (`dpm` refuses
  otherwise). Add the child's account after provisioning.
- With a Google Workspace account, do **not** enable Workspace *advanced*
  mobile management for the child's organizational unit: it
  would install Android Device Policy and fight the device owner.
- Family Link supervision is not used (Workspace accounts are not consumer
  accounts); untested with a device owner present.
