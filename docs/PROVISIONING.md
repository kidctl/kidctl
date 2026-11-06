# Setting up a phone

Once per phone. You need the server running and reachable over HTTPS
(README, "Quick start"; `$KIDCTL_URL` below is its public origin, e.g.
`https://kidctl.example.net`), the phone, a USB cable, and on your computer
adb, JDK 21 and an Android SDK with platform 37 (`ANDROID_HOME`, or
`agent/local.properties` with `sdk.dir=...`).

Keep these on your computer, never in git, `chmod 600`, in `~/.config/kidctl/`:

| File | What | Back it up |
|---|---|---|
| the release keystore + `signing.properties` | the agent's signing key (section 1). A device-owner app can only be updated with the SAME key: lose it and the phone must be factory-reset to update the agent. | **yes**, with its password, in your password manager |
| `<device>.token` | the phone's token (its SHA-256 is in `devices.yaml`) | optional (a new one can be issued) |
| the owner password | typed on the kidctl sign-in page when an MCP client connects; only its hash is on the server | yes (or set a new one: new hash, restart) |

## 1. The release signing key

Create it once, before the first phone; every agent you ever install or
publish is signed with it:

```bash
mkdir -p ~/.config/kidctl && chmod 700 ~/.config/kidctl
keytool -genkeypair -keystore ~/.config/kidctl/kidctl-release.jks -storetype PKCS12 \
  -alias kidctl -keyalg RSA -keysize 4096 -validity 36500 -dname CN=kidctl
cat > ~/.config/kidctl/signing.properties <<EOF
storeFile=$HOME/.config/kidctl/kidctl-release.jks
storePassword=<the password you chose>
keyAlias=kidctl
keyPassword=<the same password>
EOF
chmod 600 ~/.config/kidctl/signing.properties ~/.config/kidctl/kidctl-release.jks
```

The Gradle build signs release APKs with it (`agent/app/build.gradle.kts`);
without `signing.properties` it falls back to your machine's debug key,
which is fine for a test but then also has to sign every later update.

Never change the key or the package name (`io.github.kidctl.agent`) of an
installed agent: Android treats another key or package as an unrelated app,
and a device owner cannot be replaced without a factory reset.

**Play Protect.** On a Play-certified phone, Play Protect checks every
install, the device owner's updates included. For an APK of a developer
Google does not know it can show "App blocked to protect your device" and the
update waits until someone taps. Registering the package name with your key's
certificate in the Android developer console (developer verification) avoids
it; see "Updating the agent" for what was measured.

## 2. The phone's entry in the rules

```bash
kidctl token     # or: docker run --rm kidctl token
```

prints a new token and its SHA-256. Save the token in
`~/.config/kidctl/alex-phone.token`, add the phone to `devices.yaml` and push
(the child's `<child>.yaml` and `<child>.overrides.yaml` must exist):

```yaml
devices:
  - {id: alex-phone, child: alex, token_sha256: <the SHA-256>}
```

Start with gentle rules and without `no_debugging_features` (it turns USB
debugging off, see step 7).

## 3. The phone

1. **Factory reset.** In the setup wizard: Wi-Fi yes, **skip the Google
   account**, finish setup. Android only lets an app become device owner on
   a phone with no account. Then Settings > About phone > tap Build number
   seven times > Developer options > USB debugging on. Plug it in and accept
   the computer's key on the phone.
2. Provision:
   `scripts/provision.sh alex-phone $KIDCTL_URL ~/.config/kidctl/alex-phone.token`
   builds the release APK, installs it, sets it as device owner, grants it
   usage access, gives it the server URL and token, and deletes the token
   file from the phone again. With several phones plugged in, add the adb
   serial as a fourth argument.
3. Check: MCP `list_children` (or the server log) shows
   `alex-phone ... agent 0.3.0 (code N) ... device_owner=true, policy up to date (<version>)`
   after its second sync, and MCP `events` no `*_failed` event (docs/POLICY.md,
   "Problems reported by the agent").
4. Add the child's Google account (Settings > Passwords & accounts). With a
   Google Workspace account, keep Workspace's *advanced* mobile management
   off for it: it would install Android Device Policy, which fights the
   device owner.
5. Install the apps the child needs; MCP `apps` lists their package names;
   put them in the rules (`approved`, a limit, `always_allowed`).
6. Network, if you filter DNS through a VPN (Tailscale with a DNS filter,
   for example): install and log in to the VPN app, then in the rules enable
   `always_on_vpn`, `uninstall_blocked` and `user_control_disabled` for it
   (docs/CONTROLS.md, "Force stop"), `app_config` if the app has a managed
   configuration (docs/POLICY.md, "App configurations"), `no_config_vpn`,
   and `private_dns` / `disallow_config_private_dns` as you need. Push.
7. Last: `no_modify_accounts` (once the accounts are there) and
   `no_debugging_features`. After that adb is off for good; the agent
   updates itself over the air (next section).

## Updating the agent

Over the air, no cable, works with adb off:

```bash
scripts/release-agent.sh <host>:<dir>    # or a local directory the server reads
git commit -m "agent: release versionCode N" agent/version.properties
```

`<dir>` is the server's `KIDCTL_AGENT_DIR` (default `/data/agent`, on its
data volume), reached over ssh + sudo. The script builds the release APK
with versionCode = max(`agent/version.properties`, published) + 1 (clean git
tree required), checks it (package, versionCode, signed with the release
key, the same SHA-256 checks as the server), and publishes the APK, then an
`agent.json` (`{version_code, version_name, sha256, file}`), each by rename,
owned by the server's uid. It refuses a versionCode that is not above the
published one; it bumps `agent/version.properties`: commit it.

- Server: re-reads the directory within 10 s, refuses the release if the
  APK's SHA-256 does not match `agent.json` (keeps offering the previous
  one), and adds `agent: {version_code, version_name, sha256, size, url}` to
  every sync response. The APK is served at `GET /api/v1/agent/<version_code>`
  with the device's token (`X-Device-Id` header). Delete `agent.json` to
  withdraw a release.
- Phone: at its next sync (about a minute), if the offered versionCode is
  higher than its own, it downloads the APK into app-private storage, checks
  size, SHA-256, package name and versionCode, and installs it with a
  PackageInstaller session. As device owner no confirmation is needed;
  Android also checks the signature, so only an APK signed with the release
  key installs. Device owner, configuration and state survive; the new
  version restarts by itself.
- Check: MCP `list_children` shows `agent release offered: code N` and the
  phone at `(code N)`, `policy up to date`; MCP `events` shows
  `agent_download`, `agent_update_installing`, `updated version_code A -> N`,
  or `agent_update_failed <why>`.
- A failed release (bad hash, install refused...) is retried after 15 min,
  then 30 min, 1 h ... up to 24 h; publishing a new release retries at once.

**Play Protect, measured.** On the API 37 emulator (Google Play image,
October 2026), an update of an unregistered developer was blocked behind the
dialog with "Scan apps with Play Protect" on, installed silently with it off,
and was blocked again as soon as the rules had `ensure_verify_apps` (which
forces scanning on); "Got it" makes it fail
(`agent_update_failed ... INSTALL_FAILED_VERIFICATION_FAILURE`). On a Pixel 8
(Android 17, Play-certified) with the package and key registered (developer
verification), scanning on and `ensure_verify_apps` applied, every update
installed by itself within a minute, no dialog (logcat: `Install is on
enterprise device`, verdict `ALLOW`). The registration is likely what makes
the difference, but not proven: the same day an unregistered debug build was
also allowed on an emulator without a Google account. If an update ever stops at the dialog:
turn scanning off (Play Store > profile icon > Play Protect > gear > "Scan
apps with Play Protect"; with adb:
`adb shell settings put global package_verifier_user_consent -1`) and take
`ensure_verify_apps` out of the rules.

**Broken agent fallback** (it no longer updates itself): remove
`no_debugging_features` from the rules and push; if the agent still syncs it
lifts the restriction; re-enable USB debugging, `adb install -r` a fixed
release APK, put `no_debugging_features` back. An agent that no longer syncs
at all can only be replaced by a factory reset (remove `no_factory_reset`
first, which also needs a syncing agent; otherwise recovery mode).

## Removing kidctl from a phone

Remove `no_factory_reset` from the rules, push, then factory-reset the phone.
(`adb shell dpm remove-active-admin io.github.kidctl.agent/.AdminReceiver`
only works for test-only builds: a production device owner is removed by a
factory reset.)
