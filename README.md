# kidctl

Parental control for Android phones where the rules are a text file you own.

You write your child's rules (screen time per app or group of apps, bedtime,
blocked apps, apps that need your approval, phone settings) in a short YAML
file kept in a git repository. A small server you host compiles them and
serves them to the phone; an app on the phone, installed as its **device
owner**, enforces them, offline too. Change the file from anywhere (or ask
Claude to change it for you) and the phone follows within a few minutes.
Nothing goes through a third-party cloud.

```
you / Claude ──► git push ──► your server ◄── sync (every minute) ── child's phone
                                  │                                (kidctl agent,
                                  └── usage, apps, events ──► you    device owner)
```

## What it does

- **Screen time**: daily budgets per app or per group of apps ("YouTube 30 min
  on school days, 1 h at the weekend; everything else together 1 h"),
  different per weekday.
- **Downtime**: hours when only the apps you chose work (phone, messages,
  maps...), optionally with the screen itself locked.
- **Blocked apps, and approval**: block apps outright; with approval on, a
  newly installed app stays blocked until you approve it.
- **Temporary exceptions**: "30 minutes more tonight", "lock everything until
  homework is done", "no bedtime on New Year's Eve", each with an end time.
- **Notifications to the child** before a budget runs out and before downtime
  (English or French).
- **Tamper resistance**: no factory reset, no safe mode, no new users, no
  changing the clock, the agent cannot be uninstalled or stopped; listed apps
  (your VPN, say) cannot be uninstalled or force-stopped either.
- **Network**: always-on VPN, private DNS, allowed Wi-Fi networks, so a DNS
  filter follows the phone everywhere.
- **Phone settings**: hidden apps, camera, screenshots, locked default
  browser and home screen, a message on the lock screen, the managed
  configuration of apps that support one (Tailscale, for example).
- **What happened**: usage per app, installed apps, and every problem the
  phone met applying a rule, through the server's MCP (ask Claude "how long
  was Alex on YouTube today?").
- **Updates itself** over the air from your server, signed with your key,
  so USB debugging can stay off.

The full list of rules is in [docs/POLICY.md](docs/POLICY.md); every Android
control and whether kidctl uses it, in [docs/CONTROLS.md](docs/CONTROLS.md).

## What it looks like

`alex.yaml`:

```yaml
child: alex
timezone: Europe/Brussels
downtime:
  - {start: "21:30", end: "07:00"}
always_allowed: [com.google.android.dialer, com.google.android.apps.messaging]
blocked: [com.zhiliaoapp.musically]          # TikTok
approval: true
approved: [com.android.chrome, com.google.android.youtube]
limits:
  - name: video
    apps: [com.google.android.youtube]
    daily: {weekdays: 30m, weekend: 1h}
  - name: general
    apps: ["*"]
    exclude: [com.google.android.youtube]
    daily: {weekdays: 1h, weekend: 2h}
notify: {locale: en}
device:
  restrictions: [no_factory_reset, no_safe_boot, no_config_date_time]
```

`alex.overrides.yaml`, for exceptions:

```yaml
overrides:
  - {extra: 30m, limit: general, until: "2026-12-24T23:00", note: "Christmas Eve"}
```

Or, to Claude: *"give Alex 30 more minutes tonight"*. The server makes the
same edit, checks it, and commits it to your repository with a note saying
who asked.

## What you need

- An **Android phone, Android 13 or newer**, that you can **factory-reset**:
  an app can only become device owner on a phone with no account on it yet.
  Tested on a Pixel 8 with Android 17 and on the Android 17 emulator.
- A machine for the **server** that the phone can reach over **HTTPS**
  (a home server behind a reverse proxy or a tunnel, a small VPS, a
  Kubernetes cluster). It is a single Rust binary with SQLite; the Kubernetes
  example gives it 128 MiB of memory.
- A **git repository** for the rules. Plain files work too; git gives you
  history, review and undo, and the Claude write tools need it.
- A computer with **adb** (Android platform tools) to set the phone up once,
  and a JDK 21 + Android SDK to build the agent (or Android Studio).
- Optional: **Claude** (claude.ai, Claude Code) or another MCP client, to ask
  questions and change rules by talking.

Not supported: iPhones and iPads (Apple keeps Screen Time data on the device
and offers no equivalent of a device owner), and per-website limits inside a
browser (use a DNS filter for that).

## Quick start

### 1. Run the server

```bash
git clone https://github.com/kidctl/kidctl && cd kidctl
docker build -t kidctl .
mkdir -p config data && sudo chown 65532:65532 data   # the server runs as uid 65532
docker run --rm kidctl token        # prints a device token and its SHA-256
```

Put the rules in `config/` ([deploy/k8s/policies](deploy/k8s/policies) has
a commented example to start from): `devices.yaml` (each phone, its child,
the token's SHA-256), `<child>.yaml`, `<child>.overrides.yaml`. Check them:

```bash
docker run --rm -v "$PWD/config:/etc/kidctl:ro" kidctl validate /etc/kidctl
docker run -d --name kidctl -p 8080:8080 \
  -v "$PWD/config:/etc/kidctl:ro" -v "$PWD/data:/data" kidctl
curl localhost:8080/healthz          # ok
```

Then publish it over HTTPS at a hostname of yours (`https://kidctl.example.net`
below) with your reverse proxy or tunnel. The server re-reads `config/` every
10 s and keeps the previous rules if the new ones are invalid.

On Kubernetes, [deploy/k8s](deploy/k8s) is a kustomization to copy into the
repository your GitOps reconciler (ArgoCD, Flux) syncs: the rules become a
ConfigMap, and a `git push` is the whole deployment of a rule change.
`./deploy.sh` builds and pushes the image and bumps its tag there
([deploy.env.example](deploy.env.example)). Every server setting (OAuth,
write tools, abuse protection) is in [docs/SERVER.md](docs/SERVER.md).

### 2. Set up the phone

Once per phone, about 15 minutes; details and pitfalls in
[docs/PROVISIONING.md](docs/PROVISIONING.md):

1. Create your **release signing key** and keep it safe: the agent can only
   ever be updated with the key it was installed with
   ([docs/PROVISIONING.md](docs/PROVISIONING.md#1-the-release-signing-key)).
2. **Factory-reset** the phone, go through setup **without** adding a Google
   account, enable USB debugging, plug it in.
3. `scripts/provision.sh alex-phone https://kidctl.example.net <token file>`:
   builds the agent, installs it, makes it device owner and points it at your
   server.
4. Add the child's Google account, install their apps, approve them in the
   rules.

### 3. Talk to Claude (optional)

Set an owner password and the public URL on the server (OAuth,
[docs/SERVER.md](docs/SERVER.md#mcp-and-oauth)), then add
`https://kidctl.example.net/mcp` as a custom connector in claude.ai (or
`claude mcp add --transport http kidctl https://kidctl.example.net/mcp` in
Claude Code) and sign in with the password.

Claude can then read status, usage, installed apps, the rules and the
phone's events, and, when the server has write access to your rules
repository, change any rule: add or remove an exception, approve or block an
app, set a limit or the downtime, change a device setting. Each change is
validated like a manual edit, keeps your file's comments, and is a git commit
in your repository (`Requested-By:` names the client), so you can see and
revert it there. Any MCP client works the same way.

## Privacy

- Everything stays on machines you control: the rules in your repository,
  usage and events in the server's SQLite file. No account with anyone, no
  analytics, no telemetry. The phone talks to your server only (and to the
  Android and Google services it uses anyway).
- What the phone reports: foreground time per app per day, the list of
  launchable apps, and events (applied settings, problems, updates). No
  location, messages, browsing history, contacts or screenshots.
- The child can see that the phone is managed (Android says so in Settings
  and on the lock screen), and gets notifications before a limit or downtime
  starts. kidctl is meant to be used with the child knowing about it.
- Tokens and the owner password are stored as hashes only; see
  [SECURITY.md](SECURITY.md) and [docs/SERVER.md](docs/SERVER.md#security).
- If you connect Claude, what Claude reads (usage, apps, rules) goes to the
  MCP client you chose, under its own privacy terms.

## How it works

- **Rules** (`src/policy.rs`): YAML, validated and compiled to the JSON the
  phone receives; the server hot-reloads the directory and keeps the last
  valid version.
- **Server** (Rust, this repository): serves the compiled rules to each phone
  (`POST /api/v1/sync`, per-device bearer token), stores reported usage in
  SQLite, offers agent updates, and exposes an **MCP** endpoint (OAuth 2.1)
  with read tools and GitOps write tools.
- **Agent** (Kotlin, `agent/`): a headless device-owner app without
  dependencies. It measures foreground time per app, evaluates the rules
  locally every ~30 s (offline too), suspends and releases apps, notifies the
  child, applies device settings and reads each one back, and installs its
  own updates from the server (SHA-256 checked, signed with your key).
- The same evaluation rules exist twice, in `src/eval.rs` and
  `agent/.../Evaluator.kt`, and both run the shared vectors in `spec/`.

| Path | What |
|---|---|
| `src/policy.rs` | YAML model, validation, compilation to the JSON phones receive |
| `src/eval.rs` | Evaluation rules (mirrored by `agent/.../Evaluator.kt`) |
| `spec/vectors*.{json,yaml}` | Shared test vectors run by **both** evaluators |
| `src/config.rs` | Config directory loading + hot reload (keeps last valid) |
| `src/api.rs`, `src/db.rs` | Device sync API (+ agent APK download), SQLite state |
| `src/release.rs` | Agent release offered for self-update (`KIDCTL_AGENT_DIR`, verified, hot reload) |
| `src/mcp.rs` | MCP read tools: `list_children`, `status`, `usage`, `apps`, `policy`, `events`, `validate` |
| `src/mcp_write.rs` | MCP write tools (OAuth only): `policy_source`, `add_override`, `remove_override`, `prune_overrides`, `approve_app`, `block_app`, `unblock_app`, `set_limit`, `set_downtime`, `set_device`, `write_policy`, `validate_policy` |
| `src/gitops.rs` | The write path: private clone, fetch + reset, validate, commit, push |
| `src/yamledit.rs` | Comment- and layout-preserving YAML edits, verified against the typed model |
| `src/serve.rs`, `src/guard.rs` | HTTP app (sync API, MCP), abuse protection |
| `agent/` | Android app (Gradle, compileSdk 37, minSdk 33, no dependencies) |
| `e2e/` | End-to-end tests (emulator, local server), see "Testing" |
| `scripts/provision.sh` | Turn a freshly reset phone into a managed one |
| `scripts/release-agent.sh` | Build + publish an agent release (phones update themselves) |
| `deploy/k8s/`, `deploy.sh` | Kubernetes example, image build + GitOps tag bump |
| `docs/` | `POLICY.md` (rules), `CONTROLS.md` (Android controls), `PROVISIONING.md` (phone), `SERVER.md` (server reference) |

## Development

```bash
ci/run.sh                                    # everything GitHub Actions runs
cargo test                                   # unit tests + shared vectors
(cd agent && ./gradlew testDebugUnitTest)    # Kotlin evaluator on the same vectors
cargo run -- validate <config-dir>           # validate rules
cargo run -- compile <child>.yaml [<child>.overrides.yaml]
cargo run -- token                           # new device token + its SHA-256
cargo run -- hash-password                   # owner password (stdin) -> KIDCTL_OWNER_PASSWORD_HASH
cargo run -- check-agent <agent-dir>         # verify an agent release dir as the server does
scripts/release-agent.sh <host>:<dir>        # agent release over the air (docs/PROVISIONING.md)
```

OAuth and the abuse guard come from the
[mcp-oauth](https://github.com/mcp-oauth-rs/mcp-oauth) crate, a git
dependency pinned to a revision in `Cargo.toml`.

### Testing

- `cargo test` and the Kotlin unit tests run the same evaluation vectors.
- `e2e/mcp-local.sh` (no emulator): a local server with OAuth, login like an
  MCP client, read and write tools against a local bare repository, the
  abuse guard (ban, shared-IP mode), nothing secret in the log.
- `e2e/run.sh emulator-5554`: the whole loop on an Android emulator (API 37,
  Google Play image, booted, no account): provisioning, every kind of rule
  checked on the phone, notifications, lock screen, Wi-Fi, default apps, the
  MCP write matrix (each rule changed through the MCP, pushed to a local
  repository, mirrored into the server, checked on the phone, reverted), and
  the agent's over-the-air update with USB debugging off. It refuses any
  device that is not an emulator (it sets a device owner and a PIN and
  switches adb off). It needs a release signing key
  (`~/.config/kidctl/signing.properties`), `jq` and `python3`.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Status

Early, and used daily: one family's phone (Pixel 8, Android 17) has run it
since October 2026, with over-the-air updates, Tailscale as always-on VPN
with a DNS filter, and rules changed by talking to Claude. Expect rough
edges; issues and pull requests are welcome.

## License

MIT, see [LICENSE](LICENSE).
