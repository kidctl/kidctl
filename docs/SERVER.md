# Server reference

The server is one binary, `kidctl serve` (the container image's default
command). Its flags all have an environment variable (`kidctl serve --help`):

| Env | Default | What |
|---|---|---|
| `KIDCTL_CONFIG` | `/etc/kidctl` | the rules directory (`devices.yaml`, `<child>.yaml`, `<child>.overrides.yaml`), re-read every 10 s; an invalid version is ignored (the previous one is kept, the error logged) |
| `KIDCTL_DB` | `/data/kidctl.db` | SQLite state: devices, usage, apps, events |
| `KIDCTL_LISTEN` | `0.0.0.0:8080` | HTTP listen address (put HTTPS in front: phones only talk HTTPS) |
| `KIDCTL_AGENT_DIR` | `/data/agent` | agent release offered for self-update (PROVISIONING.md, "Updating the agent"); missing: none |
| `KIDCTL_ALLOWED_HOSTS` | any | comma list of `Host` headers accepted by the MCP endpoints |

`GET /healthz` answers `ok`. The image runs as uid 65532 and needs `/data`
writable by it; everything else can be read-only.

## MCP and OAuth

`kidctl serve` serves the MCP (streamable HTTP, stateless, JSON responses)
two independent ways (write tools: OAuth only, see "MCP write tools"
below):

- **OAuth 2.1 at `/mcp`** (bearer token), for claude.ai custom connectors,
  Claude Code and ChatGPT. Enabled by `KIDCTL_OWNER_PASSWORD_HASH`. kidctl is
  its own authorization server (the mcp-oauth crate): discovery at
  `/.well-known/oauth-protected-resource` (also `/.well-known/oauth-protected-resource/mcp`;
  resource `https://<host>/mcp`) and `/.well-known/oauth-authorization-server`;
  an MCP request without a valid token gets `401` with
  `WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource"`.
  `/oauth/register` (dynamic client registration), `/oauth/authorize` (PKCE
  S256 required; a page asks for the owner password, then Allow / Deny),
  `/oauth/token` (access tokens 1 h, refresh tokens 30 days, rotated),
  `/oauth/revoke`. Client ID Metadata Documents (Claude, Claude Code, ChatGPT)
  are accepted too. Details: the crate's README
  (https://github.com/mcp-oauth-rs/mcp-oauth).
- **Legacy URL token at `/mcp/t/<token>`** (`KIDCTL_MCP_TOKEN_SHA256`, the
  token's SHA-256; wrong token -> 404), kept for clients configured before
  OAuth. Unset the variable to turn it off.

Neither set: no MCP (the sync API runs anyway). `KIDCTL_ALLOWED_HOSTS` (comma
list) restricts the `Host` header of MCP requests.

| Env | What |
|---|---|
| `KIDCTL_OWNER_PASSWORD_HASH` | argon2id PHC string of the owner password (`kidctl hash-password`); enables OAuth. Environment only (no flag). |
| `KIDCTL_PUBLIC_URL` | public origin = OAuth issuer, e.g. `https://kidctl.example.net` (https; http only for localhost/127.0.0.1). Required with OAuth. |
| `KIDCTL_STATE_DIR` | OAuth state: `oauth-clients.json` (registered clients, secrets as SHA-256) and `oauth-tokens.json` (SHA-256 of the tokens), atomic writes, mode 600, dir created 700. Must persist (e.g. `/data/oauth` on the data volume). Required with OAuth. |
| `KIDCTL_REDIRECT_PATTERNS` | comma list replacing the allowed redirect URIs (default: Claude, Claude Code loopback, ChatGPT; see mcp-oauth) |
| `KIDCTL_CIMD_ALLOWLIST` | comma list of `client_id` URLs accepted as Client ID Metadata Documents; when set, only those, and dynamic registration is off. Unset: both open. |
| `KIDCTL_MCP_TOKEN_SHA256` | legacy `/mcp/t/<token>` (hex SHA-256 of the URL token) |

Setting it up: "Setting up OAuth and the write tools" below.

## MCP write tools (GitOps)

With `KIDCTL_GITOPS_REMOTE` set, the OAuth endpoint also offers write tools
that change a child's rules the GitOps way (reference: [POLICY.md](POLICY.md),
"Changing rules by talking to Claude"). For each write the server, one write
at a time:

1. fetches the branch into its private clone and hard-resets to it;
2. edits only `<child>.yaml` or `<child>.overrides.yaml` in the policies
   directory (child names are `[a-z0-9-]`, `devices` is reserved: no path
   traversal, `devices.yaml` is never read or written, no file is created);
3. validates the whole directory exactly like `kidctl validate`; invalid ->
   refused with the messages, nothing committed;
4. commits as `KIDCTL_GITOPS_AUTHOR` with the message
   `kidctl-mcp: <tool> <child>: <summary>` and a `Requested-By: <client name>
   (OAuth client <id>)` trailer, and pushes without force. If someone pushed
   meanwhile (non-fast-forward), it fetches again, re-applies the change to
   the new text and retries once, then gives up cleanly;
5. answers with the commit, the diff, and the policy version the change will
   produce (the MCP `policy` tool shows it once your GitOps reconciler has
   synced and the server reloaded; the phones apply it at their next
   1-minute sync: about 2-3 minutes end to end with ArgoCD polling git every
   minute).

A write runs in its own task: if the MCP client disconnects or the request
times out (30 s), the write still runs to its end (pushed or refused) instead
of being cut between commit and push; `policy_source` shows the outcome.

`dry_run: true` returns the diff and validation result without committing.
`write_policy` (whole file) refuses unless `base_revision` is the file's
current git blob id (`policy_source`): a concurrent edit is never
overwritten.

**Comments are kept.** The owner's files are full of comments (above keys,
after list items, inside multi-line flow lists, commented-out entries).
Re-emitting a parsed model would lose them, and no Rust YAML library both
round-trips comments and edits, so the structured tools edit the text
itself: `src/yamledit.rs` locates nodes with the `yamlpath` crate (a lossless
tree-sitter CST with byte spans, from the zizmor project) and makes minimal
byte-range edits in the style of the surrounding list (flow `[a, b]` item
before `]`, wrapped like its line if long; block `- item` line after the
last item; new key after the mapping's last pair; list updates only add and
remove the items that change). Every edit is applied twice, to the text and
to the parsed value, and the new text is accepted only if it parses with the
typed, `deny_unknown_fields` policy model to exactly the intended value;
otherwise the tool refuses and nothing is committed (`write_policy` remains).
The unit tests check every tool against a heavily commented file (every
comment kept, only the intended lines changed).

The write tools are not offered on the legacy URL token: changing rules
requires the owner password (OAuth). The image carries `git` and
`openssh-client` (Debian packages, pinned in the Dockerfile).

| Env | What |
|---|---|
| `KIDCTL_GITOPS_REMOTE` | infra repo: `git@github.com:owner/repo.git` (ssh, deploy key) or a local path / `file://` (tests). Unset: read-only MCP |
| `KIDCTL_GITOPS_BRANCH` | branch to commit to (default `main`) |
| `KIDCTL_GITOPS_PATH` | policies directory inside the repo, e.g. `kidctl/policies` (required) |
| `KIDCTL_GITOPS_SSH_KEY` | private deploy key file (write access to that repo only); required for ssh |
| `KIDCTL_GITOPS_KNOWN_HOSTS` | known_hosts pinning the git host's keys (`StrictHostKeyChecking=yes`, no trust on first use); required for ssh |
| `KIDCTL_GITOPS_AUTHOR` | commit author and committer, `Name <email>` (default `kidctl MCP <kidctl-mcp@localhost>`) |
| `KIDCTL_GITOPS_DIR` | the private clone (default `/data/gitops`, on the data volume) |

git runs with a clean environment: no system or global config, no hooks, no
prompts, only the ssh and file transports, `ssh -F /dev/null` with only the
deploy key and the pinned known_hosts, 20 s per git command. Startup fails on
an invalid configuration (e.g. an https remote, a missing key file); the
first clone happens at startup and is retried by each write.

## Security

- Phones authenticate with per-device bearer tokens (sync and the agent APK
  download `GET /api/v1/agent/<code>`). MCP clients with OAuth access tokens
  (opaque, 1 h) obtained after the owner typed the password, or with the
  legacy URL token. The server only stores SHA-256 hashes of every token and
  an argon2id hash of the password; wrong token -> 401/404.
- Agent updates: the phone installs only a higher versionCode whose SHA-256
  matches the offer; Android only accepts an APK signed with the release key.
- Rule changes through the MCP: OAuth only (owner password), validated before
  commit, attributed (`Requested-By:`), visible in the infra repo's history
  and revertable there. The server holds a deploy key with write access to
  the infra repo: GitHub deploy keys cannot be limited to a directory, so the
  key could push anything to that repo, which your reconciler applies. The server
  itself only ever writes `<child>.yaml` / `<child>.overrides.yaml`; the key
  lives only in a Kubernetes Secret mounted read-only into the kidctl pod.
  Keeping the policies in a dedicated repo (its own GitOps source) would
  shrink that to the policies alone.
- Abuse protection (`src/guard.rs` = the mcp-oauth guard configured for
  kidctl, applied once around the whole app in `serve::app`): per-IP rate
  limit (120/min, burst 40; client IP from `CF-Connecting-IP`) on every path
  but `/healthz`, OAuth endpoints included; 1 h ban after 10 auth failures in
  10 min (unknown OAuth bearer token, wrong owner password, wrong client
  secret or client assertion, wrong PKCE verifier, bad legacy MCP token, bad
  device token, unknown/scanner paths; harmless probes never count: `GET`/`HEAD`
  on `/`, `/favicon.ico`, `/robots.txt`, and anything under `/.well-known/`,
  which MCP clients probe for discovery), 1 MiB bodies, 30 s per request, 64
  concurrent requests. Volumetric DDoS is for the proxy or tunnel in front
  (e.g. Cloudflare); the rate limits are in the app so that they hold
  whatever is in front.
- A household shares one public IP, so a ban never blocks an authenticated
  client (the crate's shared-IP mode, `serve_authenticated_when_banned`): a
  banned IP gets 429 except for requests with valid credentials, which are
  served normally (still rate-limited): device token (sync, agent download),
  legacy MCP token, OAuth bearer token on `/mcp`, a valid token refresh, and
  the OAuth metadata documents. The owner password is never checked for a
  banned IP (no password oracle), so a *new* client cannot sign in from it
  until the ban ends. Failures while banned do not extend the ban.

## Setting up OAuth and the write tools

On Kubernetes ([deploy/k8s](../deploy/k8s) has the matching manifests); with
Docker, pass the same variables with `-e` and mount the files.

**Owner password** (at least 12 characters; from stdin, out of the shell
history), stored as a Secret, never in git:

```bash
read -rs P && printf '%s' "$P" | kidctl hash-password > /tmp/kidctl.hash; unset P
kubectl -n kidctl create secret generic kidctl-oauth --from-file=KIDCTL_OWNER_PASSWORD_HASH=/tmp/kidctl.hash
rm /tmp/kidctl.hash
```

(the trailing newline of the file is trimmed by the server). Set
`KIDCTL_PUBLIC_URL` and `KIDCTL_STATE_DIR`, deploy, then check:
`curl -si -X POST https://kidctl.example.net/mcp | grep -i www-authenticate`
shows `resource_metadata=".../.well-known/oauth-protected-resource"`.
Connect: claude.ai > Settings > Connectors > Add custom connector, URL
`https://kidctl.example.net/mcp`; Claude Code:
`claude mcp add --transport http kidctl https://kidctl.example.net/mcp`, then
`/mcp` > kidctl > Authenticate. Sign in with the password, Allow.

To change the password: a new hash in the Secret, restart. To sign every
client out: delete `oauth-tokens.json` in the state directory and restart.

**Write tools**: the server pushes to the repository that holds the rules
with its own deploy key.

1. A deploy key with write access (the private key never goes to git):
   ```bash
   ssh-keygen -t ed25519 -N '' -C kidctl-mcp-gitops -f /tmp/kidctl-gitops
   gh repo deploy-key add /tmp/kidctl-gitops.pub --repo <owner>/<repo> --title "kidctl MCP" --allow-write
   ```
   A deploy key is limited to that repository, not to a directory (see
   "Security"). If the branch requires pull requests, the pushes are refused:
   allow the key to push, or use a dedicated policies repository.
2. Pinned host keys (no trust on first use): fetch GitHub's keys and check
   them against the fingerprints GitHub publishes
   (https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints):
   ```bash
   ssh-keyscan -t ed25519,ecdsa,rsa github.com > /tmp/kidctl-known_hosts
   ssh-keygen -lf /tmp/kidctl-known_hosts
   ```
3. The Secret, then delete the local copies:
   ```bash
   kubectl -n kidctl create secret generic kidctl-gitops \
     --from-file=id_ed25519=/tmp/kidctl-gitops --from-file=known_hosts=/tmp/kidctl-known_hosts
   rm /tmp/kidctl-gitops /tmp/kidctl-gitops.pub /tmp/kidctl-known_hosts
   ```
4. Set the `KIDCTL_GITOPS_*` variables (deploy/k8s/server.yaml) and deploy.
   The pod needs `fsGroup: 65532` (the Secret's files are group-readable)
   and nothing else: `readOnlyRootFilesystem` stays (git's HOME and TMPDIR
   are under the clone directory), 128 MiB of memory is plenty.
5. Every child needs an overrides file in the ConfigMap (the MCP never
   creates files): `<child>.overrides.yaml` with `overrides: []`.
6. Check: the server log shows
   `gitops: <remote> branch main at <sha>, policies in <path>`. Ask Claude
   for a dry run ("block com.example.test for alex, dry run"): the answer
   shows the diff and `dry run, valid, nothing committed`.
