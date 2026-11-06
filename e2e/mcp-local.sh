#!/usr/bin/env bash
# The MCP part of e2e/run.sh without an emulator: start a local server with
# OAuth and the legacy URL token, log in over OAuth like an MCP client
# (e2e/oauth-login.sh), call MCP tools with the bearer token, check the legacy
# path, the 401 challenge, the ban on invalid bearer tokens and scanner paths,
# and that a banned IP still gets the answers to valid credentials.
# Usage: e2e/mcp-local.sh   (needs curl, python3, xxd)
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${PORT:-18081}
BASE=http://127.0.0.1:$PORT
OUT=e2e/out-mcp; rm -rf "$OUT"; mkdir -p "$OUT/config"

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; exit 1; }

cp spec/vectors-policy.yaml "$OUT/config/alex.yaml"
echo "devices: []" > "$OUT/config/devices.yaml"
MCPTOK=$(head -c 32 /dev/urandom | xxd -p -c 64)
MCPSHA=$(printf %s "$MCPTOK" | sha256sum | cut -d' ' -f1)
OWNER_PW=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')

cargo build -q --release
# GitOps "infra repo" for the write tools: a local bare repo with the same files.
ogit() { GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=owner GIT_AUTHOR_EMAIL=owner@kidctl.invalid \
  GIT_COMMITTER_NAME=owner GIT_COMMITTER_EMAIL=owner@kidctl.invalid git "$@"; }
INFRA="$PWD/$OUT/infra.git"; GPATH=overlays/local/kidctl/policies
printf 'overrides: []\n' > "$OUT/config/alex.overrides.yaml"
ogit init -q --bare -b main "$INFRA"
ogit clone -q "$INFRA" "$OUT/owner" 2>/dev/null
mkdir -p "$OUT/owner/$GPATH" && cp "$OUT/config/"*.yaml "$OUT/owner/$GPATH/"
ogit -C "$OUT/owner" add -A && ogit -C "$OUT/owner" commit -qm initial && ogit -C "$OUT/owner" push -q origin HEAD:main
OWNER_HASH=$(printf %s "$OWNER_PW" | ./target/release/kidctl hash-password)
KIDCTL_OWNER_PASSWORD_HASH=$OWNER_HASH KIDCTL_PUBLIC_URL=$BASE KIDCTL_STATE_DIR="$OUT/oauth" \
KIDCTL_MCP_TOKEN_SHA256=$MCPSHA KIDCTL_GITOPS_REMOTE="$INFRA" KIDCTL_GITOPS_PATH=$GPATH \
KIDCTL_GITOPS_DIR="$PWD/$OUT/gitops" KIDCTL_GITOPS_AUTHOR="kidctl local <local@kidctl.invalid>" \
  ./target/release/kidctl serve --config "$OUT/config" --db "$OUT/kidctl.db" \
  --listen 127.0.0.1:$PORT >"$OUT/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do curl -sf "$BASE/healthz" >/dev/null && break; sleep 0.5; done
curl -sf "$BASE/healthz" >/dev/null && pass "server up" || { cat "$OUT/server.log"; fail "server did not start"; }

rpc() { # rpc <url> <bearer|""> <json-rpc body> -> raw response
  local auth=(); [ -n "$2" ] && auth=(-H "authorization: Bearer $2")
  curl -sf -X POST "$1" "${auth[@]}" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$3"
}
text() { python3 -c 'import sys,json; r=json.load(sys.stdin); print("".join(c.get("text","") for c in r["result"]["content"]))'; }

ACCESS=$(KIDCTL_OWNER_PASSWORD=$OWNER_PW VERBOSE=1 e2e/oauth-login.sh "$BASE") && pass "OAuth login: discovery, register, authorize, token" || fail "OAuth login"
tools=$(rpc "$BASE/mcp" "$ACCESS" '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | python3 -c 'import sys,json; print(" ".join(t["name"] for t in json.load(sys.stdin)["result"]["tools"]))')
echo "tools/list over OAuth: $tools"
for t in list_children status usage apps policy events validate; do
  [[ " $tools " == *" $t "* ]] || fail "tool $t missing"
done
pass "MCP tools/list with the OAuth bearer token"
out=$(rpc "$BASE/mcp" "$ACCESS" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"status","arguments":{"child":"alex"}}}' | text)
echo "$out"
echo "$out" | grep -q "limit social" && pass "MCP tools/call status over OAuth" || fail "status over OAuth"
out=$(rpc "$BASE/mcp/t/$MCPTOK" "" '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_children","arguments":{}}}' | text)
grep -q '^alex' <<<"$out" && pass "legacy /mcp/t/<token> still served" || fail "legacy URL token"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" -H 'content-type: application/json' -d '{}')
[ "$code" = 401 ] && pass "unauthenticated /mcp -> 401" || fail "unauthenticated /mcp: HTTP $code"

# MCP write tools (GitOps): over OAuth only; a write is a commit pushed to the repo.
grep -qE '^gitops: .* branch main at [0-9a-f]+, policies in overlays/local' "$OUT/server.log" && pass "gitops clone ready at startup" \
  || { grep gitops "$OUT/server.log"; fail "gitops warm-up"; }
for t in policy_source add_override remove_override prune_overrides approve_app block_app unblock_app set_limit set_downtime set_device write_policy validate_policy; do
  [[ " $tools " == *" $t "* ]] || fail "write tool $t missing over OAuth"
done
legacy_tools=$(rpc "$BASE/mcp/t/$MCPTOK" "" '{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}' \
  | python3 -c 'import sys,json; print(" ".join(t["name"] for t in json.load(sys.stdin)["result"]["tools"]))')
[[ " $legacy_tools " != *" add_override "* ]] && pass "write tools over OAuth only (legacy URL token: read-only)" || fail "legacy: $legacy_tools"
call() { rpc "$BASE/mcp" "$ACCESS" "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" | text; }
before=$(ogit --git-dir="$INFRA" rev-list --count main)
out=$(call block_app '{"child":"alex","package":"com.example.game","dry_run":true}')
grep -q '^dry run, valid, nothing committed' <<<"$out" && [ "$(ogit --git-dir="$INFRA" rev-list --count main)" = "$before" ] \
  && pass "dry run: diff shown, nothing committed" || fail "dry run: $out"
out=$(call add_override '{"child":"alex","kind":"lock","screen":true,"until":"+1h","note":"devoirs"}')
echo "$out" | head -2
grep -q '^committed ' <<<"$out" || fail "add_override: $out"
msg=$(ogit --git-dir="$INFRA" log -1 --format='%an <%ae>%n%B' main)
grep -q '^kidctl local <local@kidctl.invalid>$' <<<"$msg" && grep -q '^kidctl-mcp: add_override alex: add override {lock: true, screen: true, until: ' <<<"$msg" \
  && grep -q '^Requested-By: kidctl e2e (OAuth client ' <<<"$msg" && pass "add_override committed and pushed (author, message, Requested-By)" || fail "commit: $msg"
ogit --git-dir="$INFRA" show "main:$GPATH/alex.overrides.yaml" | grep -q 'note: devoirs}' && pass "override in the repo's alex.overrides.yaml" || fail "repo file"
out=$(call remove_override '{"child":"alex","match":"devoirs"}')
grep -q '^committed ' <<<"$out" && [ "$(ogit --git-dir="$INFRA" show "main:$GPATH/alex.overrides.yaml")" = "overrides: []" ] \
  && pass "remove_override: file back to overrides: []" || fail "remove_override: $out"

# Invalid bearer tokens: 401 invalid_token, counted; the 10th bans the IP.
# Shared-IP mode (the home NAT): the banned IP still gets the answers to valid
# credentials (OAuth bearer, legacy URL token) and 429 for anything else.
BANNED=203.0.113.9
www=$(curl -s -o /dev/null -D - -X POST "$BASE/mcp" -H "cf-connecting-ip: $BANNED" -H 'authorization: Bearer forged' \
  -H 'content-type: application/json' -d '{}' | tr -d '\r' | grep -i '^www-authenticate:')
echo "$www"
echo "$www" | grep -q 'error="invalid_token"' && pass "forged bearer -> 401 invalid_token" || fail "forged bearer challenge"
for _ in $(seq 2 10); do curl -s -o /dev/null -X POST "$BASE/mcp" -H "cf-connecting-ip: $BANNED" -H 'authorization: Bearer forged' -d '{}'; done
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" -H "cf-connecting-ip: $BANNED" -H 'authorization: Bearer forged' \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":4,"method":"tools/list"}')
[ "$code" = 429 ] && pass "IP banned after 10 forged bearer tokens (forged token -> 429)" || fail "ban: HTTP $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/wp-login.php" -H "cf-connecting-ip: $BANNED")
[ "$code" = 429 ] && pass "banned IP: unknown path -> 429" || fail "banned IP, unknown path: HTTP $code"
out=$(curl -sf -X POST "$BASE/mcp" -H "cf-connecting-ip: $BANNED" -H "authorization: Bearer $ACCESS" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_children","arguments":{}}}' | text)
grep -q '^alex' <<<"$out" && pass "banned IP: valid OAuth bearer still served (shared-IP mode)" || fail "banned IP, valid bearer"
out=$(curl -sf -X POST "$BASE/mcp/t/$MCPTOK" -H "cf-connecting-ip: $BANNED" -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"list_children","arguments":{}}}' | text)
grep -q '^alex' <<<"$out" && pass "banned IP: legacy URL token still served" || fail "banned IP, legacy token"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp/t/guess" -H "cf-connecting-ip: $BANNED" -d '{}')
[ "$code" = 429 ] && pass "banned IP: wrong legacy token -> 429" || fail "banned IP, wrong legacy token: HTTP $code"
# Scanner paths count (harmless probes never do).
SCAN=203.0.113.10
for _ in $(seq 1 12); do curl -s -o /dev/null "$BASE/.well-known/openid-configuration" -H "cf-connecting-ip: $SCAN"; curl -s -o /dev/null "$BASE/favicon.ico" -H "cf-connecting-ip: $SCAN"; done
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/.env" -H "cf-connecting-ip: $SCAN")
[ "$code" = 404 ] && pass "24 harmless probes did not ban" || fail "harmless probes: HTTP $code"
for _ in $(seq 2 10); do curl -s -o /dev/null "$BASE/.env" -H "cf-connecting-ip: $SCAN"; done
body=$(curl -s "$BASE/.env" -H "cf-connecting-ip: $SCAN")
[ "$body" = banned ] && pass "10 scanner paths ban the IP" || fail "scanner paths: $body"
grep -E 'auth failure|banning' "$OUT/server.log" | tail -2
grep -qF -e "$ACCESS" -e "$MCPTOK" -e "$OWNER_PW" -e "$OWNER_HASH" "$OUT/server.log" \
  && fail "secret in server log" || pass "no token, password or hash in the server log"
ls -l "$OUT/oauth"
echo "ALL MCP CHECKS PASSED"
