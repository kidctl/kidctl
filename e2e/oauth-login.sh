#!/usr/bin/env bash
# OAuth 2.1 login against a kidctl server, the way an MCP client does it
# (Claude Code: public client, loopback redirect, PKCE S256), and print the
# access token on stdout:
#   unauthenticated /mcp -> 401 + resource_metadata -> protected resource
#   metadata -> authorization server metadata -> register -> authorize (owner
#   password, consent) -> code -> token.
# Usage: KIDCTL_OWNER_PASSWORD=<pw> e2e/oauth-login.sh <base-url>
#   VERBOSE=1 logs each step on stderr (never the password or tokens).
# The password goes to curl on stdin, never on its command line.
set -euo pipefail
BASE=${1:?usage: KIDCTL_OWNER_PASSWORD=<pw> $0 <base-url>}
BASE=${BASE%/}
: "${KIDCTL_OWNER_PASSWORD:?KIDCTL_OWNER_PASSWORD must be set}"
CB=http://127.0.0.1:33418/callback

log() { if [ -n "${VERBOSE:-}" ]; then echo "oauth: $*" >&2; fi; }
die() { echo "oauth: FAIL: $*" >&2; exit 1; }
# jget <key>... : read JSON on stdin, walk keys (list indexes as numbers), print.
jget() { python3 -c 'import sys,json
v=json.load(sys.stdin)
for k in sys.argv[1:]: v=v[int(k)] if isinstance(v,list) else v[k]
print(v)' "$@"; }
# qget <url> <param> : one query parameter of a URL.
qget() { python3 -c 'import sys,urllib.parse as u
print(dict(u.parse_qsl(u.urlsplit(sys.argv[1]).query)).get(sys.argv[2],""))' "$1" "$2"; }

# 1. Unauthenticated MCP request: 401 with the resource metadata URL.
hdrs=$(curl -s -o /dev/null -D - -X POST "$BASE/mcp" -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
echo "$hdrs" | head -1 | grep -q ' 401' || die "unauthenticated /mcp did not answer 401: $(echo "$hdrs" | head -1)"
prm=$(echo "$hdrs" | tr -d '\r' | sed -n 's/^www-authenticate: .*resource_metadata="\([^"]*\)".*/\1/Ip')
[ -n "$prm" ] || die "no resource_metadata in WWW-Authenticate"
log "401 from /mcp, resource metadata at $prm"

# 2. Discovery (RFC 9728, RFC 8414).
prm_json=$(curl -sf "$prm") || die "GET $prm"
resource=$(echo "$prm_json" | jget resource)
issuer=$(echo "$prm_json" | jget authorization_servers 0)
asm=$(curl -sf "$issuer/.well-known/oauth-authorization-server") || die "authorization server metadata"
reg_ep=$(echo "$asm" | jget registration_endpoint)
authz_ep=$(echo "$asm" | jget authorization_endpoint)
token_ep=$(echo "$asm" | jget token_endpoint)
log "resource $resource, issuer $issuer"

# 3. Dynamic client registration (public client).
reg=$(curl -sf -X POST "$reg_ep" -H 'content-type: application/json' \
  -d "{\"client_name\":\"kidctl e2e\",\"redirect_uris\":[\"$CB\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"token_endpoint_auth_method\":\"none\"}") \
  || die "registration"
client_id=$(echo "$reg" | jget client_id)
log "registered client $client_id"

# 4. PKCE S256.
verifier=$(head -c 32 /dev/urandom | python3 -c 'import sys,base64; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).rstrip(b"=").decode())')
challenge=$(printf %s "$verifier" | python3 -c 'import sys,hashlib,base64; print(base64.urlsafe_b64encode(hashlib.sha256(sys.stdin.buffer.read()).digest()).rstrip(b"=").decode())')
state=$(head -c 8 /dev/urandom | xxd -p)
authz=(--data-urlencode response_type=code --data-urlencode "client_id=$client_id" --data-urlencode "redirect_uri=$CB"
       --data-urlencode "state=$state" --data-urlencode "code_challenge=$challenge" --data-urlencode code_challenge_method=S256
       --data-urlencode scope=mcp --data-urlencode "resource=$resource")

# 5. Authorize: login page, owner password, consent.
code=$(curl -s -o /dev/null -w '%{http_code}' -G "$authz_ep" "${authz[@]}")
[ "$code" = 200 ] || die "GET authorize: HTTP $code"
page=$(printf %s "$KIDCTL_OWNER_PASSWORD" | curl -s -X POST "$authz_ep" "${authz[@]}" \
  --data-urlencode step=login --data-urlencode "password@-")
ticket=$(echo "$page" | sed -n 's/.*name="ticket" value="\([^"]*\)".*/\1/p' | head -1)
[ -n "$ticket" ] || die "login refused (wrong owner password?)"
log "owner password accepted, consent page shown"
out=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -X POST "$authz_ep" \
  --data-urlencode step=consent --data-urlencode "ticket=$ticket" --data-urlencode decision=allow)
[ "${out%% *}" = 303 ] || die "consent: HTTP ${out%% *}"
loc=${out#* }
[ "$(qget "$loc" state)" = "$state" ] || die "state mismatch in redirect"
[ "$(qget "$loc" iss)" = "$issuer" ] || die "iss mismatch in redirect"
authcode=$(qget "$loc" code)
[ -n "$authcode" ] || die "no code in redirect"
log "redirected to ${loc%%\?*} with code, state and iss"

# 6. Token exchange.
tok=$(curl -sf -X POST "$token_ep" --data-urlencode grant_type=authorization_code \
  --data-urlencode "code=$authcode" --data-urlencode "redirect_uri=$CB" --data-urlencode "client_id=$client_id" \
  --data-urlencode "code_verifier=$verifier" --data-urlencode "resource=$resource") || die "token exchange"
[ "$(echo "$tok" | jget token_type)" = Bearer ] || die "token_type"
log "access token issued (expires in $(echo "$tok" | jget expires_in) s)"
echo "$tok" | jget access_token
