#!/usr/bin/env bash
# Build the release-signed agent APK and publish it as the server's current
# agent release; phones install it by themselves at their next sync (see
# src/release.rs, agent Updater.kt, docs/PROVISIONING.md "Updating the agent").
#
# Usage: scripts/release-agent.sh <dest> [--version-code N]
#   dest  local directory served by a local server (e.g. e2e/out/agent), or
#         HOST:DIR over ssh + sudo: the server's KIDCTL_AGENT_DIR on its host
#         (default /data/agent, on the server's data volume).
#   Without --version-code: versionCode = max(agent/version.properties, published) + 1,
#     requires a clean git tree, and writes the new code back to
#     agent/version.properties (commit it).
#   --version-code N: build exactly N (test builds); version.properties untouched.
# The versionCode always has to be above the published one: phones only
# install a higher versionCode, and Android refuses downgrades.
# Publishing order: APK, then agent.json, each by rename: the server never
# sees a half-written release (and re-checks the SHA-256 anyway).
set -euo pipefail
cd "$(dirname "$0")/.."
die() { echo "release-agent: $*" >&2; exit 1; }
DEST="${1:?usage: scripts/release-agent.sh <dir|host:dir> [--version-code N]}"; shift
VC=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version-code) VC="${2:?--version-code N}"; shift 2 ;;
    *) die "unknown argument $1" ;;
  esac
done
PKG=io.github.kidctl.agent
SIGN="$HOME/.config/kidctl/signing.properties"
[ -f "$SIGN" ] || die "no $SIGN: refusing to publish an APK not signed with the release key"
prop() { sed -n "s/^$2=//p" "$1" | tail -1; }
SDK="${ANDROID_HOME:-$(prop agent/local.properties sdk.dir)}"
SDK="${SDK:-$HOME/Android/Sdk}"
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
[ -x "$BT/aapt2" ] && [ -x "$BT/apksigner" ] || die "aapt2/apksigner not found in $BT"

# Currently published versionCode (0 if none).
case "$DEST" in
  *:*) HOST="${DEST%%:*}"; RDIR="${DEST#*:}"
       published=$(ssh "$HOST" "sudo cat '$RDIR/agent.json' 2>/dev/null" || true) ;;
  *)   HOST=""; published=$(cat "$DEST/agent.json" 2>/dev/null || true) ;;
esac
pub=0
if [ -n "$published" ]; then
  pub=$(printf %s "$published" | jq -er '.version_code') || die "published agent.json unreadable: $published"
fi
if [ -z "$VC" ]; then
  git diff --quiet HEAD || die "uncommitted changes: commit first (a release must be reproducible)"
  file_vc=$(prop agent/version.properties versionCode)
  VC=$(( (file_vc > pub ? file_vc : pub) + 1 ))
  BUMP=1
else
  BUMP=0
fi
[[ "$VC" =~ ^[0-9]+$ ]] || die "version code must be a number"
[ "$VC" -gt "$pub" ] || die "versionCode $VC is not above the published $pub"

echo "release-agent: building versionCode $VC (published: $pub)"
(cd agent && ./gradlew -q assembleRelease "-Pkidctl.versionCode=$VC")
APK=agent/app/build/outputs/apk/release/app-release.apk

# The APK must be this app, at this versionCode, signed with the release key.
badging=$("$BT/aapt2" dump badging "$APK")   # (no "| head": pipefail + SIGPIPE)
badging="${badging%%$'\n'*}"
[[ "$badging" == *"name='$PKG'"* && "$badging" == *"versionCode='$VC'"* ]] || die "unexpected APK: $badging"
store=$(prop "$SIGN" storeFile); alias=$(prop "$SIGN" keyAlias)
want=$(KS_PASS=$(prop "$SIGN" storePassword) keytool -exportcert -keystore "$store" -alias "$alias" -storepass:env KS_PASS | sha256sum | cut -d' ' -f1)
# "Signer #1 certificate SHA-256 digest: x" or "V2 Signer: certificate SHA-256 digest: x" (by version).
got=$("$BT/apksigner" verify --print-certs "$APK" | sed -n 's/^.*[Ss]igner.*certificate SHA-256 digest: //p' | sort -u)
[ -n "$want" ] && [ "$got" = "$want" ] || die "APK signer $got is not the release key $want"

STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
NAME="kidctl-agent-$VC.apk"
cp "$APK" "$STAGE/$NAME"
SHA=$(sha256sum "$STAGE/$NAME" | cut -d' ' -f1)
VN=$(prop agent/version.properties versionName)
jq -n --argjson vc "$VC" --arg vn "$VN" --arg sha "$SHA" --arg f "$NAME" \
  '{version_code: $vc, version_name: $vn, sha256: $sha, file: $f}' > "$STAGE/agent.json"
# Same checks as the server before publishing.
cargo build -q --release
./target/release/kidctl check-agent "$STAGE"

if [ -z "$HOST" ]; then
  mkdir -p "$DEST"
  cp "$STAGE/$NAME" "$DEST/.$NAME.tmp" && mv "$DEST/.$NAME.tmp" "$DEST/$NAME"
  cp "$STAGE/agent.json" "$DEST/.agent.json.tmp" && mv "$DEST/.agent.json.tmp" "$DEST/agent.json"
  find "$DEST" -maxdepth 1 -name 'kidctl-agent-*.apk' ! -name "$NAME" -delete
else
  RTMP=$(ssh "$HOST" mktemp -d)
  scp -q "$STAGE/$NAME" "$STAGE/agent.json" "$HOST:$RTMP/"
  # The directory belongs to the server's uid (distroless nonroot 65532).
  ssh "$HOST" "set -e
    sudo install -d -o 65532 -g 65532 -m 0750 '$RDIR'
    sudo install -o 65532 -g 65532 -m 0640 '$RTMP/$NAME' '$RDIR/.$NAME.tmp'
    sudo mv '$RDIR/.$NAME.tmp' '$RDIR/$NAME'
    sudo install -o 65532 -g 65532 -m 0640 '$RTMP/agent.json' '$RDIR/.agent.json.tmp'
    sudo mv '$RDIR/.agent.json.tmp' '$RDIR/agent.json'
    sudo find '$RDIR' -maxdepth 1 -name 'kidctl-agent-*.apk' ! -name '$NAME' -delete
    rm -rf '$RTMP'"
fi
if [ "$BUMP" = 1 ]; then
  sed -i "s/^versionCode=.*/versionCode=$VC/" agent/version.properties
  echo "release-agent: agent/version.properties now at versionCode $VC: commit it"
fi
echo "release-agent: published versionCode $VC sha256 $SHA to $DEST"
