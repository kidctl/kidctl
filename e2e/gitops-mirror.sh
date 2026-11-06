#!/usr/bin/env bash
# Stands in for ArgoCD + the kidctl-policies ConfigMap in the e2e tests:
# every 2 s, fetch the branch the server pushes to (MCP write tools) and copy
# its policies directory into the server's watched config directory, changed
# files only (atomically: temp file + rename; config loading ignores
# dotfiles), and remove files that left the repo, like kubelet refreshing a
# mounted ConfigMap after an ArgoCD sync. The server then hot-reloads within
# 10 s, as in production.
# Usage: e2e/gitops-mirror.sh <bare repo> <branch> <policies path in repo> <config dir> <work dir>
set -euo pipefail
REPO=$1 BRANCH=$2 SUB=$3 DEST=$4 WORK=$5
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
rm -rf "$WORK"
git clone -q --branch "$BRANCH" "$REPO" "$WORK"
last=
while :; do
  git -C "$WORK" fetch -q origin "$BRANCH" && git -C "$WORK" reset -q --hard FETCH_HEAD
  head=$(git -C "$WORK" rev-parse --short HEAD)
  if [ "$head" != "$last" ]; then
    for f in "$WORK/$SUB"/*.yaml; do
      n=$(basename "$f")
      if ! cmp -s "$f" "$DEST/$n"; then cp "$f" "$DEST/.$n.tmp" && mv "$DEST/.$n.tmp" "$DEST/$n"; fi
    done
    for f in "$DEST"/*.yaml; do
      [ -e "$WORK/$SUB/$(basename "$f")" ] || rm -f "$f"
    done
    echo "mirror: $head -> $DEST"
    last=$head
  fi
  sleep 2
done
