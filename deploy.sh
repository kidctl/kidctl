#!/usr/bin/env bash
#
# Deploy the kidctl server image the GitOps way: build the image, push it to
# your registry, bump its tag in your infra repo's kustomization, commit and
# push the infra repo. Your GitOps reconciler (ArgoCD, Flux...) rolls it out.
#
# Policies are not deployed by this script: they live in the infra repo too
# (see docs/POLICY.md), and the server hot-reloads them.
#
# Usage: ./deploy.sh [--dry-run]
#   --dry-run  check everything and print what would be built, pushed and
#              committed, change nothing
#
# Settings come from an env file outside the repository (default
# ~/.config/kidctl/deploy.env, or $KIDCTL_DEPLOY_ENV); see deploy.env.example.
set -euo pipefail

DRY=0
case "${1:-}" in
    "") ;;
    --dry-run) DRY=1 ;;
    -h | --help) sed -n '2,/^set -e/{/^set -e/d;s/^# \{0,1\}//p}' "$0"; exit 0 ;;
    *) echo "usage: ./deploy.sh [--dry-run]" >&2; exit 2 ;;
esac

log()   { echo -e "\033[0;32m[deploy]\033[0m $1"; }
warn()  { echo -e "\033[1;33m[deploy]\033[0m $1"; }
error() { echo -e "\033[0;31m[deploy]\033[0m $1"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ENV_FILE="${KIDCTL_DEPLOY_ENV:-$HOME/.config/kidctl/deploy.env}"
[ -f "$ENV_FILE" ] || error "no $ENV_FILE: copy deploy.env.example there and fill it in"
# shellcheck source=deploy.env.example
. "$ENV_FILE"

: "${KIDCTL_DEPLOY_INFRA_DIR:?set in $ENV_FILE}"
: "${KIDCTL_DEPLOY_OVERLAY:?set in $ENV_FILE}"
: "${KIDCTL_DEPLOY_REGISTRY:?set in $ENV_FILE}"
IMAGE_NAME="${KIDCTL_DEPLOY_IMAGE:-kidctl/server}"
KUSTOMIZE_NAME="${KIDCTL_DEPLOY_KUSTOMIZE_NAME:-kidctl-server}"
PLATFORM="${KIDCTL_DEPLOY_PLATFORM:-linux/amd64}"
BUILDER="${KIDCTL_DEPLOY_BUILDER:-kidctl-builder}"
COMMIT_PREFIX="${KIDCTL_DEPLOY_COMMIT_PREFIX:-deploy: kidctl}"
TUNNEL="${KIDCTL_DEPLOY_SSH_TUNNEL:-}"
TUNNEL_HOST="${KIDCTL_DEPLOY_SSH_TUNNEL_HOST:-}"
INFRA_DIR="${KIDCTL_DEPLOY_INFRA_DIR/#\~/$HOME}"
OVERLAY_KUSTOMIZE="$INFRA_DIR/$KIDCTL_DEPLOY_OVERLAY/kustomization.yaml"

[ -f "$OVERLAY_KUSTOMIZE" ] || error "overlay not found: $OVERLAY_KUSTOMIZE"
command -v yq     &>/dev/null || error "yq required"
command -v docker &>/dev/null || error "docker required"
if [ -n "$TUNNEL" ] && [ -z "$TUNNEL_HOST" ]; then error "KIDCTL_DEPLOY_SSH_TUNNEL needs KIDCTL_DEPLOY_SSH_TUNNEL_HOST"; fi

cd "$SCRIPT_DIR"
git diff --quiet HEAD || error "uncommitted changes in $SCRIPT_DIR: commit first (the image tag is the git SHA)"
SHA=$(git rev-parse --short HEAD)
CURRENT=$(yq "(.images[] | select(.name == \"$KUSTOMIZE_NAME\")).newTag" "$OVERLAY_KUSTOMIZE")
[ -n "$CURRENT" ] && [ "$CURRENT" != null ] || error "no image named $KUSTOMIZE_NAME in $OVERLAY_KUSTOMIZE"
git -C "$INFRA_DIR" diff --quiet -- "$KIDCTL_DEPLOY_OVERLAY" || error "uncommitted changes in $INFRA_DIR/$KIDCTL_DEPLOY_OVERLAY"

if [ "$DRY" = 1 ]; then
    log "dry run, nothing changed:"
    log "  tests:   cargo test --locked in $SCRIPT_DIR"
    [ -n "$TUNNEL" ] && log "  tunnel:  ssh -fN -L $TUNNEL $TUNNEL_HOST (unless already listening)"
    log "  build:   $IMAGE_NAME @ $SHA ($PLATFORM, builder $BUILDER)"
    log "  push:    $KIDCTL_DEPLOY_REGISTRY/$IMAGE_NAME:$SHA (+ :buildcache)"
    log "  infra:   git pull --ff-only in $INFRA_DIR"
    log "  bump:    $KUSTOMIZE_NAME $CURRENT -> $SHA in $OVERLAY_KUSTOMIZE"
    log "  commit:  \"$COMMIT_PREFIX @ $SHA\", then git push"
    exit 0
fi

cargo test --locked --quiet || error "tests failed"

if [ -n "$TUNNEL" ]; then
    local_port=${TUNNEL%%:*}
    if ! ss -tln 2>/dev/null | grep -q "127.0.0.1:$local_port "; then
        log "Opening SSH tunnel $TUNNEL via $TUNNEL_HOST (registry)..."
        ssh -fN -o ExitOnForwardFailure=yes -L "$TUNNEL" "$TUNNEL_HOST" \
            || error "failed to open the registry SSH tunnel via $TUNNEL_HOST"
        for _ in $(seq 1 20); do ss -tln 2>/dev/null | grep -q "127.0.0.1:$local_port " && break; sleep 0.25; done
    fi
fi

docker buildx use "$BUILDER" >/dev/null 2>&1 \
    || docker buildx create --name "$BUILDER" --driver docker-container --use >/dev/null

CACHE_REF="$KIDCTL_DEPLOY_REGISTRY/$IMAGE_NAME:buildcache"
log "Building $IMAGE_NAME @ $SHA ($PLATFORM)..."
docker buildx build \
    --platform "$PLATFORM" \
    --tag "$KIDCTL_DEPLOY_REGISTRY/$IMAGE_NAME:$SHA" \
    --cache-to   "type=registry,ref=$CACHE_REF,mode=max" \
    --cache-from "type=registry,ref=$CACHE_REF" \
    --push \
    "$SCRIPT_DIR"

cd "$INFRA_DIR"
git pull --ff-only --quiet || error "git pull --ff-only failed in $INFRA_DIR"
log "Updating kustomization: $KUSTOMIZE_NAME -> $SHA"
yq -i "(.images[] | select(.name == \"$KUSTOMIZE_NAME\")).newTag = \"$SHA\"" "$OVERLAY_KUSTOMIZE"
if git diff --quiet -- "$KIDCTL_DEPLOY_OVERLAY"; then
    warn "No infra changes to commit (already at $SHA)"
else
    git commit -m "$COMMIT_PREFIX @ $SHA" -- "$KIDCTL_DEPLOY_OVERLAY/kustomization.yaml"
    git push --quiet
    log "Infra pushed: your GitOps reconciler rolls out $SHA."
fi
log "Done: $IMAGE_NAME @ $SHA"
