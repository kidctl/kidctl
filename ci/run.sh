#!/usr/bin/env bash
# The CI, runnable locally. GitHub Actions calls the same jobs, so a green local
# run means a green CI run.
#
#   ci/run.sh                 # all jobs: noai zizmor gitleaks wrapper fmt clippy test agent
#   ci/run.sh clippy test     # selected jobs
#
# The Rust jobs use the pinned toolchain below (installed with rustup when
# missing), so the lint set only moves with a reviewed bump. CI_HOST=1 (the
# pre-push hook) uses the host toolchain instead.
#
# The agent job (Kotlin unit tests on the shared vectors + a debug build) needs
# JDK 21 and an Android SDK with platform 37 ($ANDROID_HOME, else
# agent/local.properties, else ~/Android/Sdk). Without an SDK it fails under
# CI=true and is skipped, loudly, elsewhere.
#
# Tools that are not cargo subcommands are downloaded once, checked against a
# pinned SHA-256 and cached in $CI_TOOLS (default ~/.cache/kidctl-ci).
# When bumping a version, bump its checksum with it.
set -euo pipefail

RUST_TOOLCHAIN=1.99.1
GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ZIZMOR_VERSION=1.31.1
ZIZMOR_SHA256=d185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99
# agent/gradle/wrapper/gradle-wrapper.jar, as published by Gradle for this
# version (https://services.gradle.org/distributions/gradle-<v>-wrapper.jar.sha256).
# The distribution itself is checked by Gradle (distributionSha256Sum).
GRADLE_VERSION=9.8.2
GRADLE_WRAPPER_SHA256=3b8a25775a69158b5ad2b1d17a80a88dc7b40a352a73eb27d06c612a7ce68e98

cd "$(git rev-parse --show-toplevel)"
# No warning is tolerated: every cargo invocation turns warnings into errors.
export RUSTFLAGS="-D warnings" RUSTDOCFLAGS="-D warnings"
CI_TOOLS=${CI_TOOLS:-${XDG_CACHE_HOME:-$HOME/.cache}/kidctl-ci}
mkdir -p "$CI_TOOLS"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# fetch <url> <sha256> <file>: download into $CI_TOOLS once, verify every time.
fetch() {
    local url=$1 sum=$2 out="$CI_TOOLS/$3"
    [ -f "$out" ] || curl -fsSL --retry 5 --retry-all-errors -o "$out.part" "$url" && { [ -f "$out" ] || mv "$out.part" "$out"; }
    echo "$sum  $out" | sha256sum -c --quiet -
}

tool_gitleaks() {
    local a="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/$a" "$GITLEAKS_SHA256" "$a"
    [ -x "$CI_TOOLS/gitleaks-$GITLEAKS_VERSION" ] || {
        tar -xzf "$CI_TOOLS/$a" -C "$CI_TOOLS" gitleaks
        mv "$CI_TOOLS/gitleaks" "$CI_TOOLS/gitleaks-$GITLEAKS_VERSION"
    }
    echo "$CI_TOOLS/gitleaks-$GITLEAKS_VERSION"
}

tool_zizmor() {
    local a=zizmor-x86_64-unknown-linux-gnu.tar.gz
    fetch "https://github.com/zizmorcore/zizmor/releases/download/v${ZIZMOR_VERSION}/$a" "$ZIZMOR_SHA256" "zizmor-$ZIZMOR_VERSION.tar.gz"
    [ -x "$CI_TOOLS/zizmor-$ZIZMOR_VERSION" ] || {
        tar -xzf "$CI_TOOLS/zizmor-$ZIZMOR_VERSION.tar.gz" -C "$CI_TOOLS" zizmor
        mv "$CI_TOOLS/zizmor" "$CI_TOOLS/zizmor-$ZIZMOR_VERSION"
    }
    echo "$CI_TOOLS/zizmor-$ZIZMOR_VERSION"
}

# The pinned toolchain, unless CI_HOST=1.
toolchain() {
    [ -n "${CI_HOST:-}" ] && { rustc --version; return 0; }
    if ! rustup toolchain list | grep -q "^$RUST_TOOLCHAIN-"; then
        rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal --component rustfmt,clippy
    fi
    rustup component add --toolchain "$RUST_TOOLCHAIN" rustfmt clippy >/dev/null 2>&1
    export RUSTUP_TOOLCHAIN=$RUST_TOOLCHAIN
    rustc --version
}

# The Android SDK: $ANDROID_HOME, agent/local.properties, ~/Android/Sdk.
android_sdk() {
    local d=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
    [ -n "$d" ] || d=$(sed -n 's/^sdk\.dir=//p' agent/local.properties 2>/dev/null | tail -1)
    [ -n "$d" ] || d=$HOME/Android/Sdk
    ls -d "$d"/platforms/android-37* >/dev/null 2>&1 && echo "$d"
}

job_noai() { bash .github/scripts/no-ai-traces.sh HEAD; }
# Workflows and dependabot.yml; every finding fails, informational ones included.
job_zizmor() { "$(tool_zizmor)" --offline --persona=pedantic --min-severity=informational .github; }
# The whole history, every commit. Reviewed false positives: .gitleaksignore.
job_gitleaks() { "$(tool_gitleaks)" git --redact --exit-code 1 --no-banner .; }
job_wrapper() {
    grep -qx "distributionUrl=https\\\\://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip" agent/gradle/wrapper/gradle-wrapper.properties \
        || { echo "gradle-wrapper.properties: not Gradle $GRADLE_VERSION (bump GRADLE_* here)"; return 1; }
    grep -q '^distributionSha256Sum=[0-9a-f]\{64\}$' agent/gradle/wrapper/gradle-wrapper.properties \
        || { echo "gradle-wrapper.properties: no distributionSha256Sum"; return 1; }
    echo "$GRADLE_WRAPPER_SHA256  agent/gradle/wrapper/gradle-wrapper.jar" | sha256sum -c -
}
job_fmt() { toolchain && cargo fmt --all --check; }
job_clippy() { toolchain && cargo clippy --all-targets --locked -- -D warnings; }
job_test() { toolchain && cargo test --locked; }
job_agent() {
    local sdk
    if ! sdk=$(android_sdk); then
        if [ "${CI:-}" = true ]; then echo "no Android SDK with platform 37"; return 1; fi
        printf '\033[33mSKIPPED: no Android SDK with platform 37 (set ANDROID_HOME)\033[0m\n'
        return 0
    fi
    (cd agent && ANDROID_HOME=$sdk ./gradlew --no-daemon --no-configuration-cache testDebugUnitTest assembleDebug)
}

ALL=(noai zizmor gitleaks wrapper fmt clippy test agent)

jobs=("$@")
[ ${#jobs[@]} -eq 0 ] && jobs=("${ALL[@]}")

failed=()
for j in "${jobs[@]}"; do
    if ! declare -F "job_$j" >/dev/null; then echo "unknown job: $j" >&2; exit 2; fi
    say "$j"
    if ! "job_$j"; then failed+=("$j"); fi
done

if [ ${#failed[@]} -gt 0 ]; then
    printf '\n\033[31mFAILED: %s\033[0m\n' "${failed[*]}"
    exit 1
fi
printf '\n\033[32mOK: %s\033[0m\n' "${jobs[*]}"
