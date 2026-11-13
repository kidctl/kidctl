# Multi-stage build: glibc release binary on Debian 12 slim, nonroot.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# Dependency layer cache: build deps against a stub first.
RUN mkdir src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
    && cargo build --release --locked && rm -rf src
COPY src ./src
COPY spec ./spec
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# Runtime: the MCP write tools commit and push to the GitOps repo with the
# system git over ssh (deploy key), so the image carries git and the ssh
# client (it used to be distroless/cc, which has no package manager), plus
# the CA roots the OAuth client-metadata fetches need. Distro packages are
# pinned: when a Debian security update replaces one, the old version leaves
# the mirror and this build fails; bump the pin to the new version
# (`apt-cache policy git openssh-client ca-certificates` in debian:12-slim).
FROM debian:13-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       git=1:2.39.5-0+deb12u3 \
       openssh-client=1:9.2p1-2+deb12u10 \
       ca-certificates=20250419~deb12u2 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin nonroot
COPY --from=build /src/target/release/kidctl /kidctl
# ssh refuses to run for a uid without a passwd entry: nonroot exists above.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/kidctl"]
CMD ["serve"]
