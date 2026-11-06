# Contributing

Issues and pull requests are welcome. Please report security problems
privately instead, see [SECURITY.md](SECURITY.md).

Before opening a pull request:

- run `ci/run.sh`: the same jobs as GitHub Actions (format, clippy with
  `-D warnings`, Rust tests, the agent's Kotlin unit tests and build,
  gitleaks over the history, workflow lint, Gradle wrapper checksum);
- add a test for the behaviour you change, and update the README and
  `docs/` in the same commit when behaviour, configuration or defaults
  change;
- rule evaluation exists twice, `src/eval.rs` (server) and
  `agent/.../Evaluator.kt` (phone): a change goes into both and into the
  shared vectors `spec/vectors.json`, which both test suites run. If
  `spec/vectors-policy.yaml` changes, regenerate the `policy` member of
  `spec/vectors.json` with
  `cargo run -- compile spec/vectors-policy.yaml spec/vectors-overrides.yaml`;
- the compiled policy JSON is the wire format of deployed phones: adding a
  field is fine (the agent reads it with `opt*`), renaming or removing one
  breaks them;
- the agent stays free of dependencies and of UI;
- keep the security invariants of the README's "Security" section: every
  authentication failure is counted, nothing secret is logged or stored in
  clear, a banned IP only gets responses to valid credentials.

Changes that touch the phone side should also pass the end-to-end test on an
Android emulator, `e2e/run.sh emulator-5554` (see the README, "Testing").

`git config core.hooksPath .githooks` enables a pre-push hook that runs
`ci/run.sh` on a clean worktree of each pushed commit.

Contributions are accepted under the MIT license of this repository.
