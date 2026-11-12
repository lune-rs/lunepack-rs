#!/usr/bin/env bash
# The gate: run once per tip before merge or push. Stops at the first failing stage.
#   ./scripts/gate.sh
# Env: LUNEPACK_REQUIRE_SHELLCHECK=1  fail when shellcheck is missing (default: notice, skip)
#      LUNEPACK_GATE_DOCKER=0         skip the Docker Linux suite
# The Docker stage runs only when `docker info` succeeds, CI is unset and LUNEPACK_GATE_DOCKER
# is not 0 (CI has a native Linux job). It touches only its own --rm container and two named
# volumes; it never prunes and never touches other containers, images or volumes.
# bash 3.2 compatible.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
top=$PWD

# rust:1.99.1-slim-trixie, resolved 2026-11-12 with `docker pull` + `docker inspect`
# (RepoDigests). The tag alone is not trusted; the digest is.
IMAGE='rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7'
TARGET_VOLUME=lunepack-rs-gate-target
CARGO_VOLUME=lunepack-rs-gate-cargo

stage() {
  echo
  echo "== gate: $* =="
}

stage "cargo fmt --all -- --check"
cargo fmt --all -- --check

stage "cargo clippy --workspace --all-targets --locked -- -D warnings"
cargo clippy --workspace --all-targets --locked -- -D warnings

stage "cargo test --workspace --locked"
cargo test --workspace --locked

stage "./scripts/check-boundaries.sh"
./scripts/check-boundaries.sh

stage "./scripts/check-secrets.sh"
./scripts/check-secrets.sh

stage "bash scripts/tests/run.sh"
bash scripts/tests/run.sh

stage "shellcheck scripts/**/*.sh .claude/hooks/*.sh"
if command -v shellcheck >/dev/null 2>&1; then
  find scripts .claude/hooks -name '*.sh' -type f -print0 | xargs -0 shellcheck
elif [ "${LUNEPACK_REQUIRE_SHELLCHECK:-}" = 1 ]; then
  echo "gate: shellcheck not found and LUNEPACK_REQUIRE_SHELLCHECK=1" >&2
  exit 1
else
  echo "gate: NOTICE shellcheck not installed; stage skipped (set LUNEPACK_REQUIRE_SHELLCHECK=1 to fail instead)"
fi

stage "docker linux suite"
skip_reason=
if [ "${LUNEPACK_GATE_DOCKER:-}" = 0 ]; then
  skip_reason="LUNEPACK_GATE_DOCKER=0"
elif [ -n "${CI:-}" ]; then
  skip_reason="CI is set (the CI workflow has a native Linux job)"
elif ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  skip_reason="docker is not available (docker info failed)"
fi
if [ -n "$skip_reason" ]; then
  echo "gate: NOTICE docker linux suite skipped: $skip_reason"
else
  # Source read-only; target and cargo registry in named volumes. RUSTUP_TOOLCHAIN makes
  # rustup use the image's own 1.99.1 instead of installing the components and targets that
  # rust-toolchain.toml lists (this stage runs only `cargo test`). No host env is passed.
  # The slim image has no git, which the xtask tests drive, so it is installed from the
  # Debian archive first (apt needs the default root capabilities, so none are dropped).
  docker run --rm \
    --name "lunepack-rs-gate-$$" \
    --security-opt no-new-privileges \
    -v "$top":/src:ro \
    -v "$TARGET_VOLUME":/target \
    -v "$CARGO_VOLUME":/cargo-home \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_HOME=/cargo-home \
    -e RUSTUP_TOOLCHAIN=1.99.1 \
    -w /src \
    "$IMAGE" \
    bash -c 'apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends git >/dev/null && exec cargo test --workspace --locked'
fi

echo
echo "gate: all stages passed"
