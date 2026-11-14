# lunepack-rs

Pure-Rust installer, packager and auto-updater framework: package releases, build installers, ship full and delta updates, apply an update and restart. First consumer is Lunegit (a desktop git client); meant for other apps too.
Inspired by Velopack but not a clone: it is a reference only, so do not port its design or formats unless `docs/DECISIONS.md` says so.
Public repo (`lune-rs/lunepack-rs`), dual-licensed MIT OR Apache-2.0. The primary API is the native Rust crate API; other-language bindings are the last roadmap step. Target platforms: Windows, macOS and Linux, with per-user and per-machine installs (`docs/DECISIONS.md`).

## Start here

Read `docs/STATE.md` first. Before stopping, update it (now / next / blockers / last updated) in the
same commit as the work. Decisions live in `docs/DECISIONS.md`; do not re-open one unless the user asks.
Product design is settled by planning with the user, not guessed: if a task needs an undecided design choice, stop and ask.

## Commands

Rust toolchain 1.99.1 is pinned in `rust-toolchain.toml` (edition 2024, MSRV 1.88 checked in CI); rustup installs it on first use.
- Build: `cargo build --workspace --locked`
- Test (all): `cargo test --workspace --locked`
- Test (one): `cargo test -p <crate> --locked <test_name>`
- Format / lint: `cargo fmt --all` and `cargo clippy --workspace --all-targets --locked -- -D warnings`
- Boundary check: `./scripts/check-boundaries.sh` (a thin wrapper over `cargo run -p xtask -- check-boundaries`)
- Shell tests (scripts and agent guards; need bash, git, jq, gitleaks): `bash scripts/tests/run.sh`
- Secret scan (staged changes): `./scripts/check-secrets.sh --staged` (gitleaks over history, merge commits and tracked files, a check that fails on tracked key-container paths such as `.pfx` or `.pem`, and the optional local denylist scan before pushes; `--range <a>..<b>` for a commit range, `--require-denylist` to fail when the local denylist is missing)
- Check (fast, per commit; must be green): `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test -p <changed-crate> --locked && ./scripts/check-secrets.sh --staged`
- Gate (once per tip before merge or push; must be green): `./scripts/gate.sh` = fmt check + clippy + `cargo test --workspace --locked` + `./scripts/check-boundaries.sh` + `./scripts/check-secrets.sh` + `bash scripts/tests/run.sh` + shellcheck (`LUNEPACK_REQUIRE_SHELLCHECK=1` makes a missing shellcheck fail) + a Docker Linux `cargo test` stage (skipped when Docker is not running, `CI` is set or `LUNEPACK_GATE_DOCKER=0`; it builds one image from `scripts/gate.Dockerfile`, uses two named volumes and never prunes anything; the names are in the header of `scripts/gate.sh`)
- Windows cross-check (this Mac; compiles, does not link or run): `cargo check --target x86_64-pc-windows-msvc --locked -p lunepack-codec-lzma -p lunepack-core -p lunepack-crypto -p lunepack-fs -p lunepack-os-linux -p lunepack-os-macos -p lunepack-os-windows -p lunepack-runtime -p lunepack-testkit -p xtask`. `lunepack`, `lunepack-cli` and `lunepack-http` are left out: they build ring's C code (the HTTP stack), so CI checks them.

## Architecture rules

Crate roles are in `docs/ARCHITECTURE.md`; the boundary check enforces them.
- Rust core, bindings as adapters: `crates/lunepack-core` holds the pure logic and the traits and depends on no adapter or I/O crate. Bindings (C ABI, .NET, Node, ...; last roadmap step, not near-term) are adapter crates over the core (`crates/lunepack-ffi`, ...) and add no logic.
- Anything external or replaceable sits behind a trait owned by the core, in core types and the core error enum: filesystem, release source / network, compression and delta codec, hashing and signature verification, OS install / shortcut / autostart, process launch and restart, clock and randomness, logging sink. Implementations: `crates/lunepack-<thing>` (`lunepack-crypto`, `lunepack-codec-lzma`, `lunepack-fs`, `lunepack-http`, `lunepack-os-{windows,macos,linux}`).
- Composition roots: each shipped binary (`lunepack-runtime`, `lunepack-cli`) wires traits to adapters in its own `main.rs`; for apps that embed lunepack, the `lunepack` facade crate is the root (a builder wires the default adapters, each swappable). Nothing else constructs an adapter.
- Dependencies point inward only (`adapter -> core`). Enforced by the crate graph plus the boundary check (an xtask over `cargo metadata` and real `toml` parsing that fails closed on any form it does not recognise), run by the gate.
- Each trait has a contract suite and an in-memory fake in `crates/lunepack-testkit` (`publish = false`); every adapter's `tests/` runs the suite.
- Add a codec, platform or binding by adding a crate and one registration line in the root; the core does not change.
- `probes/` holds throwaway platform probes (scripts and two small standalone crates, outside the Cargo workspace, never published) that run only on GitHub-hosted runners through `.github/workflows/probes.yml`; they never run on a developer machine, except the read-only local cross-check `probes/p-x1/run-local.sh`.
- `fuzz/` is a cargo-fuzz project outside the workspace with its own committed `Cargo.lock`, which the boundary check holds to crates.io plus workspace crates. The Gate replays its committed seeds on stable (`cargo test -p lunepack-testkit --locked --test fuzz_replay`); libFuzzer needs nightly and `cargo-fuzz` and is not part of the Gate (`fuzz/README.md`).

## Hard rules

1. Public repo: never commit a secret, signing key, token or real credential, not even in tests (generate test keys at test time). Checked by `./scripts/check-secrets.sh --staged` in Check and Gate; `.claude/settings.json` denies reading `.env*` and key files, and a Bash hook blocks commands that name them.
2. `unsafe_code = "forbid"` in `[workspace.lints.rust]`; only `lunepack-fs`, the `lunepack-os-*` crates and the future FFI crate may lift it (the boundary check allows no other crate to), each block with a `// SAFETY:` comment. Unsafe code or asm inside a dependency is allowed only where `docs/DECISIONS.md` names it (today `lzma-rust2`'s `optimization` feature in `lunepack-codec-lzma`, confined by the boundary check, and `ring` via rustls in `lunepack-http`).
3. The core has no ambient clock, randomness, filesystem or network access; it goes through its traits so tests and replays are deterministic.
4. Errors: `thiserror` enum per library crate, causes kept; `anyhow` only in binaries. Libraries log through `tracing` and never install a subscriber; never log secrets or user data.
5. Cargo features are additive; no feature switches an adapter on or off in a way that changes core behaviour.

## Git

- Override: every task works in its own git worktree off `main`, including subagents (the user's standing request for this repo).
- Commit per change, with Check green; run the Gate once per tip before merge.

## Read on demand

- `docs/STATE.md` - current work and next steps
- `docs/DECISIONS.md` - decisions and what was rejected
- `docs/ARCHITECTURE.md` - crates, dependency direction, traits, composition roots
