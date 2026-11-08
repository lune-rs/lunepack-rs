# lunepack-rs

Pure-Rust installer, packager and auto-updater framework: package releases, build installers, ship full and delta updates, apply an update and restart. First consumer is Lunegit (a desktop git client); meant for other apps too. Inspired by Velopack but not a clone: it is a reference only, so do not port its design or formats unless `docs/DECISIONS.md` says so.
Public repo (`lune-rs/lunepack-rs`), dual-licensed MIT OR Apache-2.0. The primary API is the native Rust crate API; other-language bindings are the last roadmap step. Target platforms are not decided yet (see `docs/STATE.md`).

## Start here

Read `docs/STATE.md` first. Before stopping, update it (now / next / blockers / last updated) in the
same commit as the work. Decisions live in `docs/DECISIONS.md`; do not re-open one unless the user asks.
Product design is settled by planning with the user, not guessed: if a task needs an undecided design choice, stop and ask.

## Commands

No code exists yet; the first plan creates the Cargo workspace. Until then every cargo command below is not runnable.
- Build: `cargo build --workspace` (not yet runnable (no code))
- Test (all): `cargo test --workspace` (not yet runnable (no code))
- Test (one): `cargo test -p <crate> <test_name>` (not yet runnable (no code))
- Format / lint: `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` (not yet runnable (no code))
- Secret scan (staged changes): `gitleaks git --staged --redact`
- Check (fast, per commit; must be green): `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p <changed-crate> && gitleaks git --staged --redact` (not yet runnable (no code))
- Gate (once per tip before merge or push; must be green): `./scripts/gate.sh` = fmt check + clippy + `cargo test --workspace` + `./scripts/check-boundaries.sh` + `./scripts/check-secrets.sh` (to be created by the first plan; not yet runnable (no code))

## Architecture rules

Boundary list and crate names are provisional until the first plan confirms them; every path is to be created by the first plan.
- Rust core, bindings as adapters: `crates/lunepack-core` holds the pure logic and the traits and depends on no adapter or I/O crate. Bindings (C ABI, .NET, Node, ...; last roadmap step, not near-term) are adapter crates over the core (`crates/lunepack-ffi`, ...) and add no logic.
- Anything external or replaceable sits behind a trait owned by the core, in core types and the core error enum: filesystem, release source / network, compression and delta codec, hashing and signature verification, OS install / shortcut / autostart, process launch and restart, clock and randomness, logging sink. Implementations: `crates/lunepack-<thing>`.
- One composition root per shipped binary (e.g. `crates/lunepack-cli/src/main.rs`) wires traits to adapters; nothing else constructs an adapter.
- Dependencies point inward only (`adapter -> core`). Enforced by the crate graph plus `scripts/check-boundaries.sh` (gate).
- Each trait has a contract suite and an in-memory fake in `crates/lunepack-testkit` (`publish = false`); every adapter's `tests/` runs the suite.
- Add a codec, platform or binding by adding a crate and one registration line in the root; the core does not change.

## Hard rules

1. Public repo: never commit a secret, signing key, token or real credential, not even in tests (generate test keys at test time). Checked by `gitleaks git --staged --redact` in Check and Gate; `.claude/settings.json` denies reading `.env*` and key files.
2. `unsafe_code = "forbid"` in `[workspace.lints.rust]`; only an FFI or OS-adapter crate may lift it, each block with a `// SAFETY:` comment.
3. The core has no ambient clock, randomness, filesystem or network access; it goes through its traits so tests and replays are deterministic.
4. Errors: `thiserror` enum per library crate, causes kept; `anyhow` only in binaries. Libraries log through `tracing` and never install a subscriber; never log secrets or user data.
5. Cargo features are additive; no feature switches an adapter on or off in a way that changes core behaviour.

## Git

- Override: every task works in its own git worktree off `main`, including subagents (the user's standing request for this repo).
- Commit per change, with Check green; run the Gate once per tip before merge.

## Read on demand

- `docs/STATE.md` - current work and next steps
- `docs/DECISIONS.md` - decisions and what was rejected
