# Architecture

How the workspace is split and how the split is enforced. Crate roles and the boundary rules
are the current design; four traits are defined (below) and the rest stay provisional. The wire
format is `docs/FORMAT.md` and its threat model `docs/THREAT-MODEL.md`. Decisions behind this are in
`docs/DECISIONS.md` (D1, D6, D14, D17, D23, D26, D28, D30, D31, D33, M2-D1 to M2-D9).

## Crates

| Crate | Role | May depend on |
|---|---|---|
| `lunepack-core` | Types, rules, verification policy, planning, state machine, apply engine; owns every trait and the error enum. No I/O, clock, randomness or network of its own. Today: strict JSON, DSSE envelopes, root rotation, key sets, feeds, manifests, frame descriptors, the path, version and target rules, update policy, and the hidden `fuzz` harness module. | nothing external beyond an explicit allowlist: `serde`, `serde_json`, `base64`, `semver`, `unicode-normalization`, `thiserror` (M2-D1) |
| `lunepack-testkit` | In-memory fakes and the contract suites. Today: a fake clock, hasher, signature scheme and codec (with fault knobs), the contract suites for the traits below, document builders over the core's real writer, and the fuzz seed writer; a crash-injecting filesystem and a faulty Range transport come with their traits. `publish = false`. | core |
| `lunepack-crypto` | Hashing and signature verification adapters: SHA-256 and Ed25519 with strict verification (key-signing adapters come later). | core |
| `lunepack-codec-lzma` | Compression and delta codec adapter. | core |
| `lunepack-fs` | Filesystem adapter. | core |
| `lunepack-http` | Release source and network adapter. | core |
| `lunepack-os-windows`, `lunepack-os-macos`, `lunepack-os-linux` | OS install, shortcut, autostart and process adapters. | core |
| `lunepack` | The app-facing facade and the composition root for apps that embed lunepack: a builder wires the default adapters, each swappable. | core, adapters |
| `lunepack-runtime` | Binary: launcher, updater, installer, uninstaller, service. | core, adapters, facade |
| `lunepack-cli` | Binary `lunepack`: the packager and feed tooling. | core, adapters, facade |
| `xtask` | Repository tooling: the boundary check, the key-container file check and the optional denylist scan. | nothing in the workspace |

A language binding (a C ABI crate, later others) is one more adapter crate over the core and adds no logic.
Every crate has `publish = false` until a publishing decision is made.

## Dependency direction

Dependencies point inward only: an adapter depends on the core, never the reverse, and adapters
do not depend on each other. The facade and the binaries sit outside the adapters and may use
them. `dev-dependencies` may name `lunepack-testkit` and nothing else from the workspace.

## Traits

Owned by the core, implemented by adapters, faked in the testkit. Defined today:

- `Hasher` (one-shot and streaming SHA-256), implemented by `lunepack-crypto`;
- `Verifier` (`verify` with strict Ed25519 semantics, and the required `check_public_key` that
  rejects non-canonical and small-order keys), implemented by `lunepack-crypto`;
- `Clock` (`now_unix_secs`; the only source of time in the core);
- `Codec` (decodes one verified frame into a writer and reports the bytes consumed per stream).

Each has a contract suite in the testkit that the real implementation's `tests/` runs, and a fake
in the testkit. The others are provisional and arrive with their milestones: `Fs`, `Transport`,
`Signer`, `Rng`, `OsIntegration`, `Process`. `Transport` is object-safe with boxed `Send` futures
so a host app can inject its own client (D23).

## Composition roots

Nothing constructs an adapter except a composition root: the `lunepack` facade for embedding
apps, and `main.rs` of each shipped binary. Adding a codec, platform or binding means adding a
crate and one registration line in a root; the core does not change.

## How the boundary check enforces this

`./scripts/check-boundaries.sh` runs `xtask check-boundaries`. Dependencies, sources and package
fields come from `cargo metadata` (cargo is the authority on what a manifest declares); only the
`[lints]` tables and the root `[workspace]` keys are read with a real TOML parser. Anything the
check does not recognise is a violation, and an internal error exits 2, never 0. It rejects:

- a dependency that breaks the table above, including renamed, optional, target-specific and
  build dependencies (identified by package name), git dependencies, path dependencies outside
  the workspace, and external crates in the core that are not allowlisted;
- a workspace member it has no role for, and any member under `probes/` or `fuzz/` (both stay
  outside the workspace; when `fuzz/Cargo.toml` exists the root `exclude` must name `fuzz`);
- a crate without `[lints] workspace = true`, except the allowlisted crates (`lunepack-fs`, the
  `lunepack-os-*` crates, later the FFI crate), which may replace the table with a full copy whose
  only differences are `unsafe_code` and an added `undocumented_unsafe_blocks = "deny"`;
- a root `unsafe_code` that is not `forbid`, and package fields (edition, license, MSRV) that
  differ from the workspace's.
- a `Cargo.lock` (the workspace's and each `probes/*/`'s) that is missing, or has a package that is
  neither from crates.io nor, without a source, one of that lock's own members by name and version
  (the workspace members, or the probe's own package); this catches git and other-registry sources
  and path dependencies, including those redirected by `[patch]`, `[replace]` or a
  `.cargo/config.toml` patch, because the lock records what cargo actually resolved. A `[patch]` or
  `[replace]` section in the root or a probe manifest is flagged too. The check does not read
  `.cargo/config.toml` itself; it sees a config patch only through the lock it produced.
- `fuzz/` (M2-D9): its `Cargo.lock` is held to the same rule, with the workspace's members (by name
  and version) and the fuzz package itself as the only source-less entries, and a missing
  `fuzz/Cargo.lock` is a violation. Its manifest's dependencies (normal, dev, build and
  target-specific) must be crates.io requirements or `path` dependencies on a workspace member
  (same package name, same directory); a `git`, `registry` or `workspace` key, any other path and
  any form the check does not recognise is a violation.
- confined crates (M3-D11, `CONFINED` in `xtask/src/boundaries.rs`): `lzma-rust2` may be named only
  by `lunepack-codec-lzma`. No other workspace package may depend on it in any kind, target or
  rename (matched on the package name `cargo metadata` reports); in every lock the check reads
  (the workspace's, `probes/*/`, `fuzz/`), any `[[package]]` whose `dependencies` names it must be
  `lunepack-codec-lzma` as a source-less member, which catches pulls through third-party crates;
  an unparseable `dependencies` value is a violation. The codec crate's requirement must be exactly
  `=0.25.0` (`EXACT_PINS`).

Adding a crate is one line in `ROLES` in `xtask/src/boundaries.rs`.

## Fuzzing

`fuzz/` is a cargo-fuzz project outside the workspace, with its own committed `Cargo.lock` and one
target per harness of `lunepack_core::fuzz` (`envelope`, `root`, `keys`, `feed`, `manifest`,
`path`, `tree`, `rules`, `json`, `frame`). `fuzz/seeds/<harness>/` holds committed seeds written by
the real writers (`lunepack_testkit::fuzz_seeds`); `corpus/`, `artifacts/` and `target/` are
gitignored. The gate does not run libFuzzer (it needs nightly and a C++ build). It runs
`crates/lunepack-testkit/tests/fuzz_replay.rs` on stable: the committed seeds must equal what the
writers produce, every seed must behave as named, and random and mutated inputs must not panic.
The libFuzzer runs themselves are not done yet (CI, M13); the targets are only known to compile.
`fuzz/README.md` has the commands.

## Probes

`probes/` holds throwaway platform probes: scripts and two small standalone crates, outside the
Cargo workspace and never published. They run only on GitHub-hosted runners
(`.github/workflows/probes.yml`), each with a control that decides whether its verdict counts.
