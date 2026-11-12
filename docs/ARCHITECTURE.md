# Architecture

How the workspace is split and how the split is enforced. Crate roles, the trait list and the
boundary rules are the current design; the trait definitions arrive with the first format and
trust milestone and the list below stays provisional until then. Decisions behind this are in
`docs/DECISIONS.md` (D1, D14, D17, D23, D26, D28, D30, D31).

## Crates

| Crate | Role | May depend on |
|---|---|---|
| `lunepack-core` | Types, rules, verification policy, planning, state machine, apply engine; owns every trait and the error enum. No I/O, clock, randomness or network of its own. | nothing external beyond an explicit allowlist (empty today) |
| `lunepack-testkit` | In-memory fakes (including a crash-injecting filesystem, a faulty Range transport, a fake clock) and the contract suites. `publish = false`. | core |
| `lunepack-crypto` | Hashing, signature verification and signing adapters. | core |
| `lunepack-codec-zstd` | Compression and delta codec adapter. | core |
| `lunepack-fs` | Filesystem adapter. | core |
| `lunepack-http` | Release source and network adapter. | core |
| `lunepack-os-windows`, `lunepack-os-macos`, `lunepack-os-linux` | OS install, shortcut, autostart and process adapters. | core |
| `lunepack` | The app-facing facade and the composition root for apps that embed lunepack: a builder wires the default adapters, each swappable. | core, adapters |
| `lunepack-runtime` | Binary: launcher, updater, installer, uninstaller, service. | core, adapters, facade |
| `lunepack-cli` | Binary `lunepack`: the packager and feed tooling. | core, adapters, facade |
| `xtask` | Repository tooling: the boundary check and the optional denylist scan. | nothing in the workspace |

A language binding (a C ABI crate, later others) is one more adapter crate over the core and adds no logic.
Every crate has `publish = false` until a publishing decision is made.

## Dependency direction

Dependencies point inward only: an adapter depends on the core, never the reverse, and adapters
do not depend on each other. The facade and the binaries sit outside the adapters and may use
them. `dev-dependencies` may name `lunepack-testkit` and nothing else from the workspace.

## Traits (provisional)

Owned by the core, implemented by adapters, faked in the testkit: `Fs`, `Transport`, `Codec`,
`Hasher`, `Verifier`, `Signer`, `Clock`, `Rng`, `OsIntegration`, `Process`. `Transport` is
object-safe with boxed `Send` futures so a host app can inject its own client (D23). Each trait
gets a contract suite in the testkit that every adapter's `tests/` runs.

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
- a workspace member it has no role for, and any member under `probes/` (probes stay outside the
  workspace);
- a crate without `[lints] workspace = true`, except the allowlisted crates (`lunepack-fs`, the
  `lunepack-os-*` crates, later the FFI crate), which may replace the table with a full copy whose
  only differences are `unsafe_code` and an added `undocumented_unsafe_blocks = "deny"`;
- a root `unsafe_code` that is not `forbid`, and package fields (edition, license, MSRV) that
  differ from the workspace's.

Adding a crate is one line in `ROLES` in `xtask/src/boundaries.rs`.

## Probes

`probes/` holds throwaway platform probes: scripts and two small standalone crates, outside the
Cargo workspace and never published. They run only on GitHub-hosted runners
(`.github/workflows/probes.yml`), each with a control that decides whether its verdict counts.
