# State

Last updated: 2026-11-13 (milestone 2, format and trust, done)

## Now

Milestone 2 (format v1 and the trust core) is done on branch `orch/lunepack-v1`, not pushed and not
yet merged (review and gate pending):

- `docs/FORMAT.md` and `docs/THREAT-MODEL.md` approved by the user; the codec crate is
  `lunepack-codec-lzma`.
- `lunepack-core`: strict JSON, DSSE envelopes, root rotation, key set, feed and manifest
  verification with freshness and rollback floors, the frame descriptor and verify-then-decode, the
  shared path, version and target rules, and update policy (candidate selection, rollout bucket).
- `lunepack-crypto`: SHA-256 and Ed25519 with strict verification; `lunepack-testkit`: fakes,
  contract suites, document builders and fuzz seeds. A real-crypto test runs the whole chain and
  rejects a one-byte change in every document.
- `fuzz/`: ten harnesses (`lunepack_core::fuzz`) with cargo-fuzz targets and committed seeds;
  the gate replays them on stable, and the boundary check holds `fuzz/Cargo.lock` to crates.io plus
  workspace crates.
- `docs/DECISIONS.md` carries the revised D6 and D17, D33 to D35, the user's answers on D9 to D13,
  D19 and D39, and M2-D1 to M2-D9.
- Not done: libFuzzer has not been run (installing `cargo-fuzz` was refused in the working
  session); the targets compile on stable and the real runs move to the CI work in M13. No
  Windows NTFS differential test has run yet; it first runs at M3's push.

## Next

Milestone 3: the `lzma-rust2` codec in `lunepack-codec-lzma`, with its boundary rule and the
CLAUDE.md hard rule 2 sentence in the same commit (D34). M3's push is the first push of this
branch; the Windows NTFS path differential test first runs there.

## Blockers / open questions

- Open decisions (settled ones are in `docs/DECISIONS.md`): D8 delta algorithm and its dictionary cap,
  D15 migration from other updaters, D36 to D38, D40 and D41 (UI fallback, size budget, per-machine
  first-install elevation, accessibility, silent mode), each asked at the stop of the milestone that
  needs it.
- Fact: the primary API is the native Rust crate API. Other-language bindings (C ABI, .NET, Node, ...) are the last roadmap step; the binding set is not decided.
