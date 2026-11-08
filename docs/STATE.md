# State

Last updated: 2026-11-08 (orch-init)

## Now

Nothing in progress. The repo holds docs and config only; no code, no Cargo workspace yet.

## Next

1. Plan the design with the user: scope (platforms, installers vs updater-only, delta strategy), and what to do differently from Velopack. Record agreed choices in `docs/DECISIONS.md`.
2. First plan creates the Cargo workspace (core crate, testkit, composition-root binary), `scripts/gate.sh`, `scripts/check-boundaries.sh`, `scripts/check-secrets.sh`, and `rust-toolchain.toml` if wanted.
3. Add CI (`.github/workflows/ci.yml`) once the gate exists and passes locally.
4. Add `docs/ARCHITECTURE.md` once the boundary list is confirmed (more than three boundaries).

## Blockers / open questions

- Target platforms (Windows / macOS / Linux assumed, not confirmed), MSRV and toolchain pin: decided in planning.
- Fact: the primary API is the native Rust crate API. Other-language bindings (C ABI, .NET, Node, ...) are the last roadmap step. The binding set is not decided.
