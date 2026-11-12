# State

Last updated: 2026-11-12 (milestone 1, foundation)

## Now

Milestone 1 (foundation) is implemented on branch `orch/lunepack-v1` and not yet pushed:

- Cargo workspace (edition 2024, toolchain 1.99.1, MSRV 1.88), 12 crate skeletons plus `xtask`.
- `scripts/gate.sh`, the boundary check, the secret check with the optional local denylist scan, and shell tests.
- Agent guards for key files in `.claude/` (Read denies and a Bash hook).
- CI (`.github/workflows/ci.yml`: gate on Linux, build, clippy and tests on 3 OSes, MSRV check).
- Early platform probes under `probes/` with their workflow (`.github/workflows/probes.yml`); verdicts come from the first CI run.

## Next

1. Push the branch (after the local denylist is reviewed), read the first CI and probe results, fix what the first run breaks.
2. Milestone 2: format v1 and the trust core (format spec and threat model, core types, DSSE envelope, key set, feed and manifest verification, crypto adapter, testkit fakes). Its stop settles the open decisions below that need probe results.

## Blockers / open questions

- Probe verdicts are pending the first CI run; the decisions they inform stay open until then.
- Open decisions (see `docs/DECISIONS.md` for the settled ones), with the milestone they must be settled by:
  - D9 Linux packaging targets, D11 Windows per-user layout, D13 lifecycle hooks, D19 runtime binary provenance: before M5.
  - D10 macOS install and update model: before M7.
  - D12 per-machine model on all three OSes: before M9 (the install state is scope-aware from M4 either way).
  - D8 delta algorithm: before M11.
  - D15 migration from other updaters: before M12.
  - D9, D10, D11, D12, D13 and D19 are asked together at M2's stop.
- Fact: the primary API is the native Rust crate API. Other-language bindings (C ABI, .NET, Node, ...) are the last roadmap step; the binding set is not decided.
