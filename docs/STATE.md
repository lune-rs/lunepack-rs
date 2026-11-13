# State

Last updated: 2026-11-13 (milestone 2, format and trust, step 4)

## Now

Milestone 1 (foundation) is merged to `main`. Milestone 2 (format v1 and the trust core) is in
progress on branch `orch/lunepack-v1`, not pushed:

- Steps 1-3 done: `docs/FORMAT.md` and `docs/THREAT-MODEL.md` approved by the user; the codec crate
  is `lunepack-codec-lzma`.
- Step 4 done: core foundation in `lunepack-core` (strict JSON pre-pass, hex and canonical base64,
  `Sha256Digest`, `U53`, `Limits`, the `Hasher`/`Verifier`/`Clock`/`Codec` traits, the error enum);
  the boundary check allowlists core's six pure external crates.

## Next

Milestone 2 steps 5-12: shared path/version/target rules, testkit fakes and contract suites, the
crypto adapter, envelope/root/key-set verification, the frame parser, feed and manifest
verification and policy, fuzz targets, and the DECISIONS/ARCHITECTURE updates with a test that
keeps FORMAT.md's examples parsing.

## Blockers / open questions

- M1 probe verdicts: all PASS with control ok (CI runs 43258313963 and the probes re-run); they feed the step-3 decisions.
- Open decisions (see `docs/DECISIONS.md` for the settled ones), with the milestone they must be settled by:
  - D9 Linux packaging targets, D11 Windows per-user layout, D13 lifecycle hooks, D19 runtime binary provenance: before M5.
  - D10 macOS install and update model: before M7.
  - D12 per-machine model on all three OSes: before M9 (the install state is scope-aware from M4 either way).
  - D8 delta algorithm: before M11.
  - D15 migration from other updaters: before M12.
  - D9, D10, D11, D12, D13 and D19 are asked together at M2's stop.
- Fact: the primary API is the native Rust crate API. Other-language bindings (C ABI, .NET, Node, ...) are the last roadmap step; the binding set is not decided.
