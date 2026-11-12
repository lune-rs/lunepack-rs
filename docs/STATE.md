# State

Last updated: 2026-11-13 (milestone 2, format and trust, step 1)

## Now

Milestone 1 (foundation) is merged to `main`. Milestone 2 (format v1 and the trust core) is in
progress on branch `orch/lunepack-v1`, not pushed:

- Step 1 done: `docs/FORMAT.md` (format v1 draft: envelope, documents, caps, frames and codecs,
  path/version/target rules, verification order and policy) and `docs/THREAT-MODEL.md` (draft).
- Awaiting the user's approval of both documents. No code that encodes the wire format is written
  before that approval.

## Next

1. User stop: approve or change `docs/FORMAT.md` and `docs/THREAT-MODEL.md`; decide D9, D10, D11,
   D12, D13 and D19 (D39 may be asked early).
2. Milestone 2 steps 4–12: core foundation (strict JSON, encodings, traits), shared path/version/
   target rules, testkit fakes and contract suites, the crypto adapter, envelope/root/key-set
   verification, the frame parser, feed and manifest verification and policy, fuzz targets, and the
   DECISIONS/ARCHITECTURE updates with a test that keeps FORMAT.md's examples parsing.

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
