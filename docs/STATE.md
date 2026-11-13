# State

Last updated: 2026-11-13 (milestone 3, packager MVP, done on the branch; push and review pending)

## Now

Milestones 2 (format v1 and the trust core) and 3 (the packager) are done on branch
`orch/lunepack-v1`, not pushed and not yet merged (review, gate and the first push pending):

- M2: `docs/FORMAT.md` and `docs/THREAT-MODEL.md`; `lunepack-core` (strict JSON, DSSE envelopes, root
  rotation, key set, feed and manifest verification with freshness and rollback floors, frame
  descriptors and verify-then-decode, shared rules, update policy); `lunepack-crypto`;
  `lunepack-testkit`; `fuzz/` harnesses and seeds replayed by the gate. libFuzzer itself has not run
  (CI work, M13).
- M3: the `lunepack` CLI (`docs/CLI.md`): `init`, `keys gen|show|set|rotate-root`, `pack`,
  `feed add|refresh`, `verify`, `inspect`. `pack` takes any app's build-output directory (M3-D13) and
  writes a deterministic, signed pack and manifest; every output is verified with the client's own
  verifiers before it is placed. Codec: `lunepack-codec-lzma` over `lzma-rust2` (stored, LZMA2, BCJ x86
  and ARM64, BCJ2; decoder limits from the signed descriptor), confined to that crate by the boundary
  check (M3-D11, D34). Signers in `lunepack-crypto` (PKCS#8 PEM file and env, command), `SystemClock`
  in the facade. Revocation in two moves with a guard on `keys set` and `keys rotate-root`
  (M3-R1-D1). Decisions M3-D1 to M3-D13 and M3-R1-D1 are in `docs/DECISIONS.md`.
- Probe P-U1 (LuneUI on hosted runners) is in `probes/luneui/` and `probes.yml`; it has not run.

## Next

Push of `orch/lunepack-v1` (the first push of M2 and M3; the user's stop), which runs CI on three OSes
(including the MSRV job, the Windows NTFS path differential test and the cross-host encoder
known-answer tests) and every probe job. Then M3's review and merge, then Milestone 4 (the installer
stage and the apply engine over the release directory C2).

## Known limits and open items from M3

- Unverified until CI: the MSRV (1.88) build with the new dependencies; the encoder known-answer tests
  on x86-64 against arm64 (if they differ, the determinism claim in `docs/CLI.md` needs a revision);
  the Windows NTFS differential test; P-U1's verdicts.
- The pack is built in memory, so a multi-gigabyte app needs that much RAM (M3-D8, `docs/CLI.md`).
- A leaked release-key threshold can sign `seq` 2^53-1 and block `feed refresh` on that channel
  (workaround: a new channel). Owner: the threat-model pass in M13.
- How a non-Rust app triggers an update from inside the app is not decided (client milestone).

## Blockers / open questions

- Open decisions (settled ones are in `docs/DECISIONS.md`): D8 delta algorithm and its dictionary cap,
  D15 migration from other updaters, D36 to D38, D40 and D41 (UI fallback, size budget, per-machine
  first-install elevation, accessibility, silent mode), each asked at the stop of the milestone that
  needs it.
- Fact: the primary API is the native Rust crate API. Other-language bindings (C ABI, .NET, Node, ...) are the last roadmap step; the binding set is not decided.
