# State

Last updated: 2026-11-15 (milestone 4, client fetch and stage: review round 1 fixed on the branch; re-review and push pending)

## Now

Milestones 2 (format v1 and the trust core), 3 (the packager) and 4 (client fetch and stage) are done
on branch `orch/lunepack-v1`, not pushed and not yet merged (review, gate and the first push pending):

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
- M4: an app embedding `lunepack` can check for an update, download it resumably and stage a verified
  version tree (`Updater::check`, `download`, `stage`, `staged`; `lunepack::blocking`), on tokio,
  smol, futures or no runtime, with cancel by drop or token and progress on the polling thread. Core:
  the transport and `Fs` traits, the HTTP response rules, the install-state store (FORMAT.md 12; one
  record per file, crash-safe at every write point) and the stage engine. Adapters: `lunepack-fs`
  (`StdFs`, the OS lock), `lunepack-http` (ureq with the platform verifier and system proxies, and a
  directory source). `ring` is reachable only through `lunepack-http` (boundary check). Proof: a
  scenario suite under five executors, cancel at every poll, cross-process `staged()` and a
  hard-killed lock holder (`crates/lunepack/tests/`), and a CI job `os-trust` that re-checks the OS
  trust store and the system proxy through the real adapter on three OSes. Decisions M4-D1 to M4-D23
  are in `docs/DECISIONS.md` (M4-D10, 403 as an absent root, decided by the user).
- Probe P-U1 (LuneUI on hosted runners) is in `probes/luneui/` and `probes.yml`; it has not run.

M4 review round 1 (F1 to F11, `M4-R1-D1` in `docs/DECISIONS.md`) is fixed on the branch: download and scan progress totals, a
best-effort cache cleanup after the staged commit, disk errors as `Error::Fs`, the transport worker
holding the operation lock, `DirSource` running the transport suite, the facade re-exporting its API
types (and `lunepack::trusted_root`), a complete cached pack re-hashed before use, the store assigning
the record seq, a symlinked `current_tree` not followed, the task plumbing hidden in
`unstable_internals`, and a refusal of versions whose directory names differ only in case.

## Next

Push of `orch/lunepack-v1` (the first push of M2, M3 and M4; the user's stop), which runs CI on three
OSes (including the MSRV job, the Windows NTFS path differential test, the cross-host encoder
known-answer tests, and the new `os-trust` job) and every probe job. Then the review and merge of M3
and M4, then Milestone 5 (the Linux runtime: tree install, apply and the app-facing command line over
the staged tree).

## Known limits and open items from M3

- Unverified until CI: the MSRV (1.88) build with the new dependencies; the encoder known-answer tests
  on x86-64 against arm64 (if they differ, the determinism claim in `docs/CLI.md` needs a revision);
  the Windows NTFS differential test; P-U1's verdicts.
- The pack is built in memory, so a multi-gigabyte app needs that much RAM (M3-D8, `docs/CLI.md`).
- A leaked release-key threshold can sign `seq` 2^53-1 and block `feed refresh` on that channel
  (workaround: a new channel). Owner: the threat-model pass in M13.
- How a non-Rust app triggers an update from inside the app is not decided (client milestone).

## Known limits and open items from M4

- Unverified until CI: everything that builds ring's C code (the facade, `lunepack-http` and the CLI
  cannot be cross-checked for Windows from the Mac); the `os-trust` job's accept-after and proxy
  halves (only its control flow ran locally, under stubs); Windows directory durability (`sync_dir` on
  a directory handle is an assumption in `lunepack-fs`; a commit could be lost, never corrupted, on
  power loss).
- Windows CI fix (unverified until the next run): `StdFs::create_dir_all` no longer inspects a bare
  Windows prefix (`\\?\C:`, which a canonicalised path starts with), the cause of the
  `cross_process` failure (empty-name `FsError`, kind `Other`, "Uncategorized"). `FsError` now carries
  the failed operation and the OS code, so a repeat names itself.
- A dropped download on the default transport leaves its worker in a socket read until the per-read
  timeout (30 s), and the updater lock stays held meanwhile (`Busy`); documented in the threat model.
- Per-OS layout discovery, `Layout` for installed apps and the apply step are M5, M7 and M8.

## Blockers / open questions

- Open decisions (settled ones are in `docs/DECISIONS.md`): D8 delta algorithm and its dictionary cap,
  D15 migration from other updaters, D36 to D38, D40 and D41 (UI fallback, size budget, per-machine
  first-install elevation, accessibility, silent mode), each asked at the stop of the milestone that
  needs it.
- Fact: the primary API is the native Rust crate API. Other-language bindings (C ABI, .NET, Node, ...) are the last roadmap step; the binding set is not decided.
