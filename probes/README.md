# probes

Throwaway scripts and small probe crates that test platform premises the design relies on
(runner admin rights, Windows service start, socket-activated daemons, transport behavior).
They are not part of the product:

- Not in the Cargo workspace (`exclude = ["probes"]`); never published; ignored by the boundary check.
- Run only on GitHub-hosted runners by `.github/workflows/probes.yml`. Every script refuses to
  run (exit 3, nothing touched) unless `GITHUB_ACTIONS=true` and `RUNNER_ENVIRONMENT=github-hosted`
  (fallback if the runner does not set it: `GITHUB_ACTIONS=true` plus a non-empty `ImageOS`).
  They change runner security settings (services, launchd, systemd, trust stores), so they never
  run on a developer machine. The one local probe (P-X1) changes nothing.
- Each probe writes `probe-results/<id>.json` with `verdict` (PASS, FAIL or INVALID) and `control`
  (ok or failed). A control is an instrument check that must behave in a known way; if it does
  not, the verdict is forced to INVALID. The workflow uploads the file as artifact `probe-<id>`.
- Result details carry named fields only: never an environment, a registry hive, a keychain or a
  file dump. Passwords for users a probe creates are generated at run time and never printed.

Helpers: `lib/result.sh` and `lib/result.ps1` (guard and result writer; `--self-test` /
`-SelfTest` exercise them in a temp dir). `runner-facts/` is P-R0 (admin rights and runner facts
on all three OSes).

## P-U1: LuneUI on hosted runners

`luneui/run.sh` (Linux, macOS) and `luneui/run.ps1` (Windows) clone `lune-rs/luneui-rs` at commit
`ec17ff0` (v0.5.1) into `RUNNER_TEMP` (no Cargo dependency, lock or path in this repo refers to it),
build the gallery `--release` with the runner's stable toolchain, run `gallery --dump` headless
(PNG count; adapter name and backend from the gallery's `--bench` line), then open the window for
about 5 s and take one screenshot (details only). Controls: the clone is at the pin; the binary
lists its scenes; on Linux `--dump` must fail to find an adapter before Mesa is installed; at least
one dumped PNG has more than one colour. PASS: the dump rendered and the controls hold. FAIL: no
adapter or no PNG with the controls ok. INVALID otherwise. Results: `probe-results/P-U1-<os>.json`.
