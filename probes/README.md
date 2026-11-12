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
