# lunepack-rs

A pure-Rust installer, packager and auto-updater framework: package releases, build installers, ship full and delta updates, apply an update and restart. Built first for Lunegit and meant for other apps.

Status: early. The workspace, build gate and CI exist as crate skeletons; the format, packager, client and installers are still to come. Design decisions are in [`docs/DECISIONS.md`](docs/DECISIONS.md), the crate layout in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and the current state in [`docs/STATE.md`](docs/STATE.md).

## Build and test

Rust 1.99.1 is pinned in `rust-toolchain.toml` and installed by rustup on first use.

```sh
cargo build --workspace --locked
cargo test --workspace --locked
./scripts/gate.sh   # everything CI's gate runs; see CLAUDE.md for the stages
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
