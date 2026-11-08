# Decisions

| ID | Date | Decision | Why | Rejected |
|---|---|---|---|---|
| D1 | 2026-11-08 | Rust core with language bindings as adapters over it; exact binding set undecided | One implementation, many hosts; keeps bindings free of logic | Per-language reimplementations |
| D2 | 2026-11-08 | Velopack is a reference only; lunepack-rs is a new design, not a 1:1 clone | Goal is a better design that avoids Velopack's mistakes | Porting Velopack's design and formats wholesale |
| D3 | 2026-11-08 | License is MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`) | Rust ecosystem convention; user's choice | Single license |
| D4 | 2026-11-08 | Public GitHub repo `lune-rs/lunepack-rs`, `main` is the base branch | User's choice; first consumer is Lunegit | Private repo |
| D5 | 2026-11-08 | Primary API is Rust; other-language bindings are the last roadmap step (user, 2026-11-08) | Rust consumers come first; other languages later, so bindings are not near-term | Building a .NET (or other) binding early |
