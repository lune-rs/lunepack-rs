//! Repository maintenance tasks: boundary check and denylist scan.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("check-boundaries") => {
            if let Some(extra) = args.next() {
                eprintln!("xtask: check-boundaries takes no arguments, got `{extra}`");
                return ExitCode::from(2);
            }
            xtask::boundaries::main()
        }
        other => {
            eprintln!("xtask: unknown or missing task {other:?}; tasks: check-boundaries");
            ExitCode::from(2)
        }
    }
}
