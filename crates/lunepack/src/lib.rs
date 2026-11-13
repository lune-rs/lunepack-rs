//! Facade crate: the public Rust API that applications depend on, and the root that wires the
//! default adapters.

use std::time::{SystemTime, UNIX_EPOCH};

use lunepack_core::Clock;

/// The wall clock: seconds since the Unix epoch from the operating system (M3-D5).
///
/// A system time before the epoch reads as 0. Core never reaches for the time itself (hard rule 3);
/// it takes a [`Clock`], and this is the one the shipped binaries and embedding apps give it.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}
