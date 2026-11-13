//! A settable clock.

use std::sync::{Arc, Mutex, PoisonError};

use lunepack_core::Clock;

/// 2100-01-01T00:00:00Z in Unix seconds.
pub const YEAR_2100_UNIX_SECS: u64 = 4_102_444_800;

const SECS_PER_DAY: u64 = 86_400;

/// A clock whose time only changes when a test says so. Clones share the same time, so a test can
/// keep one handle and give another to the code under test.
#[derive(Debug, Clone)]
pub struct FakeClock {
    now: Arc<Mutex<u64>>,
}

impl FakeClock {
    /// A clock set to `unix_secs`.
    pub fn new(unix_secs: u64) -> Self {
        FakeClock {
            now: Arc::new(Mutex::new(unix_secs)),
        }
    }

    /// Sets the time.
    pub fn set(&self, unix_secs: u64) {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner) = unix_secs;
    }

    /// Moves the time forward by `secs` (saturating).
    pub fn advance_secs(&self, secs: u64) {
        let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
        *now = now.saturating_add(secs);
    }

    /// Moves the time forward by `days` whole days.
    pub fn advance_days(&self, days: u64) {
        self.advance_secs(days.saturating_mul(SECS_PER_DAY));
    }

    /// Moves the time forward by 400 days, far enough to age out any fixed window.
    pub fn advance_400_days(&self) {
        self.advance_days(400);
    }

    /// Sets the time to 2100-01-01T00:00:00Z.
    pub fn set_year_2100(&self) {
        self.set(YEAR_2100_UNIX_SECS);
    }
}

impl Clock for FakeClock {
    fn now_unix_secs(&self) -> u64 {
        *self.now.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
