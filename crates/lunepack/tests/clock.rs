//! `SystemClock` against the clock contract suite.

use lunepack::SystemClock;
use lunepack_core::Clock;
use lunepack_testkit::run_clock_suite;

#[test]
fn system_clock_passes_the_clock_suite() {
    // A real clock cannot be moved, so there is no shifted variant.
    run_clock_suite(&SystemClock, None);
}

#[test]
fn system_clock_reads_a_plausible_time() {
    // After 2024-01-01 and before the format's integer ceiling.
    let now = SystemClock.now_unix_secs();
    assert!(now > 1_704_067_200, "{now}");
    assert!(now < (1 << 53) - 1);
}
