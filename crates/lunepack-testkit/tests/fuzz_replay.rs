//! Stable-toolchain replay of the fuzz harnesses (M2-D8, M2-D9): the committed seeds under
//! `fuzz/seeds/` are exactly what the real writers produce, every seed runs through its harness as
//! expected, and random and mutated inputs never panic. The libFuzzer targets in `fuzz/` call the
//! same harnesses (`lunepack_core::fuzz`).
//!
//! To rewrite the committed seeds after a writer change:
//! `LUNEPACK_WRITE_SEEDS=1 cargo test -p lunepack-testkit --test fuzz_replay committed_seeds`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use lunepack_core::fuzz::{HARNESSES, accepts};
use lunepack_testkit::{Seed, fuzz_seeds};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

/// Random inputs per harness (M2 step 11 contract).
const RANDOM_CASES: u32 = 10_000;
/// Mutated-seed inputs per harness.
const MUTATED_CASES: u32 = 10_000;
/// Longest random input.
const MAX_RANDOM_LEN: usize = 1024;

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

fn seed_dir(harness: &str) -> PathBuf {
    fuzz_dir().join("seeds").join(harness)
}

fn seeds_of(harness: &str) -> Vec<Seed> {
    fuzz_seeds()
        .into_iter()
        .filter(|s| s.harness == harness)
        .collect()
}

fn run(harness: &str, data: &[u8]) -> bool {
    accepts(harness, data).unwrap_or_else(|| panic!("no harness named {harness}"))
}

#[test]
fn committed_seeds_match_the_writer() {
    let write = std::env::var_os("LUNEPACK_WRITE_SEEDS").is_some();
    let seeds = fuzz_seeds();
    let mut problems = Vec::new();
    let mut expected: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for seed in &seeds {
        expected
            .entry(seed.harness)
            .or_default()
            .insert(seed.name.clone());
        let path = seed_dir(seed.harness).join(&seed.name);
        if write {
            fs::create_dir_all(seed_dir(seed.harness)).expect("create seed dir");
            fs::write(&path, &seed.bytes).expect("write seed");
            continue;
        }
        match fs::read(&path) {
            Ok(committed) if committed == seed.bytes => {}
            Ok(_) => problems.push(format!(
                "{}/{} differs from the writer",
                seed.harness, seed.name
            )),
            Err(_) => problems.push(format!("{}/{} is not committed", seed.harness, seed.name)),
        }
    }
    for (harness, _) in HARNESSES {
        let names = expected.get(harness).cloned().unwrap_or_default();
        assert!(!names.is_empty(), "harness {harness} has no seeds");
        if let Ok(dir) = fs::read_dir(seed_dir(harness)) {
            for entry in dir.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !names.contains(&name) {
                    problems.push(format!(
                        "{harness}/{name} is committed but no writer makes it"
                    ));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "seeds out of date (rerun with LUNEPACK_WRITE_SEEDS=1):\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_harness_has_a_fuzz_target_and_both_kinds_of_seed() {
    for (harness, _) in HARNESSES {
        let target = fuzz_dir()
            .join("fuzz_targets")
            .join(format!("{harness}.rs"));
        let source = fs::read_to_string(&target).unwrap_or_else(|e| {
            panic!("no fuzz target for {harness} at {}: {e}", target.display())
        });
        assert!(
            source.contains(&format!("lunepack_core::fuzz::{harness}(")),
            "{} does not call lunepack_core::fuzz::{harness}",
            target.display()
        );
        let seeds = seeds_of(harness);
        assert!(
            seeds.iter().any(|s| s.accepted),
            "{harness}: no accepted seed"
        );
        assert!(
            seeds.iter().any(|s| !s.accepted),
            "{harness}: no rejected seed"
        );
    }
    let targets = fs::read_dir(fuzz_dir().join("fuzz_targets"))
        .expect("fuzz_targets dir")
        .flatten()
        .count();
    assert_eq!(targets, HARNESSES.len(), "a fuzz target without a harness");
}

#[test]
fn committed_seeds_run_as_expected() {
    for (harness, _) in HARNESSES {
        let expected: BTreeMap<String, bool> = seeds_of(harness)
            .into_iter()
            .map(|s| (s.name, s.accepted))
            .collect();
        let mut seen = 0;
        for entry in fs::read_dir(seed_dir(harness)).expect("seed dir").flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = fs::read(entry.path()).expect("read seed");
            let got = run(harness, &bytes);
            if let Some(&want) = expected.get(&name) {
                assert_eq!(
                    got, want,
                    "{harness}/{name}: accepted = {got}, expected {want}"
                );
            }
            seen += 1;
        }
        assert!(seen > 0, "{harness}: no committed seeds");
    }
}

/// Every single-byte change, every truncation and every one-byte insertion of every seed (strided
/// for the largest seeds so the whole test stays quick).
#[test]
fn seed_neighbourhoods_do_not_panic() {
    for (harness, _) in HARNESSES {
        for seed in seeds_of(harness) {
            let bytes = &seed.bytes;
            let stride = (bytes.len() / 250).max(1);
            for i in (0..=bytes.len()).step_by(stride) {
                run(harness, &bytes[..i]);
                if i < bytes.len() {
                    for flip in [0x01u8, 0xff] {
                        let mut m = bytes.clone();
                        m[i] ^= flip;
                        run(harness, &m);
                    }
                    let mut dropped = bytes.clone();
                    dropped.remove(i);
                    run(harness, &dropped);
                }
                let mut inserted = bytes.clone();
                inserted.insert(i, b'"');
                run(harness, &inserted);
            }
        }
    }
}

fn runner(cases: u32) -> TestRunner {
    TestRunner::new(Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    })
}

fn random_inputs(harness: &str) {
    let strategy = prop::collection::vec(any::<u8>(), 0..MAX_RANDOM_LEN);
    runner(RANDOM_CASES)
        .run(&strategy, |data| {
            run(harness, &data);
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{harness}: random input: {e}"));
}

fn mutated_seeds(harness: &str) {
    let seeds: Vec<Vec<u8>> = seeds_of(harness).into_iter().map(|s| s.bytes).collect();
    let strategy = (
        prop::sample::select(seeds),
        prop::collection::vec((any::<u16>(), any::<u8>(), 0u8..3), 1..8),
    );
    runner(MUTATED_CASES)
        .run(&strategy, |(mut data, edits)| {
            for (at, byte, op) in edits {
                let at = usize::from(at) % (data.len() + 1);
                match op {
                    0 if at < data.len() => data[at] ^= byte | 1,
                    1 => data.insert(at, byte),
                    _ if at < data.len() => {
                        data.remove(at);
                    }
                    _ => {}
                }
            }
            run(harness, &data);
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{harness}: mutated seed: {e}"));
}

macro_rules! replay {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        fn $name() {
            random_inputs(stringify!($name));
            mutated_seeds(stringify!($name));
        }
    )*};
}

replay!(
    envelope, root, keys, feed, manifest, path, tree, rules, json, frame
);

#[test]
fn the_replay_list_covers_every_harness() {
    let named: BTreeSet<&str> = [
        "envelope", "root", "keys", "feed", "manifest", "path", "tree", "rules", "json", "frame",
    ]
    .into_iter()
    .collect();
    let all: BTreeSet<&str> = HARNESSES.iter().map(|(n, _)| *n).collect();
    assert_eq!(named, all);
}
