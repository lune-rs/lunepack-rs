//! Shared harness of the CLI tests: run the real binary, and scan everything it prints for secrets.

#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Output, Stdio};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

/// Runs `lunepack` with `args` and the extra environment `env`, in the current directory.
///
/// `SOURCE_DATE_EPOCH` is removed from the inherited environment first, so a test that wants it
/// says so. The environment cannot be changed in this process (edition 2024 and no `unsafe`), which
/// is why every environment-dependent case runs the binary as a child with its own environment.
pub fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    run_in(None, args, env)
}

/// Like [`run`], in directory `cwd`.
pub fn run_in(cwd: Option<&Path>, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lunepack"));
    cmd.args(args)
        .stdin(Stdio::null())
        .env_remove("SOURCE_DATE_EPOCH");
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("start lunepack")
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Panics unless `output` succeeded.
pub fn assert_ok(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed ({}): {}",
        output.status,
        stderr(output)
    );
}

/// Panics unless `output` failed with exit status `code`; returns stderr.
pub fn assert_fails(output: &Output, code: i32, what: &str) -> String {
    assert_eq!(
        output.status.code(),
        Some(code),
        "{what}: expected exit {code}, got {} (stderr: {})",
        output.status,
        stderr(output)
    );
    stderr(output)
}

fn forms(secret: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let mut out = vec![
        ("raw", secret.to_vec()),
        ("hex", hex.clone().into_bytes()),
        ("HEX", hex.to_uppercase().into_bytes()),
        ("base64", STANDARD.encode(secret).into_bytes()),
        (
            "base64 unpadded",
            STANDARD_NO_PAD.encode(secret).into_bytes(),
        ),
        ("base64url", URL_SAFE.encode(secret).into_bytes()),
        (
            "base64url unpadded",
            URL_SAFE_NO_PAD.encode(secret).into_bytes(),
        ),
    ];
    // PEM text: every body line of 16 or more characters is a secret in its own right.
    if let Ok(text) = std::str::from_utf8(secret) {
        for line in text.lines() {
            if line.len() >= 16 && !line.starts_with("--") {
                out.push(("pem body line", line.as_bytes().to_vec()));
            }
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Panics if stdout or stderr of `output` holds any of `secrets` raw, in hex (either case), in
/// standard or URL-safe base64 (padded or not), or, for PEM text, any body line of 16 or more
/// characters. The panic names the stream and the form, never the secret.
pub fn assert_no_secrets(output: &Output, secrets: &[&[u8]]) {
    for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        for (i, secret) in secrets.iter().enumerate() {
            for (form, needle) in forms(secret) {
                assert!(
                    !contains(bytes, &needle),
                    "{stream} holds secret #{i} ({form} form)"
                );
            }
        }
    }
}

/// The instrument's own check: the scan fires on every form it claims to look for.
pub fn self_check_secret_scan() {
    let secret = b"line-one-of-a-secret-body\nline-two-of-a-secret-body\n";
    for (form, needle) in forms(secret) {
        let output = Output {
            status: std::process::ExitStatus::default(),
            stdout: [b"before ".as_slice(), &needle, b" after"].concat(),
            stderr: Vec::new(),
        };
        let hit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_no_secrets(&output, &[secret])
        }));
        assert!(hit.is_err(), "the scan misses the {form} form");
    }
    let clean = Output {
        status: std::process::ExitStatus::default(),
        stdout: b"nothing to see".to_vec(),
        stderr: Vec::new(),
    };
    assert_no_secrets(&clean, &[secret]);
}

/// The value after `prefix` on the line of `text` that starts with it.
pub fn field(text: &str, prefix: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("no `{prefix}` line in the output"))
        .trim()
        .to_owned()
}
