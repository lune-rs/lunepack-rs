//! Step 6: the Ed25519 signers (file, environment variable, external command), key generation and
//! their refusals, with real crypto. Keys are generated at test time in a temporary directory; no
//! key material is committed, and no test reads a key through a shell.
//!
//! This test has its own `main` (see Cargo.toml): the command-signer tests run this same binary
//! as the helper command (`--sign-helper`), and the environment-signer tests run it as a child
//! process that has the key in its environment (`--env-child`), because the environment of this
//! process cannot be changed without `unsafe`. A helper's stdout must hold its answer and nothing
//! else, which the libtest harness would not allow.

use std::error::Error as StdError;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::panic::catch_unwind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePublicKey};
use lunepack_core::{Error, Signer};
use lunepack_crypto::signer::{MAX_COMMAND_OUTPUT_BYTES, MAX_KEY_FILE_BYTES};
use lunepack_crypto::{
    CommandSigner, Ed25519Signer, Ed25519Verifier, Sha256Hasher, generate_key_file,
};
use lunepack_testkit::run_signer_suite;

const ENV_KEY_VAR: &str = "LUNEPACK_TEST_SIGNING_KEY";

/// The dashes of PEM armour, so no armour line appears as a literal in this file.
const ARMOR: &str = "-----";

type TestFn = fn();

const TESTS: &[(&str, TestFn)] = &[
    ("file_signer_runs_the_signer_suite", file_signer_suite),
    ("generated_key_files", generated_key_files),
    (
        "generate_refuses_an_existing_path",
        generate_refuses_existing,
    ),
    ("key_file_refusals", key_file_refusals),
    ("key_file_permissions", key_file_permissions),
    ("pem_refusals_leak_nothing", pem_refusals),
    ("env_signer_runs_the_signer_suite", env_signer_suite),
    ("env_signer_refusals_leak_nothing", env_signer_refusals),
    ("command_signer_runs_the_signer_suite", command_signer_suite),
    ("command_signer_refusals", command_signer_refusals),
    ("command_signer_spawn_failure", command_signer_spawn_failure),
    ("command_signer_construction", command_signer_construction),
    ("command_signer_never_hangs", command_signer_never_hangs),
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--sign-helper") => return sign_helper(&args[1..]),
        Some("--env-child") => return env_child(&args[1..]),
        _ => {}
    }
    let filters: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let mut failed = Vec::new();
    let mut run = 0;
    for (name, test) in TESTS {
        if !filters.is_empty() && !filters.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        run += 1;
        match catch_unwind(test) {
            Ok(()) => println!("test {name} ... ok"),
            Err(_) => {
                println!("test {name} ... FAILED");
                failed.push(*name);
            }
        }
    }
    println!(
        "test result: {}. {} passed; {} failed",
        if failed.is_empty() { "ok" } else { "FAILED" },
        run - failed.len(),
        failed.len()
    );
    if !failed.is_empty() {
        std::process::exit(1);
    }
}

// ---- secrets and redaction -----------------------------------------------------------------------

/// Every form of a secret that must never appear in an error, a `Debug` or a log: the PEM text and
/// each of its lines and body, the seed or DER in hex and base64.
struct Secrets {
    forms: Vec<(&'static str, String)>,
}

impl Secrets {
    /// From PEM text (and, when it parses, the seed inside it).
    fn from_pem(pem: &str) -> Self {
        let mut forms = vec![("pem text", pem.trim().to_owned())];
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        if body.len() >= 16 {
            forms.push(("pem body", body.clone()));
        }
        for line in pem
            .lines()
            .filter(|l| !l.starts_with("-----") && l.len() >= 16)
        {
            forms.push(("pem line", line.to_owned()));
        }
        if let Ok(der) = STANDARD.decode(&body) {
            forms.extend(Self::bytes(&der).forms);
        }
        if let Ok(key) = SigningKey::from_pkcs8_pem(pem) {
            forms.extend(Self::bytes(&key.to_bytes()).forms);
        }
        Secrets { forms }
    }

    fn bytes(bytes: &[u8]) -> Self {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Secrets {
            forms: vec![
                ("hex", hex.clone()),
                ("HEX", hex.to_uppercase()),
                ("base64", STANDARD.encode(bytes)),
                ("base64 unpadded", STANDARD_NO_PAD.encode(bytes)),
                ("base64url", URL_SAFE.encode(bytes)),
                ("base64url unpadded", URL_SAFE_NO_PAD.encode(bytes)),
            ],
        }
    }

    /// Panics if `text` holds any form; the panic names the form and `context`, never the text.
    fn assert_absent(&self, text: &str, context: &str) {
        for (label, form) in &self.forms {
            assert!(
                form.is_empty() || !text.contains(form.as_str()),
                "{context}: the {label} form of a secret is in the output"
            );
        }
    }
}

/// Every way an error can be printed: Display with its causes, Debug, and pretty Debug.
fn error_text(error: &Error) -> String {
    let mut out = format!("{error} | {error:?} | {error:#?}");
    let mut next = error.source();
    while let Some(cause) = next {
        out.push_str(&format!(" | {cause} | {cause:?}"));
        next = cause.source();
    }
    out
}

/// The Display chain only: what a user sees.
fn display_chain(error: &Error) -> String {
    let mut out = error.to_string();
    let mut next = error.source();
    while let Some(cause) = next {
        out.push_str(&format!(": {cause}"));
        next = cause.source();
    }
    out
}

// ---- fixtures ------------------------------------------------------------------------------------

struct Fixture {
    dir: tempfile::TempDir,
    key_path: PathBuf,
    pem: String,
    seed: [u8; 32],
    public_key: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let generated = generate_key_file(&dir.path().join("signing")).expect("key generation");
        let pem = fs::read_to_string(&generated.path).expect("read the generated key");
        let seed = SigningKey::from_pkcs8_pem(&pem)
            .expect("the generated PEM parses")
            .to_bytes();
        Fixture {
            dir,
            key_path: generated.path,
            pem,
            seed,
            public_key: generated.public_key,
        }
    }

    fn secrets(&self) -> Secrets {
        Secrets::from_pem(&self.pem)
    }

    fn file_signer(&self) -> Ed25519Signer {
        Ed25519Signer::from_key_file(&self.key_path).expect("load the generated key")
    }

    fn command(&self, mode: &str) -> CommandSigner {
        self.command_with(mode, &self.key_path, None)
    }

    fn command_with(&self, mode: &str, key: &Path, other: Option<&Path>) -> CommandSigner {
        let mut argv = vec![
            exe().display().to_string(),
            "--sign-helper".to_owned(),
            mode.to_owned(),
            key.display().to_string(),
        ];
        if let Some(other) = other {
            argv.push(other.display().to_string());
        }
        CommandSigner::new(argv, self.public_key).expect("a valid command signer")
    }
}

fn exe() -> PathBuf {
    std::env::current_exe().expect("this test's path")
}

fn write_key_file(path: &Path, contents: &[u8], mode: u32) {
    // Replace, not rewrite: the file may be read-only from the previous call.
    let _ = fs::remove_file(path);
    fs::write(path, contents).expect("write");
    set_mode(path, mode);
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) {}

// ---- file signer ---------------------------------------------------------------------------------

fn file_signer_suite() {
    let fx = Fixture::new();
    // The instrument first: the leak check must fire on every form it looks for.
    let secrets = fx.secrets();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for (label, form) in &secrets.forms {
        let probe = format!("prefix {form} suffix");
        assert!(
            catch_unwind(|| secrets.assert_absent(&probe, "self-check")).is_err(),
            "the leak check misses the {label} form"
        );
    }
    assert!(secrets.forms.len() >= 8);
    assert!(catch_unwind(|| secrets.assert_absent("nothing secret here", "self-check")).is_ok());
    std::panic::set_hook(hook);

    let signer = fx.file_signer();
    run_signer_suite(&signer, &Ed25519Verifier, &fx.seed);
    assert_eq!(signer.public_key(), fx.public_key);
    assert_eq!(
        signer.public_key_hex(),
        fx.public_key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let id = {
        use lunepack_core::Hasher;
        Sha256Hasher.sha256(&fx.public_key).to_hex()
    };
    assert_eq!(signer.key_id_hex(), id);
    let shown = format!("{signer:?}");
    assert!(shown.contains(&id), "Debug shows the key id");
    fx.secrets()
        .assert_absent(&shown, "Debug of the file signer");

    // The same key from its PEM text.
    let from_text = Ed25519Signer::from_pkcs8_pem(&fx.pem).unwrap();
    assert_eq!(from_text.public_key(), fx.public_key);
    assert_eq!(
        from_text.sign(b"m").unwrap(),
        signer.sign(b"m").unwrap(),
        "Ed25519 signatures are deterministic"
    );
}

fn generated_key_files() {
    let dir = tempfile::tempdir().unwrap();
    // No extension: `.key` is appended.
    let bare = generate_key_file(&dir.path().join("release")).unwrap();
    assert_eq!(bare.path, dir.path().join("release.key"));
    assert!(bare.path.is_file());
    // An extension is kept.
    let with_ext = generate_key_file(&dir.path().join("ci.p8")).unwrap();
    assert_eq!(with_ext.path, dir.path().join("ci.p8"));
    assert_ne!(
        bare.public_key, with_ext.public_key,
        "fresh randomness each time"
    );

    let pem = fs::read_to_string(&bare.path).unwrap();
    assert!(pem.starts_with(&format!("{ARMOR}BEGIN PRIVATE KEY{ARMOR}\n")));
    assert!(pem.ends_with(&format!("{ARMOR}END PRIVATE KEY{ARMOR}\n")));
    assert!(!pem.contains('\r'), "LF line endings");
    let key = SigningKey::from_pkcs8_pem(&pem).unwrap();
    assert_eq!(key.verifying_key().to_bytes(), bare.public_key);
    // The returned value prints its public key and path, not the key.
    Secrets::from_pem(&pem).assert_absent(&format!("{bare:?}"), "Debug of GeneratedKey");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&bare.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "created with mode 0600");
    }
    // It loads straight back (permissions pass the loader's check).
    Ed25519Signer::from_key_file(&bare.path).unwrap();

    // A missing directory is an error, and leaves nothing behind.
    assert!(generate_key_file(&dir.path().join("missing").join("k")).is_err());
}

fn generate_refuses_existing() {
    let dir = tempfile::tempdir().unwrap();
    // The exact path.
    let taken = dir.path().join("taken.pem");
    write_key_file(&taken, b"keep me", 0o600);
    let e = generate_key_file(&taken).unwrap_err();
    assert!(
        display_chain(&e).contains("already exists"),
        "{}",
        display_chain(&e)
    );
    assert_eq!(fs::read(&taken).unwrap(), b"keep me", "left untouched");

    // The path after `.key` was appended.
    let taken_key = dir.path().join("name.key");
    write_key_file(&taken_key, b"keep me too", 0o600);
    assert!(generate_key_file(&dir.path().join("name")).is_err());
    assert_eq!(fs::read(&taken_key).unwrap(), b"keep me too");

    // A directory, and a dangling or live symlink, are not overwritten either.
    let sub = dir.path().join("sub.d");
    fs::create_dir(&sub).unwrap();
    assert!(generate_key_file(&sub).is_err());
    #[cfg(unix)]
    {
        let target = dir.path().join("victim");
        fs::write(&target, b"victim").unwrap();
        let link = dir.path().join("link.k");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(generate_key_file(&link).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"victim");
        let dangling = dir.path().join("dangling.k");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert!(generate_key_file(&dangling).is_err());
        assert!(
            !dir.path().join("nowhere").exists(),
            "no file created through the link"
        );
    }
}

fn key_file_refusals() {
    let fx = Fixture::new();
    let dir = fx.dir.path();
    let secrets = fx.secrets();
    let check = |path: &Path, expect: &str, context: &str| {
        let e = Ed25519Signer::from_key_file(path).expect_err(context);
        let shown = display_chain(&e);
        assert!(shown.contains(expect), "{context}: {shown}");
        secrets.assert_absent(&error_text(&e), context);
        e
    };

    // Missing, a directory, empty, not UTF-8, garbage, over the cap.
    let missing = dir.join("absent.k");
    let e = check(&missing, "absent.k", "missing file names the path");
    assert!(
        error_text(&e).contains("NotFound"),
        "the io error is kept as the cause"
    );
    check(dir, "not a regular file", "a directory");
    let empty = dir.join("empty.k");
    write_key_file(&empty, b"", 0o600);
    check(&empty, "not a PKCS#8 Ed25519 private key", "an empty file");
    let binary = dir.join("binary.k");
    write_key_file(&binary, &[0xff, 0xfe, 0x00, 0x80], 0o600);
    check(&binary, "not UTF-8", "a binary file");
    let garbage = dir.join("garbage.k");
    write_key_file(
        &garbage,
        format!("{ARMOR}BEGIN PRIVATE KEY{ARMOR}\nAAAA\n{ARMOR}END PRIVATE KEY{ARMOR}\n")
            .as_bytes(),
        0o600,
    );
    check(&garbage, "not a PKCS#8 Ed25519 private key", "a short PEM");

    // Over the cap by one byte; at the cap the PEM still has to parse (it does not, it is padding).
    let over = dir.join("over.k");
    let mut padded = fx.pem.clone().into_bytes();
    padded.resize(MAX_KEY_FILE_BYTES as usize + 1, b'\n');
    write_key_file(&over, &padded, 0o600);
    check(&over, "over 16 KiB", "one byte over the cap");
    padded.truncate(MAX_KEY_FILE_BYTES as usize);
    let at = dir.join("at.k");
    write_key_file(&at, &padded, 0o600);
    // Trailing newlines after the END line: accepted or refused, but never over-read.
    let _ = Ed25519Signer::from_key_file(&at);
}

#[cfg(unix)]
fn key_file_permissions() {
    let fx = Fixture::new();
    let secrets = fx.secrets();
    let readable = fx.dir.path().join("readable.k");
    for mode in [0o644, 0o640, 0o604, 0o660, 0o666, 0o604, 0o620] {
        write_key_file(&readable, fx.pem.as_bytes(), mode);
        let e = Ed25519Signer::from_key_file(&readable).expect_err("group/other-accessible");
        let shown = display_chain(&e);
        assert!(
            shown.contains("readable.k"),
            "{mode:o}: names the path: {shown}"
        );
        assert!(shown.contains("chmod 600"), "{mode:o}: {shown}");
        secrets.assert_absent(&error_text(&e), "permission refusal");
    }
    for mode in [0o600, 0o400, 0o700] {
        write_key_file(&readable, fx.pem.as_bytes(), mode);
        Ed25519Signer::from_key_file(&readable).unwrap_or_else(|e| panic!("{mode:o}: {e}"));
    }
}

#[cfg(not(unix))]
fn key_file_permissions() {}

fn pem_refusals() {
    let fx = Fixture::new();
    let body: String = fx.pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = STANDARD.decode(&body).unwrap();
    let wrap = |label: &str, der: &[u8]| {
        let b64 = STANDARD.encode(der);
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "{ARMOR}BEGIN {label}{ARMOR}\n{}\n{ARMOR}END {label}{ARMOR}\n",
            lines.join("\n")
        )
    };

    // Same structure, but the algorithm OID is X25519 (1.3.101.110) instead of Ed25519 (.112).
    let mut x25519 = der.clone();
    let at = x25519
        .windows(5)
        .position(|w| w == [0x06, 0x03, 0x2b, 0x65, 0x70])
        .expect("the Ed25519 OID is in the DER");
    x25519[at + 4] = 0x6e;

    let public = SigningKey::from_pkcs8_pem(&fx.pem)
        .unwrap()
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    let cut = fx.pem.len() - 40;
    let cases: Vec<(&str, String)> = vec![
        ("empty string", String::new()),
        ("garbage", "this is not a key at all".to_owned()),
        ("x25519 key", wrap("PRIVATE KEY", &x25519)),
        ("wrong label", wrap("RSA PRIVATE KEY", &der)),
        ("public key", public),
        ("truncated", fx.pem[..cut].to_owned()),
        ("body only", body.clone()),
        ("der in the wrong armour", wrap("CERTIFICATE", &der)),
        ("one byte short", wrap("PRIVATE KEY", &der[..der.len() - 1])),
    ];
    for (name, text) in cases {
        let e = Ed25519Signer::from_pkcs8_pem(&text).expect_err(name);
        let shown = display_chain(&e);
        assert!(
            shown.contains("not a PKCS#8 Ed25519 private key"),
            "{name}: {shown}"
        );
        // What went in (a mutated copy) and the real key must both stay out.
        Secrets::from_pem(&text).assert_absent(&error_text(&e), name);
        fx.secrets().assert_absent(&error_text(&e), name);
    }
}

// ---- environment signer (child process) ----------------------------------------------------------

fn run_child(mode: &str, env: &[(&str, OsString)]) {
    let mut child = Command::new(exe());
    child.arg("--env-child").arg(mode).stdin(Stdio::null());
    for (k, v) in env {
        child.env(k, v);
    }
    let output = child.output().expect("start the child");
    assert!(
        output.status.success(),
        "env child {mode} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn env_signer_suite() {
    let fx = Fixture::new();
    run_child("ok", &[(ENV_KEY_VAR, fx.pem.clone().into())]);
}

fn env_signer_refusals() {
    let fx = Fixture::new();
    // Unset (the child's environment holds the key variable under another name only).
    run_child("unset", &[("LUNEPACK_TEST_OTHER", fx.pem.clone().into())]);
    run_child(
        "garbage",
        &[(ENV_KEY_VAR, "SENTINEL-not-a-key-3f9a".into())],
    );
    run_child(
        "garbage",
        &[(ENV_KEY_VAR, fx.pem[..fx.pem.len() - 40].into())],
    );
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = b"SENTINEL-bytes-77".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        run_child("non-utf8", &[(ENV_KEY_VAR, OsString::from_vec(bytes))]);
    }
}

fn env_child(args: &[String]) {
    let mode = args[0].as_str();
    let value = std::env::var_os(ENV_KEY_VAR);
    let value_text = value.as_ref().map(|v| v.to_string_lossy().into_owned());
    match mode {
        "ok" => {
            let pem = value_text.expect("the parent sets the key variable");
            let signer = Ed25519Signer::from_env(ENV_KEY_VAR).expect("load from the environment");
            let seed = SigningKey::from_pkcs8_pem(&pem).unwrap().to_bytes();
            run_signer_suite(&signer, &Ed25519Verifier, &seed);
            Secrets::from_pem(&pem)
                .assert_absent(&format!("{signer:?}"), "Debug of the env signer");
        }
        "unset" => {
            assert!(value.is_none());
            let e = Ed25519Signer::from_env(ENV_KEY_VAR).expect_err("unset variable");
            let shown = display_chain(&e);
            assert!(shown.contains(ENV_KEY_VAR), "names the variable: {shown}");
        }
        "garbage" | "non-utf8" => {
            let value = value.expect("set by the parent");
            let e = Ed25519Signer::from_env(ENV_KEY_VAR).expect_err("bad value");
            let shown = display_chain(&e);
            assert!(shown.contains(ENV_KEY_VAR), "names the variable: {shown}");
            let text = error_text(&e);
            assert!(!text.contains("SENTINEL"), "the value is in the error");
            let lossy = value.to_string_lossy().into_owned();
            Secrets::from_pem(&lossy).assert_absent(&text, mode);
            if lossy.len() >= 8 {
                assert!(!text.contains(lossy.as_str()), "the value is in the error");
            }
        }
        other => panic!("unknown env-child mode {other}"),
    }
}

// ---- command signer ------------------------------------------------------------------------------

fn command_signer_suite() {
    let fx = Fixture::new();
    for mode in ["ok", "ok-noeol"] {
        let signer = fx.command(mode);
        run_signer_suite(&signer, &Ed25519Verifier, &fx.seed);
        assert_eq!(signer.public_key(), fx.public_key);
        // Debug shows the key id only: not the program, not the arguments (the key path).
        let shown = format!("{signer:?}");
        assert!(!shown.contains("sign-helper"), "{shown}");
        assert!(!shown.contains(fx.key_path.to_str().unwrap()), "{shown}");
        fx.secrets()
            .assert_absent(&shown, "Debug of the command signer");
    }
}

fn command_signer_refusals() {
    let fx = Fixture::new();
    let other = {
        let g = generate_key_file(&fx.dir.path().join("other")).unwrap();
        g.path
    };
    let program = exe().display().to_string();
    let key_arg = fx.key_path.display().to_string();
    let message = b"DSSEv1 some message";

    let cases: &[(&str, &str)] = &[
        ("exit1", "exit"),
        ("valid-exit3", "3"),
        ("big", "4096"),
        ("upper", "128 lowercase hex"),
        ("short", "128 lowercase hex"),
        ("long", "128 lowercase hex"),
        ("nonhex", "128 lowercase hex"),
        ("crlf", "128 lowercase hex"),
        ("double-nl", "128 lowercase hex"),
        ("empty", "128 lowercase hex"),
        ("other-message", "does not verify"),
        ("other-key", "does not verify"),
        ("zero-sig", "does not verify"),
    ];
    for (mode, expect) in cases {
        let signer = fx.command_with(mode, &fx.key_path, Some(&other));
        let e = signer.sign(message).expect_err(mode);
        let shown = display_chain(&e);
        assert!(shown.contains(&program), "{mode}: names argv[0]: {shown}");
        assert!(shown.contains(expect), "{mode}: {shown}");
        let all = error_text(&e);
        assert!(
            !all.contains(&key_arg),
            "{mode}: an argument is in the error"
        );
        assert!(
            !all.contains("sign-helper"),
            "{mode}: an argument is in the error"
        );
        fx.secrets().assert_absent(&all, mode);
    }

    // The cap itself: exactly 4096 bytes that are not a signature fails as a bad signature, 4097
    // as over the cap.
    assert_eq!(MAX_COMMAND_OUTPUT_BYTES, 4096);
    let at_cap = fx.command_with("at-cap", &fx.key_path, None);
    let shown = display_chain(&at_cap.sign(message).unwrap_err());
    assert!(shown.contains("128 lowercase hex"), "{shown}");
}

fn command_signer_spawn_failure() {
    let fx = Fixture::new();
    let missing = fx.dir.path().join("no-such-program");
    let signer = CommandSigner::new(
        vec![
            missing.display().to_string(),
            "arg-with-config-value".to_owned(),
        ],
        fx.public_key,
    )
    .unwrap();
    let e = signer.sign(b"m").unwrap_err();
    let shown = display_chain(&e);
    assert!(shown.contains("no-such-program"), "{shown}");
    assert!(!error_text(&e).contains("arg-with-config-value"));
    // The io::Error is kept as a cause.
    let mut found = None;
    let mut next = e.source();
    while let Some(cause) = next {
        if let Some(io) = cause.downcast_ref::<io::Error>() {
            found = Some(io.kind());
        }
        next = cause.source();
    }
    assert_eq!(found, Some(io::ErrorKind::NotFound));
}

fn command_signer_construction() {
    let fx = Fixture::new();
    assert!(CommandSigner::new(Vec::new(), fx.public_key).is_err());
    assert!(CommandSigner::new(vec![String::new()], fx.public_key).is_err());
    // The identity point is small-order: not a key to sign for.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(CommandSigner::new(vec!["x".to_owned()], identity).is_err());
    CommandSigner::new(vec!["x".to_owned()], fx.public_key).unwrap();
}

fn command_signer_never_hangs() {
    let fx = Fixture::new();
    // A command that never reads its 1 MiB input and exits: the writer must not block the signer.
    let big = vec![0x42u8; 1024 * 1024];
    assert!(fx.command("exit1").sign(&big).is_err());
    // A command that never stops writing: stopped at the cap.
    assert!(fx.command("flood").sign(b"m").is_err());
    // Both at once with a message larger than any pipe buffer: the command blocks on a full
    // stdout while the writer blocks on a full stdin, unless the signer stops the command first.
    assert!(fx.command("flood").sign(&big).is_err());
    // A command that reads everything and answers late is fine (covered by the suite's 1 MiB).
}

// ---- the helper command --------------------------------------------------------------------------

/// `--sign-helper <mode> <key file> [<other key file>]`: reads stdin, answers on stdout.
fn sign_helper(args: &[String]) {
    let mode = args[0].as_str();
    let signer = Ed25519Signer::from_key_file(Path::new(&args[1])).expect("helper key");
    let out = io::stdout();
    let print = |text: &[u8]| {
        let mut out = out.lock();
        let _ = out.write_all(text);
        let _ = out.flush();
    };
    if mode == "exit1" {
        std::process::exit(1);
    }
    if mode == "flood" {
        let chunk = [b'a'; 65536];
        let mut out = out.lock();
        while out.write_all(&chunk).is_ok() {}
        return;
    }
    let mut message = Vec::new();
    io::stdin().read_to_end(&mut message).expect("read stdin");
    let hex = |sig: [u8; 64]| sig.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let sig = hex(signer.sign(&message).unwrap());
    match mode {
        "ok" => print(format!("{sig}\n").as_bytes()),
        "ok-noeol" => print(sig.as_bytes()),
        "valid-exit3" => {
            print(sig.as_bytes());
            std::process::exit(3);
        }
        "big" => print(&vec![b'a'; MAX_COMMAND_OUTPUT_BYTES + 1]),
        "at-cap" => print(&vec![b'a'; MAX_COMMAND_OUTPUT_BYTES]),
        "upper" => print(sig.to_uppercase().as_bytes()),
        "short" => print(&sig.as_bytes()[..127]),
        "long" => print(format!("{sig}0").as_bytes()),
        "nonhex" => print(&[b'g'; 128]),
        "crlf" => print(format!("{sig}\r\n").as_bytes()),
        "double-nl" => print(format!("{sig}\n\n").as_bytes()),
        "empty" => {}
        "zero-sig" => print(&[b'0'; 128]),
        "other-message" => {
            let mut changed = message.clone();
            changed.push(b'x');
            print(hex(signer.sign(&changed).unwrap()).as_bytes());
        }
        "other-key" => {
            let other = Ed25519Signer::from_key_file(Path::new(&args[2])).expect("other key");
            print(hex(other.sign(&message).unwrap()).as_bytes());
        }
        other => panic!("unknown helper mode {other}"),
    }
}
