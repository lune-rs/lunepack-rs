//! Step 4 contract: strict JSON, encodings, digest and integer types, error text, traits, purity.

use std::fs;
use std::io::Write;
use std::path::Path;

use lunepack_core::digest::{Sha256Digest, U53};
use lunepack_core::encoding::{base64_decode, base64_encode, hex_decode_array, hex_encode};
use lunepack_core::error::{
    Base64Error, CodecError, Error, HexError, IntegerError, JsonError, SignatureError, Untrusted,
};
use lunepack_core::json::{check_strict, parse_strict};
use lunepack_core::limits::{Limits, MAX_JSON_DEPTH, MAX_JSON_INT};
use lunepack_core::traits::{
    Clock, Codec, CodecId, DecodeReport, FrameView, HashState, Hasher, SignatureAlg, Verifier,
};
use serde::Deserialize;

fn json_err(bytes: &[u8]) -> JsonError {
    match check_strict(bytes) {
        Err(Error::Json(e)) => e,
        other => panic!("expected a JSON rejection, got {other:?}"),
    }
}

fn nested_objects(levels: usize) -> String {
    let mut s = String::new();
    for _ in 0..levels {
        s.push_str("{\"a\":");
    }
    s.push('1');
    for _ in 0..levels {
        s.push('}');
    }
    s
}

// ---- strict JSON ----

#[test]
fn json_accepts_plain_document() {
    check_strict(br#" {"a":1,"b":[{"c":"x"},{"c":"y"}],"d":{"e":true,"f":null}} "#).unwrap();
    check_strict(b"{}").unwrap();
}

#[test]
fn json_rejects_duplicate_key_top_level() {
    assert!(matches!(
        json_err(br#"{"a":1,"a":2}"#),
        JsonError::DuplicateKey(_)
    ));
}

#[test]
fn json_rejects_duplicate_key_nested_and_in_array() {
    assert!(matches!(
        json_err(br#"{"x":{"y":{"a":1,"a":2}}}"#),
        JsonError::DuplicateKey(_)
    ));
    assert!(matches!(
        json_err(br#"{"x":[{"ok":1},{"a":1,"a":2}]}"#),
        JsonError::DuplicateKey(_)
    ));
}

#[test]
fn json_rejects_duplicate_unknown_keys_even_when_typed_parse_would_ignore_them() {
    #[derive(Deserialize)]
    struct Known {
        #[allow(dead_code)]
        a: u64,
    }
    let doc = br#"{"a":1,"mystery":1,"mystery":2}"#;
    // Serde alone accepts it (the differential the pre-pass closes) ...
    assert!(serde_json::from_slice::<Known>(doc).is_ok());
    // ... the strict path does not.
    assert!(matches!(
        parse_strict::<Known>(doc),
        Err(Error::Json(JsonError::DuplicateKey(_)))
    ));
}

#[test]
fn json_duplicates_are_compared_after_unescaping_and_case_sensitively() {
    assert!(matches!(
        json_err(br#"{"a":1,"a":2}"#),
        JsonError::DuplicateKey(_)
    ));
    check_strict(br#"{"a":1,"A":2}"#).unwrap();
}

#[test]
fn json_same_document_without_duplicates_is_accepted() {
    #[derive(Deserialize, Debug, PartialEq)]
    struct D {
        a: u64,
        b: u64,
    }
    assert_eq!(
        parse_strict::<D>(br#"{"a":1,"b":2}"#).unwrap(),
        D { a: 1, b: 2 }
    );
}

#[test]
fn json_depth_cap() {
    assert_eq!(MAX_JSON_DEPTH, 32);
    check_strict(nested_objects(32).as_bytes()).unwrap();
    assert!(matches!(
        json_err(nested_objects(33).as_bytes()),
        JsonError::TooDeep { max: 32 }
    ));
    // Arrays count too.
    let arr = |levels: usize| format!("{{\"a\":{}1{}}}", "[".repeat(levels), "]".repeat(levels));
    check_strict(arr(31).as_bytes()).unwrap();
    assert!(matches!(
        json_err(arr(32).as_bytes()),
        JsonError::TooDeep { .. }
    ));
    // Far deeper than serde_json's own limit still ends in a typed rejection, not a stack problem.
    assert!(matches!(
        json_err(nested_objects(5000).as_bytes()),
        JsonError::TooDeep { .. }
    ));
}

#[test]
fn json_rejects_invalid_utf8_and_bom() {
    assert!(matches!(
        json_err(b"{\"a\":\"\xff\"}"),
        JsonError::InvalidUtf8
    ));
    assert!(matches!(
        json_err(b"\xef\xbb\xbf{\"a\":1}"),
        JsonError::ByteOrderMark
    ));
}

#[test]
fn json_rejects_trailing_data_and_non_object_top_level() {
    assert!(matches!(json_err(br#"{"a":1} x"#), JsonError::TrailingData));
    assert!(matches!(
        json_err(br#"{"a":1}{"a":1}"#),
        JsonError::TrailingData
    ));
    check_strict(b"{\"a\":1}\n\t \r\n").unwrap();
    for doc in [&b"[1]"[..], b"1", b"\"x\"", b"null", b"true"] {
        assert!(matches!(json_err(doc), JsonError::NotObject), "{doc:?}");
    }
    assert!(matches!(json_err(b""), JsonError::Syntax(_)));
}

#[test]
fn json_rejects_lone_surrogates() {
    for doc in [
        &br#"{"a":"\ud800"}"#[..],
        br#"{"a":"\udc00"}"#,
        br#"{"a":"\ud800x"}"#,
        br#"{"\ud800":1}"#,
        br#"{"a":"\udc00\ud800"}"#,
    ] {
        // serde_json words a lone leading surrogate as a malformed hex escape, so the class
        // varies; the contract is the rejection.
        assert!(
            matches!(
                json_err(doc),
                JsonError::LoneSurrogate | JsonError::Syntax(_)
            ),
            "{}",
            String::from_utf8_lossy(doc)
        );
    }
    assert!(matches!(
        json_err(br#"{"a":"\udc00"}"#),
        JsonError::LoneSurrogate
    ));
    // A proper pair is fine.
    check_strict(br#"{"a":"\ud83d\ude00"}"#).unwrap();
}

#[test]
fn json_typed_parse_sees_the_same_bytes() {
    #[derive(Deserialize, Debug, PartialEq)]
    struct D {
        s: String,
    }
    // Escapes decode identically in both passes.
    assert_eq!(parse_strict::<D>(br#"{"s":"ab\n"}"#).unwrap().s, "ab\n");
    // A shape error is a Schema rejection, a malformed document stays a JSON rejection.
    assert!(matches!(
        parse_strict::<D>(br#"{"s":1}"#),
        Err(Error::Schema(_))
    ));
    assert!(matches!(
        parse_strict::<D>(br#"{"s":"x""#),
        Err(Error::Json(JsonError::Syntax(_)))
    ));
}

// ---- integers ----

#[derive(Deserialize, Debug)]
struct Int {
    n: U53,
}

fn int(text: &str) -> Result<U53, Error> {
    parse_strict::<Int>(format!("{{\"n\":{text}}}").as_bytes()).map(|v| v.n)
}

#[test]
fn integer_bounds() {
    assert_eq!(MAX_JSON_INT, 9_007_199_254_740_991);
    assert_eq!(int("0").unwrap().get(), 0);
    assert_eq!(int("9007199254740991").unwrap(), U53::MAX);
    for bad in [
        "9007199254740992",
        "-1",
        "-0",
        "1.0",
        "1e3",
        "1E3",
        "0.5",
        "18446744073709551616",
        "99999999999999999999999",
        "\"1\"",
        "null",
        "true",
    ] {
        assert!(int(bad).is_err(), "{bad} must be rejected");
    }
    assert!(matches!(
        U53::new(1 << 53),
        Err(IntegerError::TooLarge { .. })
    ));
    assert_eq!(U53::new((1 << 53) - 1).unwrap(), U53::MAX);
    assert_eq!(u64::from(U53::MAX), MAX_JSON_INT);
}

// ---- hex ----

#[test]
fn hex_roundtrip_and_rejections() {
    let bytes: [u8; 4] = [0x00, 0x0f, 0xa5, 0xff];
    let text = hex_encode(&bytes);
    assert_eq!(text, "000fa5ff");
    assert_eq!(hex_decode_array::<4>(&text).unwrap(), bytes);
    assert!(matches!(
        hex_decode_array::<4>("000FA5FF"),
        Err(HexError::InvalidCharacter { offset: 3 })
    ));
    assert!(matches!(
        hex_decode_array::<4>("000fa5f"),
        Err(HexError::Length {
            expected: 8,
            actual: 7
        })
    ));
    assert!(hex_decode_array::<4>("000fa5ffa").is_err());
    assert!(hex_decode_array::<4>("000fa5fg").is_err());
    assert!(hex_decode_array::<4>("000fa5f ").is_err());
    assert!(hex_decode_array::<4>("0x0fa5ff").is_err());
    // Non-ASCII bytes cannot slip through the length check as characters.
    assert!(hex_decode_array::<4>("é1é1").is_err());
}

#[test]
fn sha256_digest_hex_rules() {
    let h = "ab".repeat(32);
    let d = Sha256Digest::from_hex(&h).unwrap();
    assert_eq!(d.to_hex(), h);
    assert_eq!(d.to_string(), h);
    assert_eq!(d.as_bytes(), &[0xab; 32]);
    assert!(Sha256Digest::from_hex(&h[..63]).is_err());
    assert!(Sha256Digest::from_hex(&format!("{h}a")).is_err());
    assert!(Sha256Digest::from_hex(&"AB".repeat(32)).is_err());
    // In JSON too.
    #[derive(Deserialize)]
    struct W {
        #[allow(dead_code)]
        sha256: Sha256Digest,
    }
    assert!(parse_strict::<W>(format!("{{\"sha256\":\"{h}\"}}").as_bytes()).is_ok());
    assert!(
        parse_strict::<W>(format!("{{\"sha256\":\"{}\"}}", h.to_uppercase()).as_bytes()).is_err()
    );
    assert!(parse_strict::<W>(format!("{{\"sha256\":\"{}\"}}", &h[..63]).as_bytes()).is_err());
    assert_eq!(serde_json::to_string(&d).unwrap(), format!("\"{h}\""));
}

// ---- base64 ----

#[test]
fn base64_roundtrip_of_writer_output() {
    for len in 0..=40usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let text = base64_encode(&data);
        assert_eq!(text.len() % 4, 0);
        assert_eq!(base64_decode(&text, 64).unwrap(), data, "len {len}");
    }
    assert_eq!(base64_encode(b"Man"), "TWFu");
    assert_eq!(base64_encode(b"Ma"), "TWE=");
    assert_eq!(base64_encode(b"M"), "TQ==");
}

#[test]
fn base64_rejections() {
    // URL-safe alphabet.
    assert!(matches!(
        base64_decode("-_-_", 16),
        Err(Base64Error::InvalidCharacter { .. })
    ));
    assert!(base64_decode("+/+/", 16).is_ok());
    // Missing / extra padding.
    assert!(base64_decode("TQ", 16).is_err());
    assert!(base64_decode("TWE", 16).is_err());
    assert!(base64_decode("TQ===", 16).is_err());
    assert!(base64_decode("TQ=A", 16).is_err());
    assert!(base64_decode("TWFu=", 16).is_err());
    // Non-zero trailing bits: "TR==" would decode to the same byte as "TQ==".
    assert!(matches!(
        base64_decode("TR==", 16),
        Err(Base64Error::TrailingBits)
    ));
    assert!(base64_decode("TWF=", 16).is_err());
    // Whitespace.
    for bad in ["TWFu ", " TWFu", "TW\nFu", "TW Fu", "TWFu\n", "TW\tFu"] {
        assert!(base64_decode(bad, 16).is_err(), "{bad:?}");
    }
    assert_eq!(base64_decode("TWFu", 16).unwrap(), b"Man");
}

#[test]
fn base64_cap_applies_before_and_after_decoding() {
    let big = base64_encode(&[0u8; 100]);
    assert!(matches!(
        base64_decode(&big, 99),
        Err(Base64Error::TooLong { cap: 99 })
    ));
    assert_eq!(base64_decode(&big, 100).unwrap().len(), 100);
    // The text-length bound is checked without decoding anything.
    assert!(matches!(
        base64_decode(&"A".repeat(1_000_000), 10),
        Err(Base64Error::TooLong { .. })
    ));
}

// ---- error text ----

#[test]
fn untrusted_text_is_capped_and_escaped() {
    let long = "x".repeat(10_000);
    let shown = Untrusted::new(&long).to_string();
    assert!(shown.chars().count() <= 64, "{}", shown.chars().count());
    assert!(shown.ends_with("..."));
    assert_eq!(Untrusted::new("short").to_string(), "short");
    // Exactly at the cap stays whole.
    let at_cap = "y".repeat(64);
    assert_eq!(Untrusted::new(&at_cap).to_string(), at_cap);
    assert!(Untrusted::new(&"y".repeat(65)).to_string().ends_with("..."));

    let ctl = Untrusted::new("a\u{0}b\nc\rd\u{1b}[31me\u{7f}f\u{202e}g").to_string();
    for c in ctl.chars() {
        assert!(!c.is_control(), "control char left in {ctl:?}");
        assert_ne!(c, '\u{202e}');
    }
    assert!(ctl.contains("\\n") && ctl.contains("\\r") && ctl.contains("\\u{1b}"));

    // Escapes expand but never push the shown text past the cap.
    let nasty = "\u{1b}".repeat(500);
    assert!(Untrusted::new(&nasty).to_string().chars().count() <= 64);
    // Multi-byte characters are cut on a character boundary.
    assert!(Untrusted::new(&"é".repeat(500)).to_string().chars().count() <= 64);
}

#[test]
fn error_display_never_leaks_long_or_control_input() {
    let key = format!("k\\n{}", "z".repeat(5000));
    let doc = format!("{{\"{key}\":1,\"{key}\":2}}");
    let err = check_strict(doc.as_bytes()).unwrap_err();
    assert!(matches!(err, Error::Json(JsonError::DuplicateKey(_))));
    let text = err.to_string();
    assert!(text.len() < 200, "{} bytes: {text}", text.len());
    assert!(!text.contains('\n'));

    // A serde message that echoes input is capped as well.
    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct Strict {
        #[allow(dead_code)]
        a: u64,
    }
    let bad = format!("{{\"a\":1,\"{}\":1}}", "q".repeat(5000));
    let err = parse_strict::<Strict>(bad.as_bytes()).unwrap_err();
    assert!(matches!(err, Error::Schema(_)));
    assert!(err.to_string().len() < 200, "{err}");
}

#[test]
fn errors_keep_their_cause() {
    use std::error::Error as _;
    let e = Error::Codec(CodecError::Write(std::io::Error::other("disk")));
    let inner = e.source().and_then(|s| s.source());
    assert_eq!(inner.map(ToString::to_string).as_deref(), Some("disk"));
    let e = Error::from(SignatureError::Mismatch);
    assert!(matches!(e, Error::Signature(SignatureError::Mismatch)));
}

// ---- traits ----

#[test]
fn traits_are_object_safe_send_and_sync() {
    fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<dyn Hasher>();
    assert_send_sync::<dyn Verifier>();
    assert_send_sync::<dyn Clock>();
    assert_send_sync::<dyn Codec>();
    fn assert_send<T: ?Sized + Send>() {}
    assert_send::<dyn HashState>();

    struct FixedClock;
    impl Clock for FixedClock {
        fn now_unix_secs(&self) -> u64 {
            42
        }
    }
    struct RejectAll;
    impl Verifier for RejectAll {
        fn verify(
            &self,
            _: SignatureAlg,
            _: &[u8; 32],
            _: &[u8],
            _: &[u8; 64],
        ) -> Result<(), Error> {
            Err(SignatureError::Mismatch.into())
        }
        fn check_public_key(&self, _: SignatureAlg, _: &[u8; 32]) -> Result<(), Error> {
            Err(SignatureError::InvalidPublicKey.into())
        }
    }
    struct NullCodec;
    impl Codec for NullCodec {
        fn decode(&self, f: &FrameView<'_>, out: &mut dyn Write) -> Result<DecodeReport, Error> {
            out.write_all(b"").map_err(CodecError::Write)?;
            Ok(DecodeReport {
                consumed: f.streams.iter().map(|s| s.input.len() as u64).collect(),
            })
        }
    }
    let clock: Box<dyn Clock> = Box::new(FixedClock);
    assert_eq!(clock.now_unix_secs(), 42);
    let v: Box<dyn Verifier> = Box::new(RejectAll);
    assert!(
        v.verify(SignatureAlg::Ed25519, &[0; 32], b"", &[0; 64])
            .is_err()
    );
    let c: Box<dyn Codec> = Box::new(NullCodec);
    let frame = FrameView {
        codec: CodecId::Stored,
        output_size: 0,
        streams: &[],
    };
    let mut sink = Vec::new();
    assert_eq!(
        c.decode(&frame, &mut sink).unwrap().consumed,
        Vec::<u64>::new()
    );
}

#[test]
fn hasher_default_one_shot_uses_the_streaming_state() {
    struct Sum;
    struct SumState(u8);
    impl HashState for SumState {
        fn update(&mut self, data: &[u8]) {
            for b in data {
                self.0 = self.0.wrapping_add(*b);
            }
        }
        fn finalize(self: Box<Self>) -> Sha256Digest {
            Sha256Digest::from_bytes([self.0; 32])
        }
    }
    impl Hasher for Sum {
        fn sha256_start(&self) -> Box<dyn HashState> {
            Box::new(SumState(0))
        }
    }
    let h: &dyn Hasher = &Sum;
    assert_eq!(h.sha256(&[1, 2, 3]), Sha256Digest::from_bytes([6; 32]));
}

#[test]
fn algorithm_and_codec_ids_are_byte_exact() {
    assert_eq!(
        SignatureAlg::from_id("ed25519"),
        Some(SignatureAlg::Ed25519)
    );
    assert_eq!(SignatureAlg::from_id("Ed25519"), None);
    assert_eq!(SignatureAlg::from_id("ed25519 "), None);
    for id in [
        "stored",
        "lzma2",
        "bcj-x86+lzma2",
        "bcj-arm64+lzma2",
        "bcj2",
    ] {
        assert_eq!(CodecId::from_id(id).unwrap().id(), id);
    }
    for id in ["STORED", "Lzma2", "zstd", "bcj", "bcj-x86", ""] {
        assert_eq!(CodecId::from_id(id), None, "{id}");
    }
}

#[test]
fn limits_match_format_section_4() {
    let l = Limits::V1;
    assert_eq!(l, Limits::default());
    assert_eq!(l.root_doc_bytes, 65_536);
    assert_eq!(l.keys_doc_bytes, 65_536);
    assert_eq!(l.feed_doc_bytes, 8_388_608);
    assert_eq!(l.manifest_doc_bytes, 67_108_864);
    assert_eq!(l.signatures_per_envelope, 16);
    assert_eq!(l.root_keys, 16);
    assert_eq!(l.release_keys, 64);
    assert_eq!(l.releases_per_feed, 10_000);
    assert_eq!(l.manifest_entries, 200_000);
    assert_eq!(l.lzma2_dict_bytes, 16_777_216);
    assert_eq!(l.json_depth, 32);
}

// ---- purity (hard rule 3) ----

const FORBIDDEN: &[&str] = &[
    "std::fs",
    "std::env",
    "std::net",
    "std::process",
    "std::thread",
    "thread::",
    "std::time",
    "SystemTime",
    "Instant",
    "RandomState",
    "HashMap",
    "HashSet",
    "getrandom",
    "println!",
    "eprintln!",
    "stdin",
    "stdout",
    "stderr",
    "unsafe",
];

/// The one narrow exception (M4-D12, user decision Q30): budgeted parallel decode in the stage
/// engine uses scoped threads. Exactly these (file, token) pairs; nothing else in `std::thread`.
const ALLOWED: &[(&str, &str)] = &[
    ("stage.rs", "std::thread::scope"),
    ("stage.rs", "std::thread::panicking"),
];

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Remove each allowed token of `file` from `code`, but only where the token is a whole path
/// (not followed by an identifier character) and the line is not a `use` item.
fn without_allowed(file: &str, code: &str) -> String {
    if code.trim_start().starts_with("use ") || code.trim_start().starts_with("pub use ") {
        return code.to_string();
    }
    let mut out = code.to_string();
    for (f, token) in ALLOWED {
        if *f != file {
            continue;
        }
        let mut rest = String::new();
        let mut tail = out.as_str();
        while let Some(at) = tail.find(token) {
            let after = &tail[at + token.len()..];
            rest.push_str(&tail[..at]);
            if after.chars().next().is_some_and(is_ident_char) {
                rest.push_str(token);
            }
            tail = after;
        }
        rest.push_str(tail);
        out = rest;
    }
    out
}

/// The forbidden token found in one line of code of core library file `file` (a file name such as
/// `stage.rs`, comments already removed), if any.
fn forbidden_in_line(file: &str, code: &str) -> Option<&'static str> {
    let code = without_allowed(file, code);
    FORBIDDEN.iter().copied().find(|word| code.contains(word))
}

/// Core library code touches no filesystem, network, process, environment, clock or randomness.
#[test]
fn core_source_has_no_ambient_capabilities() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = 0;
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let file = path.file_name().unwrap().to_str().unwrap().to_string();
        let text = fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if let Some(word) = forbidden_in_line(&file, code) {
                panic!(
                    "{}:{}: `{word}` is forbidden in core library code",
                    path.display(),
                    n + 1
                );
            }
        }
        scanned += 1;
    }
    assert!(scanned >= 7, "scanned only {scanned} files");
}

/// The thread exception is exactly `std::thread::scope` and `std::thread::panicking` in `stage.rs`.
#[test]
fn thread_exception_is_narrow() {
    // allowed, in stage.rs only
    assert_eq!(
        forbidden_in_line("stage.rs", "    std::thread::scope(|s| {"),
        None
    );
    assert_eq!(
        forbidden_in_line("stage.rs", "if self.stop || std::thread::panicking() {"),
        None
    );
    // anything else in stage.rs
    for line in [
        "std::thread::spawn(|| {});",
        "std::thread::sleep(d);",
        "std::thread::scoped_thing();",
        "std::thread::panicking_x();",
        "use std::thread;",
        "use std::thread::scope;",
        "use std::thread::{self, scope};",
        "thread::sleep(d);",
        "std::thread::scope(|s| { std::thread::spawn(f); });",
    ] {
        assert!(forbidden_in_line("stage.rs", line).is_some(), "{line}");
    }
    // the same allowed calls in any other core file
    for file in ["fetch.rs", "state.rs", "lib.rs", "stage2.rs", "mystage.rs"] {
        for line in [
            "std::thread::scope(|s| {",
            "std::thread::panicking()",
            "std::thread::spawn(|| {});",
        ] {
            assert!(forbidden_in_line(file, line).is_some(), "{file}: {line}");
        }
    }
    // unrelated forbidden tokens stay forbidden in stage.rs
    assert!(forbidden_in_line("stage.rs", "let m: HashMap<u8, u8>;").is_some());
    assert!(forbidden_in_line("stage.rs", "std::time::Duration::ZERO").is_some());
}
