//! Keeps the examples in `docs/FORMAT.md` honest: every fenced block tagged `json <kind>` parses
//! as that kind with the reader's own checks (`lunepack_core::fuzz::parse_example`), so the
//! document cannot drift from the code unnoticed. Semantics (keys, signatures, bindings) are
//! covered by the verification tests; the examples carry placeholder keys and signatures.

use std::path::Path;

use lunepack_core::fuzz::parse_example;

const KINDS: [&str; 5] = ["envelope", "root", "keys", "feed", "manifest"];

/// `(kind, body, first line number)` of every ```` ```json <kind> ```` block.
fn example_blocks(text: &str) -> Vec<(String, String, usize)> {
    let mut out = Vec::new();
    let mut current: Option<(String, String, usize)> = None;
    for (index, line) in text.lines().enumerate() {
        match &mut current {
            None => {
                if let Some(kind) = line.strip_prefix("```json ") {
                    current = Some((kind.trim().to_owned(), String::new(), index + 2));
                }
            }
            Some((_, body, _)) => {
                if line.starts_with("```") {
                    out.extend(current.take());
                } else {
                    body.push_str(line);
                    body.push('\n');
                }
            }
        }
    }
    assert!(current.is_none(), "an unterminated code block");
    out
}

fn format_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/FORMAT.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn every_format_example_parses_as_its_kind() {
    let blocks = example_blocks(&format_md());
    for kind in KINDS {
        assert!(
            blocks.iter().any(|(k, _, _)| k == kind),
            "docs/FORMAT.md has no ```json {kind} example"
        );
    }
    for (kind, body, line) in &blocks {
        assert!(
            KINDS.contains(&kind.as_str()),
            "line {line}: unknown example kind {kind:?}"
        );
        if let Err(e) = parse_example(kind, body.as_bytes()) {
            panic!("docs/FORMAT.md line {line}: the {kind} example does not parse: {e}");
        }
    }
}

#[test]
fn the_example_check_rejects_a_broken_example() {
    // The instrument: a known-bad document of each kind must fail, or the test above proves nothing.
    for kind in KINDS {
        assert!(
            parse_example(kind, b"{\"format\":2}").is_err(),
            "{kind} accepted a bad document"
        );
    }
    assert!(parse_example("root", br#"{"format":1,"kind":"root","kind":"root"}"#).is_err());
}
