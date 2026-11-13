//! Strict JSON (FORMAT.md 3.1, M2-D2). Serde's derive silently ignores a repeated unknown key and
//! keeps the last of a repeated known one, so a typed parse alone leaves a parser differential:
//! this pre-pass walks the very same bytes first and rejects what the format forbids.
//!
//! Rejected: invalid UTF-8, a byte-order mark, a non-object top level, trailing data, a repeated
//! object key at any depth (unknown keys included), nesting beyond 32 and lone surrogate escapes.
//! Number ranges are enforced where an integer is expected ([`crate::digest::U53`]).

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use crate::error::{Error, JsonError, Result, Untrusted};
use crate::limits::MAX_JSON_DEPTH;

const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Runs the strict pre-pass over `bytes`.
pub fn check_strict(bytes: &[u8]) -> Result<()> {
    if bytes.starts_with(&BOM) {
        return Err(JsonError::ByteOrderMark.into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| JsonError::InvalidUtf8)?;
    let reject = Cell::new(None);
    let mut de = serde_json::Deserializer::from_str(text);
    let walk = Walk {
        depth: 1,
        top: true,
        reject: &reject,
    };
    if let Err(err) = walk.deserialize(&mut de) {
        return Err(reject.take().unwrap_or_else(|| classify(&err)).into());
    }
    de.end().map_err(|_| JsonError::TrailingData)?;
    Ok(())
}

/// Strict pre-pass, then the typed parse of the same bytes.
pub fn parse_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    check_strict(bytes)?;
    serde_json::from_slice(bytes).map_err(|err| {
        if err.is_data() {
            Error::Schema(Untrusted::new(&err.to_string()))
        } else {
            classify(&err).into()
        }
    })
}

fn classify(err: &serde_json::Error) -> JsonError {
    let msg = err.to_string();
    if msg.contains("surrogate") {
        JsonError::LoneSurrogate
    } else {
        JsonError::Syntax(Untrusted::new(&msg))
    }
}

/// Walks one value; `reject` carries the typed reason out of serde's untyped error channel.
struct Walk<'c> {
    depth: u32,
    top: bool,
    reject: &'c Cell<Option<JsonError>>,
}

impl Walk<'_> {
    fn fail<E: de::Error>(&self, reason: JsonError) -> E {
        self.reject.set(Some(reason));
        E::custom("rejected by the strict JSON check")
    }

    fn leaf<E: de::Error>(&self) -> Result<(), E> {
        if self.top {
            Err(self.fail(JsonError::NotObject))
        } else {
            Ok(())
        }
    }

    fn enter<E: de::Error>(&self) -> Result<(), E> {
        if self.depth > MAX_JSON_DEPTH {
            Err(self.fail(JsonError::TooDeep {
                max: MAX_JSON_DEPTH,
            }))
        } else {
            Ok(())
        }
    }

    fn child(&self) -> Walk<'_> {
        Walk {
            depth: self.depth + 1,
            top: false,
            reject: self.reject,
        }
    }
}

impl<'de> DeserializeSeed<'de> for Walk<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Walk<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.leaf()
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.leaf()
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.leaf()
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.leaf()
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        self.leaf()
    }
    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        self.leaf()
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.leaf()
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.leaf()?;
        self.enter()?;
        while seq.next_element_seed(self.child())?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        self.enter()?;
        // BTreeSet: no hasher randomness in the core (hard rule 3).
        let mut seen: BTreeSet<String> = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(self.fail(JsonError::DuplicateKey(Untrusted::new(&key))));
            }
            map.next_value_seed(self.child())?;
        }
        Ok(())
    }
}
