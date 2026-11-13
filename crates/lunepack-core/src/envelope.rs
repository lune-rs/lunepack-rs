//! DSSE envelopes (FORMAT.md 2): the pre-authentication encoding, the writer, and opening in the
//! order of FORMAT.md 2.6.
//!
//! Opening is split in two so no payload byte can reach a parser before the signature threshold:
//! [`OpenedEnvelope::open`] runs the checks that need no key (size cap, strict JSON, fields,
//! payload type, signature count and encodings) and keeps the payload private;
//! [`OpenedEnvelope::authenticate`] verifies the signatures against a key ring and only then hands
//! out the payload bytes. The root walk authenticates one envelope against two rings.

use std::fmt;

use serde::de::{Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::digest::Sha256Digest;
use crate::encoding::{base64_decode, base64_encode, hex_decode_array};
use crate::error::{Error, Result};
use crate::json::parse_strict;
use crate::limits::Limits;
use crate::traits::Verifier;
use crate::trust::KeyRing;

/// The four document kinds of format v1 (FORMAT.md 1, 2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadKind {
    /// `root-<k>.json`.
    Root,
    /// `keys.json`.
    Keys,
    /// `feed-<channel>.json`.
    Feed,
    /// `<ver>/<target>.manifest.json`.
    Manifest,
}

impl PayloadKind {
    /// The exact `payloadType` of this kind.
    pub const fn payload_type(self) -> &'static str {
        match self {
            PayloadKind::Root => "application/vnd.lunepack.root.v1+json",
            PayloadKind::Keys => "application/vnd.lunepack.keys.v1+json",
            PayloadKind::Feed => "application/vnd.lunepack.feed.v1+json",
            PayloadKind::Manifest => "application/vnd.lunepack.manifest.v1+json",
        }
    }

    /// The payload's `kind` field.
    pub const fn name(self) -> &'static str {
        match self {
            PayloadKind::Root => "root",
            PayloadKind::Keys => "keys",
            PayloadKind::Feed => "feed",
            PayloadKind::Manifest => "manifest",
        }
    }

    /// The document byte cap of this kind (FORMAT.md 4).
    pub const fn doc_cap(self, limits: &Limits) -> u64 {
        match self {
            PayloadKind::Root => limits.root_doc_bytes,
            PayloadKind::Keys => limits.keys_doc_bytes,
            PayloadKind::Feed => limits.feed_doc_bytes,
            PayloadKind::Manifest => limits.manifest_doc_bytes,
        }
    }
}

/// `PAE(payload_type, payload)` = `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`
/// (FORMAT.md 2.3). Signatures are made and verified over these bytes.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let head = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut out = Vec::with_capacity(head.len() + payload.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(payload);
    out
}

/// One signature of an envelope: the signing key's id and the 64 signature bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeSignature {
    /// The key id (SHA-256 of the public key).
    pub keyid: Sha256Digest,
    /// The signature over `pae(payload_type, payload)`.
    pub sig: [u8; 64],
}

/// The envelope writer: serialises `payload_type`, the base64 of `payload` and `signatures` as a
/// DSSE JSON envelope. It writes what it is given; a caller wanting a valid envelope signs
/// `pae(payload_type, payload)` and passes the kind's [`PayloadKind::payload_type`].
pub fn write_envelope(
    payload_type: &str,
    payload: &[u8],
    signatures: &[EnvelopeSignature],
) -> Vec<u8> {
    #[derive(Serialize)]
    struct Sig {
        keyid: String,
        sig: String,
    }
    #[derive(Serialize)]
    struct Envelope<'a> {
        #[serde(rename = "payloadType")]
        payload_type: &'a str,
        payload: String,
        signatures: Vec<Sig>,
    }
    let envelope = Envelope {
        payload_type,
        payload: base64_encode(payload),
        signatures: signatures
            .iter()
            .map(|s| Sig {
                keyid: s.keyid.to_hex(),
                sig: base64_encode(&s.sig),
            })
            .collect(),
    };
    // Serialising plain strings into a Vec cannot fail.
    serde_json::to_vec_pretty(&envelope).unwrap_or_default()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureIn {
    keyid: String,
    sig: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeIn {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: String,
    signatures: CappedSignatures,
}

/// The `signatures` array: counts every element but keeps at most `MAX_KEPT`, so a long array
/// costs no memory while the count check still runs in its place in the order (after the type).
struct CappedSignatures {
    kept: Vec<SignatureIn>,
    count: usize,
}

const MAX_KEPT: usize = 16;

impl<'de> Deserialize<'de> for CappedSignatures {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SeqVisitor;
        impl<'de> Visitor<'de> for SeqVisitor {
            type Value = CappedSignatures;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array of signature objects")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut kept = Vec::new();
                let mut count = 0usize;
                loop {
                    if kept.len() < MAX_KEPT {
                        match seq.next_element::<SignatureIn>()? {
                            Some(s) => kept.push(s),
                            None => break,
                        }
                    } else if seq.next_element::<IgnoredAny>()?.is_none() {
                        break;
                    }
                    count += 1;
                }
                Ok(CappedSignatures { kept, count })
            }
        }
        deserializer.deserialize_seq(SeqVisitor)
    }
}

/// An envelope whose key-independent checks passed (FORMAT.md 2.6 steps 1–5). Its payload is
/// reachable only through [`OpenedEnvelope::authenticate`].
pub struct OpenedEnvelope {
    kind: PayloadKind,
    payload: Vec<u8>,
    signatures: Vec<EnvelopeSignature>,
}

impl fmt::Debug for OpenedEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedEnvelope")
            .field("kind", &self.kind)
            .field("payload_len", &self.payload.len())
            .field("signatures", &self.signatures.len())
            .finish()
    }
}

impl OpenedEnvelope {
    /// Steps 1–5 of FORMAT.md 2.6, in order: size cap, strict JSON, envelope fields (unknown
    /// fields rejected), exact `payloadType`, 1 to 16 signatures, then the payload, every `keyid`
    /// and every `sig` decoded.
    pub fn open(bytes: &[u8], kind: PayloadKind, limits: &Limits) -> Result<OpenedEnvelope> {
        let cap = kind.doc_cap(limits);
        let size = bytes.len() as u64;
        if size > cap {
            return Err(Error::TooLarge {
                what: kind.name(),
                size,
                cap,
            });
        }
        let envelope: EnvelopeIn = parse_strict(bytes)?;
        if envelope.payload_type.as_bytes() != kind.payload_type().as_bytes() {
            return Err(Error::PayloadType {
                expected: kind.payload_type(),
            });
        }
        let max = limits.signatures_per_envelope.min(MAX_KEPT);
        let count = envelope.signatures.count;
        if count == 0 || count > max {
            return Err(Error::SignatureCount { count, max });
        }
        let payload_cap = usize::try_from(cap).unwrap_or(usize::MAX);
        let payload = base64_decode(&envelope.payload, payload_cap)?;
        let mut signatures = Vec::with_capacity(count);
        for s in &envelope.signatures.kept {
            let keyid = hex_decode_array::<32>(&s.keyid).map_err(Error::KeyIdSyntax)?;
            // Decode with room for one extra byte so a long signature reports its length.
            let raw = base64_decode(&s.sig, 65)?;
            let sig: [u8; 64] = raw
                .as_slice()
                .try_into()
                .map_err(|_| Error::SignatureLength { len: raw.len() })?;
            signatures.push(EnvelopeSignature {
                keyid: Sha256Digest::from_bytes(keyid),
                sig,
            });
        }
        Ok(OpenedEnvelope {
            kind,
            payload,
            signatures,
        })
    }

    /// The kind this envelope was opened as.
    pub fn kind(&self) -> PayloadKind {
        self.kind
    }

    /// Step 6 of FORMAT.md 2.6: verifies every signature over `PAE(payloadType, payload)` with
    /// the key its `keyid` selects in `ring`, and returns the payload bytes only when at least
    /// `threshold` distinct keys verified. A `keyid` not in the ring and a signature that does not
    /// verify are skipped; a key that signs twice counts once. A threshold of 0 never passes.
    pub fn authenticate(
        &self,
        ring: &KeyRing,
        threshold: usize,
        verifier: &dyn Verifier,
    ) -> Result<&[u8]> {
        let message = pae(self.kind.payload_type(), &self.payload);
        let mut counted: Vec<Sha256Digest> = Vec::new();
        for s in &self.signatures {
            if counted.contains(&s.keyid) {
                continue;
            }
            let Some(key) = ring.get(&s.keyid) else {
                continue;
            };
            if verifier
                .verify(key.alg(), key.public().as_bytes(), &message, &s.sig)
                .is_ok()
            {
                counted.push(s.keyid);
            }
        }
        if threshold == 0 || counted.len() < threshold {
            return Err(Error::Threshold {
                need: threshold,
                got: counted.len(),
            });
        }
        Ok(&self.payload)
    }
}
