//! Pure update-framework logic and the traits behind every external or replaceable capability; depends on no adapter or I/O crate.

pub mod digest;
pub mod encoding;
pub mod envelope;
pub mod error;
pub mod frame;
pub mod ident;
pub mod json;
pub mod keyset;
pub mod limits;
pub mod path;
pub mod root;
pub mod target;
pub mod traits;
pub mod trust;
pub mod version;

pub use digest::{Sha256Digest, U53};
pub use envelope::{EnvelopeSignature, OpenedEnvelope, PayloadKind, pae, write_envelope};
pub use error::{Error, Result};
pub use frame::{
    CheckedFrame, FrameDesc, StreamDesc, check_file_frame, decode_verified, decoder_memory,
};
pub use ident::{AppId, Channel};
pub use keyset::{KeySetDocument, ReleaseKeyEntry, VerifiedKeySet, verify_key_set};
pub use limits::Limits;
pub use path::{EntryKind, RelPath, validate_path, validate_tree};
pub use root::{RootDocument, TrustedRoot, advance_root};
pub use target::Target;
pub use traits::{
    Clock, Codec, CodecId, DecodeReport, FrameView, HashState, Hasher, SignatureAlg, StreamView,
    Verifier,
};
pub use trust::{ClockReading, KeyEntry, KeyRing, PublicKey, RollbackFloor};
pub use version::Version;
