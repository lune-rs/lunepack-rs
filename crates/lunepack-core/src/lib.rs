//! Pure update-framework logic and the traits behind every external or replaceable capability; depends on no adapter or I/O crate.

pub mod digest;
pub mod encoding;
pub mod error;
pub mod ident;
pub mod json;
pub mod limits;
pub mod path;
pub mod target;
pub mod traits;
pub mod version;

pub use digest::{Sha256Digest, U53};
pub use error::{Error, Result};
pub use ident::{AppId, Channel};
pub use limits::Limits;
pub use path::{EntryKind, RelPath, validate_path, validate_tree};
pub use target::Target;
pub use traits::{
    Clock, Codec, CodecId, DecodeReport, FrameView, HashState, Hasher, SignatureAlg, StreamView,
    Verifier,
};
pub use version::Version;
