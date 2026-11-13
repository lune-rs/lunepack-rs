//! Pure update-framework logic and the traits behind every external or replaceable capability; depends on no adapter or I/O crate.

pub mod digest;
pub mod encoding;
pub mod error;
pub mod json;
pub mod limits;
pub mod traits;

pub use digest::{Sha256Digest, U53};
pub use error::{Error, Result};
pub use limits::Limits;
pub use traits::{
    Clock, Codec, CodecId, DecodeReport, FrameView, HashState, Hasher, SignatureAlg, StreamView,
    Verifier,
};
