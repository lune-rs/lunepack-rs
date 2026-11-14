//! Pure update-framework logic and the traits behind every external or replaceable capability; depends on no adapter or I/O crate.

pub mod cancel;
pub mod digest;
pub mod encoding;
pub mod envelope;
pub mod error;
pub mod feed;
pub mod fetch;
pub mod frame;
pub mod fs;
#[doc(hidden)]
pub mod fuzz;
pub mod ident;
pub mod json;
pub mod keyset;
pub mod limits;
pub mod manifest;
pub mod pack;
pub mod path;
pub mod policy;
pub mod progress;
pub mod root;
pub mod state;
pub mod target;
pub mod traits;
pub mod transport;
pub mod trust;
pub mod version;
pub mod write;

pub use cancel::CancelToken;
pub use digest::{Sha256Digest, U53};
pub use envelope::{EnvelopeSignature, OpenedEnvelope, PayloadKind, pae, write_envelope};
pub use error::{Error, Result, StateError};
pub use feed::{
    ArtifactRef, CheckedRef, FeedDocument, FeedTargetEntry, ReleaseDoc, Rollout, RolloutDoc,
    VerifiedFeed, VerifiedRelease, verify_feed,
};
pub use fetch::{
    ContentRange, FetchPlan, FetchPolicy, Outcome, RangeError, ResponseInfo, Run, check_document,
    plan_fetch,
};
pub use frame::{
    CheckedFrame, FrameDesc, StreamDesc, check_file_frame, decode_verified, decoder_memory,
};
pub use fs::{
    DirEntryInfo, FileKind, FileWrite, Fs, FsError, FsErrorKind, LockGuard, Meta, ReadAt,
};
pub use ident::{AppId, Channel};
pub use keyset::{KeySetDocument, ReleaseKeyEntry, VerifiedKeySet, verify_key_set};
pub use limits::Limits;
pub use manifest::{EntryDoc, ManifestDocument, VerifiedEntry, VerifiedManifest, verify_manifest};
pub use pack::{FileClass, PackedFile, ReleaseLayout, candidates, classify, pack_file};
pub use path::{EntryKind, RelPath, validate_path, validate_tree};
pub use policy::{Candidate, in_rollout, rollout_bucket, select_candidate};
pub use progress::{FileProgress, Phase, Progress, Source};
pub use root::{RootDocument, TrustedRoot, advance_root};
pub use state::{
    CurrentRef, Floors, InstallCounters, InstallState, Loaded, MachineScope, PendingRef,
    PreviousRef, Record, RootParts, Scope, StagedRef, UserScope,
};
pub use target::Target;
pub use traits::{
    Clock, CodeSign, Codec, CodecId, DecodeReport, EncodedFrame, EncodedStream, Encoder, FrameView,
    HashState, Hasher, SignatureAlg, Signer, StreamView, Verifier,
};
pub use transport::{
    BlockingResponse, BlockingTransport, Body, BoxFuture, ByteRange, Head, Request, Response,
    Transport, TransportError, TransportErrorKind, Validator,
};
pub use trust::{ClockReading, KeyEntry, KeyRing, PublicKey, RollbackFloor};
pub use version::Version;
pub use write::{
    DEFAULT_FEED_LIFETIME_SECS, next_feed, next_key_set, rollout_seed, rotate_root, sign_envelope,
};
