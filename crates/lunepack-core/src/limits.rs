//! The size and count caps of FORMAT.md section 4. Readers enforce them before the work they bound.

use crate::frame::MAX_DICT_SIZE;

// `Limits::V1.lzma2_dict_bytes` is `MAX_DICT_SIZE`; it must fit the `u32` field.
const _: () = assert!(MAX_DICT_SIZE <= u32::MAX as u64);

/// Largest integer a document may carry: 2^53 - 1 (FORMAT.md 3.1).
pub const MAX_JSON_INT: u64 = (1 << 53) - 1;

/// Deepest JSON nesting a document may have; the top-level object is depth 1 (FORMAT.md 3.1).
pub const MAX_JSON_DEPTH: u32 = 32;

/// The caps of one format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `root-<k>.json` document bytes.
    pub root_doc_bytes: u64,
    /// `keys.json` document bytes.
    pub keys_doc_bytes: u64,
    /// `feed-<channel>.json` document bytes.
    pub feed_doc_bytes: u64,
    /// `<ver>/<target>.manifest.json` document bytes.
    pub manifest_doc_bytes: u64,
    /// Signatures per envelope.
    pub signatures_per_envelope: usize,
    /// Keys in a root.
    pub root_keys: usize,
    /// Release keys in a key set.
    pub release_keys: usize,
    /// Releases in a feed.
    pub releases_per_feed: usize,
    /// Entries in a manifest.
    pub manifest_entries: usize,
    /// LZMA2 dictionary bytes per stream.
    pub lzma2_dict_bytes: u32,
    /// JSON nesting depth.
    pub json_depth: u32,
}

impl Limits {
    /// The caps of format v1 (FORMAT.md section 4).
    pub const V1: Limits = Limits {
        root_doc_bytes: 64 * 1024,
        keys_doc_bytes: 64 * 1024,
        feed_doc_bytes: 8 * 1024 * 1024,
        manifest_doc_bytes: 64 * 1024 * 1024,
        signatures_per_envelope: 16,
        root_keys: 16,
        release_keys: 64,
        releases_per_feed: 10_000,
        manifest_entries: 200_000,
        lzma2_dict_bytes: MAX_DICT_SIZE as u32,
        json_depth: MAX_JSON_DEPTH,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Limits::V1
    }
}
