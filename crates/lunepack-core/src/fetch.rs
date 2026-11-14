//! The pure HTTP response rules and fetch planning (M4-D8, M4-D9). Every transport's answer goes
//! through these rules before a body byte is read, so a hostile or buggy server, proxy or CDN can
//! only make a fetch fail or fall back to the full pack, never change what is read or where it is
//! written. The rules fail closed: RFC 9110 allows more forms than the ones accepted here, and
//! rejecting the rest costs only a fall back.

use std::fmt;

use crate::limits::MAX_JSON_INT;
use crate::transport::{ByteRange, Head, Validator};

/// Why a response was refused (FORMAT.md 7.1 states the signed sizes the response is held to).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RangeError {
    /// A header that must appear at most once appears more than once.
    #[error("header {name} appears more than once")]
    DuplicateHeader {
        /// The header.
        name: &'static str,
    },
    /// A header value with a byte outside printable ASCII.
    #[error("header {name} is not printable ASCII")]
    HeaderBytes {
        /// The header.
        name: &'static str,
    },
    /// `Content-Range` is not `bytes <first>-<last>/<total>` in the exact form accepted.
    #[error("content-range is not in the accepted form")]
    ContentRangeSyntax,
    /// `Content-Length` is not a plain decimal number.
    #[error("content-length is not a plain decimal number")]
    ContentLengthSyntax,
    /// `Content-Encoding` is something other than `identity`.
    #[error("content-encoding is not identity")]
    ContentCoding,
    /// A `206` without `Content-Range`.
    #[error("206 response without content-range")]
    ContentRangeMissing,
    /// A `Content-Range` on a response that is not a `206`.
    #[error("content-range on a response that is not partial")]
    ContentRangeUnexpected,
    /// `Content-Range` names another range or total than the request and the signed size.
    #[error("content-range {found} does not match the expected {expected}")]
    ContentRangeMismatch {
        /// What the request and the signed size call for.
        expected: ContentRange,
        /// What the response says.
        found: ContentRange,
    },
    /// `Content-Length` differs from the number of bytes expected.
    #[error("content-length {found} differs from the expected {expected}")]
    ContentLength {
        /// The expected byte count.
        expected: u64,
        /// The header's value.
        found: u64,
    },
    /// A document's `Content-Length` is over the document cap.
    #[error("content-length {found} is over the {cap} byte cap")]
    ContentLengthOverCap {
        /// The cap.
        cap: u64,
        /// The header's value.
        found: u64,
    },
    /// A status that this request cannot be answered with.
    #[error("unexpected status {status}")]
    Status {
        /// The status code.
        status: u16,
    },
    /// The caller's numbers contradict each other (a bug in the caller, never the server).
    #[error("inconsistent request: {0}")]
    Inconsistent(&'static str),
}

/// A parsed `Content-Range: bytes <first>-<last>/<total>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentRange {
    /// First byte, inclusive.
    pub first: u64,
    /// Last byte, inclusive.
    pub last: u64,
    /// Complete length of the representation.
    pub total: u64,
}

impl fmt::Display for ContentRange {
    /// The header value, as a server writes it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bytes {}-{}/{}", self.first, self.last, self.total)
    }
}

impl ContentRange {
    /// Parses the header value: the lowercase unit `bytes`, one space, then `first-last/total`, each
    /// 1 to 16 ASCII digits, values at most 2^53 - 1, `first <= last`. `*` forms, other case or
    /// spacing, and anything after the total are refused.
    pub fn parse(value: &[u8]) -> Result<ContentRange, RangeError> {
        let rest = value
            .strip_prefix(b"bytes ")
            .ok_or(RangeError::ContentRangeSyntax)?;
        let dash = rest
            .iter()
            .position(|&b| b == b'-')
            .ok_or(RangeError::ContentRangeSyntax)?;
        let slash = rest
            .iter()
            .position(|&b| b == b'/')
            .ok_or(RangeError::ContentRangeSyntax)?;
        if slash < dash {
            return Err(RangeError::ContentRangeSyntax);
        }
        let first = decimal(&rest[..dash]).ok_or(RangeError::ContentRangeSyntax)?;
        let last = decimal(&rest[dash + 1..slash]).ok_or(RangeError::ContentRangeSyntax)?;
        let total = decimal(&rest[slash + 1..]).ok_or(RangeError::ContentRangeSyntax)?;
        if first > last {
            return Err(RangeError::ContentRangeSyntax);
        }
        Ok(ContentRange { first, last, total })
    }
}

/// 1 to 16 ASCII digits, at most 2^53 - 1.
fn decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || digits.len() > 16 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut value = 0u64;
    for &d in digits {
        value = value * 10 + u64::from(d - b'0');
    }
    (value <= MAX_JSON_INT).then_some(value)
}

/// What the headers of a response say, once the single-valued ones are checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseInfo {
    /// The status code.
    pub status: u16,
    /// The parsed `Content-Range`, when present.
    pub content_range: Option<ContentRange>,
    /// The parsed `Content-Length`, when present.
    pub content_length: Option<u64>,
    /// The validator to send as `If-Range` on a later request: a strong `ETag`, else
    /// `Last-Modified`, else none.
    pub validator: Option<Validator>,
}

/// The one value of a header that may appear at most once, checked to be printable ASCII.
fn single<'a>(head: &'a Head, name: &'static str) -> Result<Option<&'a [u8]>, RangeError> {
    let mut values = head.values(name);
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(RangeError::DuplicateHeader { name });
    }
    if !value.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err(RangeError::HeaderBytes { name });
    }
    Ok(Some(value))
}

impl ResponseInfo {
    /// Applies the header rules of M4-D9: at most one each of `content-range`, `content-length`,
    /// `content-encoding`, `etag` and `last-modified` (a duplicate fails, names compared ASCII
    /// case-insensitively), each printable ASCII, `Content-Range` and `Content-Length` in their exact
    /// forms, and `Content-Encoding` absent or `identity`.
    pub fn from_head(head: &Head) -> Result<ResponseInfo, RangeError> {
        let content_range = single(head, "content-range")?
            .map(ContentRange::parse)
            .transpose()?;
        let content_length = single(head, "content-length")?
            .map(|v| decimal(v).ok_or(RangeError::ContentLengthSyntax))
            .transpose()?;
        match single(head, "content-encoding")? {
            Some(coding) if !coding.eq_ignore_ascii_case(b"identity") => {
                return Err(RangeError::ContentCoding);
            }
            _ => {}
        }
        let etag = single(head, "etag")?;
        let last_modified = single(head, "last-modified")?;
        let validator = etag
            .and_then(Validator::from_etag)
            .or_else(|| last_modified.and_then(Validator::from_last_modified));
        Ok(ResponseInfo {
            status: head.status,
            content_range,
            content_length,
            validator,
        })
    }
}

/// What a response to a pack request is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A `206` for exactly the requested bytes: the body is `first..=last` of the pack.
    Partial {
        /// First byte of the body in the pack.
        first: u64,
        /// Last byte of the body in the pack.
        last: u64,
    },
    /// The whole pack (`200`), whether or not a range was asked for.
    Full,
}

/// Decides what a response to a pack request is (M4-D9), before the body is read.
///
/// - `request_range`: the range that was sent, if any.
/// - `signed_total`: the pack's signed size (`pack.size`).
/// - `expected_len`: the bytes a `206` body must hold, `last - first + 1` of the request (an open
///   range ends at `signed_total - 1`). A `200` body must hold `signed_total` bytes.
///
/// A `206` is accepted only for a range request, with a `Content-Range` whose first, last and total
/// equal the request and the signed size. A `200` is the full pack (it answers a range request
/// when the server ignores the range or the `If-Range` validator no longer matches) and must carry
/// no `Content-Range`. A `Content-Length`, when present, must equal the bytes the body must hold.
/// Every other status is an error, `416` included.
pub fn classify(
    request_range: Option<ByteRange>,
    info: &ResponseInfo,
    signed_total: u64,
    expected_len: u64,
) -> Result<Outcome, RangeError> {
    match (info.status, request_range) {
        (206, Some(range)) => {
            let last = range.last.unwrap_or(signed_total.saturating_sub(1));
            if signed_total == 0 || range.first > last || last >= signed_total {
                return Err(RangeError::Inconsistent("range is outside the pack"));
            }
            if last - range.first + 1 != expected_len {
                return Err(RangeError::Inconsistent(
                    "expected length differs from the range",
                ));
            }
            let expected = ContentRange {
                first: range.first,
                last,
                total: signed_total,
            };
            let found = info.content_range.ok_or(RangeError::ContentRangeMissing)?;
            if found != expected {
                return Err(RangeError::ContentRangeMismatch { expected, found });
            }
            check_length(info, expected_len)?;
            Ok(Outcome::Partial {
                first: range.first,
                last,
            })
        }
        (200, _) => {
            if info.content_range.is_some() {
                return Err(RangeError::ContentRangeUnexpected);
            }
            check_length(info, signed_total)?;
            Ok(Outcome::Full)
        }
        (status, _) => Err(RangeError::Status { status }),
    }
}

fn check_length(info: &ResponseInfo, expected: u64) -> Result<(), RangeError> {
    match info.content_length {
        Some(found) if found != expected => Err(RangeError::ContentLength { expected, found }),
        _ => Ok(()),
    }
}

/// Checks a document response (feed, key set, root, manifest): status `200`, no `Content-Range`,
/// and a `Content-Length`, when present, at most `cap`. The body reader enforces the cap on the
/// bytes it really reads.
pub fn check_document(info: &ResponseInfo, cap: u64) -> Result<(), RangeError> {
    if info.status != 200 {
        return Err(RangeError::Status {
            status: info.status,
        });
    }
    if info.content_range.is_some() {
        return Err(RangeError::ContentRangeUnexpected);
    }
    match info.content_length {
        Some(found) if found > cap => Err(RangeError::ContentLengthOverCap { cap, found }),
        _ => Ok(()),
    }
}

/// How the needed frames are fetched (M4-D8). `Default` is the documented v1 policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchPolicy {
    /// Two frames whose gap is at most this many bytes share one range request.
    pub gap: u64,
    /// The full pack is fetched when the needed bytes are at least this percentage of its size.
    pub full_ratio: u8,
    /// The full pack is fetched when more than this many range requests would be needed.
    pub max_runs: usize,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        FetchPolicy {
            gap: 64 * 1024,
            full_ratio: 50,
            max_runs: 64,
        }
    }
}

/// One range request that covers one or more needed frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// First byte, inclusive.
    pub first: u64,
    /// Last byte, inclusive.
    pub last: u64,
    /// Indices into the `needed` list of the frames this run covers, by offset (then length, then
    /// index).
    pub frames: Vec<usize>,
}

/// The result of [`plan_fetch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchPlan {
    /// Fetch these runs, one request each.
    Runs(Vec<Run>),
    /// Fetch the whole pack.
    FullPack,
}

/// Plans the fetch of `needed` frames, `(offset, length)` pairs of a pack of `pack_size` bytes.
///
/// Frames are sorted by offset and merged into single-range runs when the gap between them is at
/// most `policy.gap` bytes (adjacent and overlapping frames always merge). Frames that overlap or
/// repeat (shared frames, M3-D8) count once towards the needed bytes. The plan is the full pack
/// when the needed bytes are at least `policy.full_ratio` percent of `pack_size`, when more than
/// `policy.max_runs` runs would be needed, or when a frame does not lie inside the pack (the
/// transfer that needs no per-frame trust). An empty list needs nothing: `Runs([])`. A frame of
/// length 0 needs no bytes and is in no run. All arithmetic is checked.
pub fn plan_fetch(needed: &[(u64, u64)], pack_size: u64, policy: FetchPolicy) -> FetchPlan {
    // (offset, exclusive end, original index) of every frame that needs bytes.
    let mut frames: Vec<(u64, u64, usize)> = Vec::with_capacity(needed.len());
    for (index, &(offset, length)) in needed.iter().enumerate() {
        if length == 0 {
            continue;
        }
        match offset.checked_add(length) {
            Some(end) if end <= pack_size => frames.push((offset, end, index)),
            _ => return FetchPlan::FullPack,
        }
    }
    if frames.is_empty() {
        return FetchPlan::Runs(Vec::new());
    }
    frames.sort_unstable();

    let mut runs: Vec<Run> = Vec::new();
    let mut needed_bytes: u128 = 0;
    let mut covered_end = 0u64; // exclusive end of the union so far
    // The run in progress: its first byte, exclusive end and frames.
    let mut current: Option<(u64, u64, Vec<usize>)> = None;
    for &(offset, end, index) in &frames {
        let new_start = offset.max(covered_end);
        if end > new_start {
            needed_bytes += u128::from(end - new_start);
        }
        covered_end = covered_end.max(end);

        current = match current {
            Some((first, run_end, mut idx)) if offset.saturating_sub(run_end) <= policy.gap => {
                idx.push(index);
                Some((first, run_end.max(end), idx))
            }
            Some((first, run_end, idx)) => {
                runs.push(finish(first, run_end, idx));
                Some((offset, end, vec![index]))
            }
            None => Some((offset, end, vec![index])),
        };
    }
    if let Some((first, run_end, idx)) = current {
        runs.push(finish(first, run_end, idx));
    }

    let over_ratio = needed_bytes * 100 >= u128::from(pack_size) * u128::from(policy.full_ratio);
    if over_ratio || runs.len() > policy.max_runs {
        FetchPlan::FullPack
    } else {
        FetchPlan::Runs(runs)
    }
}

fn finish(first: u64, end: u64, frames: Vec<usize>) -> Run {
    Run {
        first,
        // `end > first` always (a frame has length >= 1).
        last: end - 1,
        frames,
    }
}
