//! Step 1 (M4): the transport types, the pure response rules (M4-D9), fetch planning (M4-D8),
//! cancellation and the event types.

use std::error::Error as StdError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

use lunepack_core::fetch::classify;
use lunepack_core::{
    BoxFuture, ByteRange, CancelToken, ContentRange, Error, FetchPlan, FetchPolicy, FileProgress,
    Head, Outcome, Phase, Progress, RangeError, RelPath, Request, ResponseInfo, Run, Source,
    Transport, TransportError, TransportErrorKind, Validator, check_document, plan_fetch,
};

const TOTAL: u64 = 1_787_248;

fn head(status: u16, headers: &[(&str, &[u8])]) -> Head {
    Head {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
            .collect(),
    }
}

fn range(first: u64, last: u64) -> Option<ByteRange> {
    Some(ByteRange {
        first,
        last: Some(last),
    })
}

fn judge(
    request: Option<ByteRange>,
    status: u16,
    headers: &[(&str, &[u8])],
    total: u64,
    expected_len: u64,
) -> Result<Outcome, RangeError> {
    let info = ResponseInfo::from_head(&head(status, headers))?;
    classify(request, &info, total, expected_len)
}

fn partial(headers: &[(&str, &[u8])]) -> Result<Outcome, RangeError> {
    judge(range(0, 99), 206, headers, TOTAL, 100)
}

// ---- Content-Range and the response rules ----------------------------------------------------------

#[test]
fn the_github_asset_answer_is_partial() {
    let outcome = partial(&[
        ("content-range", b"bytes 0-99/1787248"),
        ("content-length", b"100"),
    ]);
    assert_eq!(outcome, Ok(Outcome::Partial { first: 0, last: 99 }));
}

#[test]
fn an_open_ended_range_ends_at_the_last_byte() {
    let request = Some(ByteRange {
        first: TOTAL - 10,
        last: None,
    });
    let value = ContentRange {
        first: TOTAL - 10,
        last: TOTAL - 1,
        total: TOTAL,
    }
    .to_string();
    let outcome = judge(
        request,
        206,
        &[("content-range", value.as_bytes())],
        TOTAL,
        10,
    );
    assert_eq!(
        outcome,
        Ok(Outcome::Partial {
            first: TOTAL - 10,
            last: TOTAL - 1
        })
    );
}

#[test]
fn content_range_forms_that_are_refused() {
    let refused: &[(&str, &[u8])] = &[
        ("capital unit", b"Bytes 0-99/1787248"),
        ("two spaces", b"bytes  0-99/1787248"),
        ("no space", b"bytes0-99/1787248"),
        ("tab", b"bytes\t0-99/1787248"),
        ("unknown total", b"bytes 0-99/*"),
        ("unsatisfied form", b"bytes */1787248"),
        ("last differs", b"bytes 0-98/1787248"),
        ("first differs", b"bytes 1-99/1787248"),
        ("total differs", b"bytes 0-99/1787249"),
        ("17 digits", b"bytes 0-99/10000000000000000"),
        ("2^53", b"bytes 0-99/9007199254740992"),
        ("last before first", b"bytes 99-0/1787248"),
        ("trailing space", b"bytes 0-99/1787248 "),
        ("trailing text", b"bytes 0-99/1787248x"),
        ("sign", b"bytes +0-99/1787248"),
        ("empty", b""),
        ("no slash", b"bytes 0-99"),
        ("two dashes", b"bytes 0-9-9/1787248"),
        ("slash before dash", b"bytes 0/5-99"),
        ("list", b"bytes 0-99/1787248, bytes 0-99/1787248"),
    ];
    for (what, value) in refused {
        let outcome = partial(&[("content-range", value)]);
        assert!(outcome.is_err(), "{what}: accepted {outcome:?}");
    }
}

#[test]
fn syntax_errors_and_mismatches_are_told_apart() {
    assert_eq!(
        partial(&[("content-range", b"bytes 0-99/*")]),
        Err(RangeError::ContentRangeSyntax)
    );
    assert!(matches!(
        partial(&[("content-range", b"bytes 0-98/1787248")]),
        Err(RangeError::ContentRangeMismatch { .. })
    ));
}

#[test]
fn the_largest_accepted_numbers_parse() {
    let max = (1u64 << 53) - 1;
    let parsed = ContentRange::parse(format!("bytes 0-{max}/{max}").as_bytes());
    assert_eq!(
        parsed,
        Ok(ContentRange {
            first: 0,
            last: max,
            total: max
        })
    );
    assert_eq!(ContentRange::parse(b"bytes 0-0/1").map(|c| c.last), Ok(0));
}

#[test]
fn two_content_range_headers_fail() {
    let both = partial(&[
        ("content-range", b"bytes 0-99/1787248"),
        ("content-range", b"bytes 0-99/1787248"),
    ]);
    assert_eq!(
        both,
        Err(RangeError::DuplicateHeader {
            name: "content-range"
        })
    );
}

#[test]
fn every_single_valued_header_rejects_a_duplicate() {
    for name in [
        "content-range",
        "content-length",
        "content-encoding",
        "etag",
        "last-modified",
    ] {
        let value: &[u8] = match name {
            "content-range" => b"bytes 0-99/1787248",
            "content-length" => b"100",
            "content-encoding" => b"identity",
            "etag" => b"\"a\"",
            _ => b"Wed, 21 Oct 2026 07:28:00 GMT",
        };
        let err = ResponseInfo::from_head(&head(206, &[(name, value), (name, value)]));
        assert_eq!(err, Err(RangeError::DuplicateHeader { name }), "{name}");
    }
}

#[test]
fn a_header_name_in_capitals_is_still_checked() {
    // A transport must lowercase names; if one does not, the rules still apply.
    let err = ResponseInfo::from_head(&head(
        206,
        &[
            ("Content-Range", b"bytes 0-99/1787248"),
            ("content-range", b"bytes 0-99/1787248"),
        ],
    ));
    assert!(matches!(err, Err(RangeError::DuplicateHeader { .. })));
}

#[test]
fn content_encoding_must_be_identity() {
    let cr: (&str, &[u8]) = ("content-range", b"bytes 0-99/1787248");
    assert!(partial(&[cr, ("content-encoding", b"identity")]).is_ok());
    assert_eq!(
        partial(&[cr, ("content-encoding", b"gzip")]),
        Err(RangeError::ContentCoding)
    );
    assert_eq!(
        partial(&[cr, ("content-encoding", b"")]),
        Err(RangeError::ContentCoding)
    );
    assert_eq!(
        partial(&[cr, ("content-encoding", b"identity, gzip")]),
        Err(RangeError::ContentCoding)
    );
}

#[test]
fn content_length_must_equal_the_expected_count() {
    let cr: (&str, &[u8]) = ("content-range", b"bytes 0-99/1787248");
    assert!(partial(&[cr, ("content-length", b"100")]).is_ok());
    assert_eq!(
        partial(&[cr, ("content-length", b"101")]),
        Err(RangeError::ContentLength {
            expected: 100,
            found: 101
        })
    );
    for bad in [&b"+100"[..], b"1e2", b"100 ", b"", b"100, 100", b"-1"] {
        assert_eq!(
            partial(&[cr, ("content-length", bad)]),
            Err(RangeError::ContentLengthSyntax),
            "{bad:?}"
        );
    }
    // A full pack must be exactly the signed size.
    assert_eq!(
        judge(None, 200, &[("content-length", b"100")], TOTAL, TOTAL),
        Err(RangeError::ContentLength {
            expected: TOTAL,
            found: 100
        })
    );
}

#[test]
fn a_200_to_a_range_request_is_the_full_pack() {
    let outcome = judge(
        range(0, 99),
        200,
        &[("content-length", b"1787248")],
        TOTAL,
        100,
    );
    assert_eq!(outcome, Ok(Outcome::Full));
    assert_eq!(
        judge(None, 200, &[], TOTAL, TOTAL),
        Ok(Outcome::Full),
        "no content-length is accepted; the body reader counts"
    );
}

#[test]
fn a_200_with_a_content_range_is_refused() {
    let outcome = judge(
        range(0, 99),
        200,
        &[("content-range", b"bytes 0-99/1787248")],
        TOTAL,
        100,
    );
    assert_eq!(outcome, Err(RangeError::ContentRangeUnexpected));
}

#[test]
fn a_206_needs_a_content_range_and_a_range_request() {
    assert_eq!(partial(&[]), Err(RangeError::ContentRangeMissing));
    assert_eq!(
        judge(
            None,
            206,
            &[("content-range", b"bytes 0-99/1787248")],
            TOTAL,
            TOTAL
        ),
        Err(RangeError::Status { status: 206 })
    );
}

#[test]
fn other_statuses_are_refused() {
    for status in [301, 304, 403, 404, 416, 500, 503] {
        assert_eq!(
            judge(range(0, 99), status, &[], TOTAL, 100),
            Err(RangeError::Status { status })
        );
    }
}

#[test]
fn non_ascii_and_control_bytes_in_a_checked_header_fail() {
    for (name, value) in [
        ("content-range", &b"bytes 0-99/1787248\xff"[..]),
        ("content-length", b"1\x800"),
        ("content-encoding", b"identity\r\nx: y"),
        ("etag", b"\"a\xc3\xa9\""),
        ("last-modified", b"Wed\x00"),
    ] {
        let err = ResponseInfo::from_head(&head(206, &[(name, value)]));
        assert_eq!(err, Err(RangeError::HeaderBytes { name }), "{name}");
    }
    // Headers the rules do not read are not held to them.
    assert!(ResponseInfo::from_head(&head(200, &[("x-note", b"caf\xc3\xa9")])).is_ok());
}

#[test]
fn inconsistent_caller_numbers_are_errors_not_panics() {
    let info =
        ResponseInfo::from_head(&head(206, &[("content-range", b"bytes 0-99/1787248")])).unwrap();
    for (request, total, len) in [
        (range(0, 99), TOTAL, 99),
        (range(100, 99), TOTAL, 100),
        (range(0, TOTAL), TOTAL, TOTAL + 1),
        (range(0, 99), 0, 100),
        (
            Some(ByteRange {
                first: 0,
                last: None,
            }),
            0,
            0,
        ),
    ] {
        assert!(matches!(
            classify(request, &info, total, len),
            Err(RangeError::Inconsistent(_))
        ));
    }
}

#[test]
fn the_validator_is_a_strong_etag_else_last_modified() {
    let etag = ResponseInfo::from_head(&head(
        200,
        &[
            ("etag", b"\"abc\""),
            ("last-modified", b"Wed, 21 Oct 2026 07:28:00 GMT"),
        ],
    ))
    .unwrap();
    assert_eq!(
        etag.validator,
        Some(Validator::StrongETag("\"abc\"".to_owned()))
    );
    let weak = ResponseInfo::from_head(&head(
        200,
        &[
            ("etag", b"W/\"abc\""),
            ("last-modified", b"Wed, 21 Oct 2026 07:28:00 GMT"),
        ],
    ))
    .unwrap();
    assert_eq!(
        weak.validator,
        Some(Validator::LastModified(
            "Wed, 21 Oct 2026 07:28:00 GMT".to_owned()
        ))
    );
    assert_eq!(
        ResponseInfo::from_head(&head(200, &[("etag", b"W/\"abc\"")]))
            .unwrap()
            .validator,
        None
    );
    assert_eq!(
        ResponseInfo::from_head(&head(200, &[])).unwrap().validator,
        None
    );
}

#[test]
fn a_weak_or_malformed_etag_cannot_be_a_validator() {
    assert_eq!(Validator::from_etag(b"W/\"abc\""), None);
    assert_eq!(Validator::from_etag(b"w/\"abc\""), None, "unquoted");
    assert_eq!(Validator::from_etag(b"abc"), None);
    assert_eq!(Validator::from_etag(b"\""), None);
    assert_eq!(Validator::from_etag(b""), None);
    assert_eq!(Validator::from_etag(b"\"a\"b\""), None, "inner quote");
    assert_eq!(Validator::from_etag(b"\"a b\""), None, "space");
    assert_eq!(Validator::from_etag(b"\"a\r\nx: y\""), None, "line break");
    assert_eq!(
        Validator::from_etag(b"\"\""),
        Some(Validator::StrongETag("\"\"".to_owned()))
    );
    assert_eq!(Validator::from_last_modified(b"a\r\nb"), None);
    assert_eq!(Validator::from_last_modified(b""), None);
    assert_eq!(Validator::from_last_modified(&[b'a'; 65]), None);
    assert!(Validator::from_last_modified(&[b'a'; 64]).is_some());
}

#[test]
fn header_values_for_the_request() {
    assert_eq!(
        ByteRange {
            first: 5,
            last: Some(9)
        }
        .header_value(),
        "bytes=5-9"
    );
    assert_eq!(
        ByteRange {
            first: 5,
            last: None
        }
        .header_value(),
        "bytes=5-"
    );
    assert_eq!(
        Validator::from_etag(b"\"x\"").unwrap().header_value(),
        "\"x\""
    );
}

#[test]
fn documents_need_200_and_a_length_within_the_cap() {
    let ok = |headers: &[(&str, &[u8])], status| {
        let info = ResponseInfo::from_head(&head(status, headers)).unwrap();
        check_document(&info, 1000)
    };
    assert_eq!(ok(&[("content-length", b"1000")], 200), Ok(()));
    assert_eq!(ok(&[], 200), Ok(()));
    assert_eq!(
        ok(&[("content-length", b"1001")], 200),
        Err(RangeError::ContentLengthOverCap {
            cap: 1000,
            found: 1001
        })
    );
    assert_eq!(ok(&[], 404), Err(RangeError::Status { status: 404 }));
    assert_eq!(ok(&[], 206), Err(RangeError::Status { status: 206 }));
    assert_eq!(
        ok(&[("content-range", b"bytes 0-1/2")], 200),
        Err(RangeError::ContentRangeUnexpected)
    );
}

// ---- plan_fetch ------------------------------------------------------------------------------------

const KIB: u64 = 1024;

fn runs(plan: FetchPlan) -> Vec<Run> {
    match plan {
        FetchPlan::Runs(runs) => runs,
        FetchPlan::FullPack => panic!("expected runs, got the full pack"),
    }
}

fn policy() -> FetchPolicy {
    FetchPolicy::default()
}

#[test]
fn the_default_policy_is_the_documented_one() {
    assert_eq!(
        policy(),
        FetchPolicy {
            gap: 64 * KIB,
            full_ratio: 50,
            max_runs: 64
        }
    );
}

#[test]
fn adjacent_frames_merge() {
    let plan = plan_fetch(&[(0, 100), (100, 50)], 100_000_000, policy());
    assert_eq!(
        runs(plan),
        vec![Run {
            first: 0,
            last: 149,
            frames: vec![0, 1]
        }]
    );
}

#[test]
fn a_gap_of_exactly_64_kib_merges_and_one_more_byte_does_not() {
    let pack = 1_000_000_000;
    let merged = runs(plan_fetch(
        &[(0, 100), (100 + 64 * KIB, 10)],
        pack,
        policy(),
    ));
    assert_eq!(merged.len(), 1);
    assert_eq!((merged[0].first, merged[0].last), (0, 100 + 64 * KIB + 9));
    let split = runs(plan_fetch(
        &[(0, 100), (100 + 64 * KIB + 1, 10)],
        pack,
        policy(),
    ));
    assert_eq!(split.len(), 2);
    assert_eq!((split[0].first, split[0].last), (0, 99));
    assert_eq!(
        (split[1].first, split[1].last),
        (100 + 64 * KIB + 1, 100 + 64 * KIB + 10)
    );
}

#[test]
fn frames_are_sorted_by_offset_and_report_their_original_index() {
    let plan = plan_fetch(&[(5_000_000, 10), (0, 10)], 1_000_000_000, policy());
    let got = runs(plan);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].frames, vec![1]);
    assert_eq!(got[1].frames, vec![0]);
}

#[test]
fn half_the_pack_or_more_is_the_full_pack() {
    assert_eq!(plan_fetch(&[(0, 500)], 1000, policy()), FetchPlan::FullPack);
    assert!(matches!(
        plan_fetch(&[(0, 499)], 1000, policy()),
        FetchPlan::Runs(_)
    ));
    // Two frames with a gap: the needed bytes, not the fetched ones, count.
    assert!(matches!(
        plan_fetch(&[(0, 250), (300, 250)], 1000, policy()),
        FetchPlan::FullPack
    ));
    assert!(matches!(
        plan_fetch(&[(0, 250), (300, 249)], 1000, policy()),
        FetchPlan::Runs(_)
    ));
}

#[test]
fn more_than_64_runs_is_the_full_pack() {
    let spaced = |n: u64| -> Vec<(u64, u64)> { (0..n).map(|i| (i * 1_000_000, 10)).collect() };
    let pack = 10_000_000_000;
    assert_eq!(runs(plan_fetch(&spaced(64), pack, policy())).len(), 64);
    assert_eq!(plan_fetch(&spaced(65), pack, policy()), FetchPlan::FullPack);
}

#[test]
fn an_empty_list_needs_nothing() {
    assert_eq!(plan_fetch(&[], 1000, policy()), FetchPlan::Runs(vec![]));
    assert_eq!(plan_fetch(&[], 0, policy()), FetchPlan::Runs(vec![]));
    assert_eq!(
        plan_fetch(&[(10, 0)], 1000, policy()),
        FetchPlan::Runs(vec![]),
        "a zero-length frame needs no bytes"
    );
}

#[test]
fn repeated_and_overlapping_frames_count_once() {
    let pack = 1_000_000_000;
    let got = runs(plan_fetch(&[(0, 100), (0, 100), (50, 100)], pack, policy()));
    assert_eq!(
        got,
        vec![Run {
            first: 0,
            last: 149,
            frames: vec![0, 1, 2]
        }]
    );
    // 400 distinct bytes of 1000 are under the ratio even though the list sums to 600.
    assert!(matches!(
        plan_fetch(&[(0, 200), (0, 200), (200, 200)], 1000, policy()),
        FetchPlan::Runs(_)
    ));
    assert_eq!(
        plan_fetch(&[(0, 200), (200, 300)], 1000, policy()),
        FetchPlan::FullPack
    );
}

#[test]
fn a_frame_outside_the_pack_or_overflowing_is_the_full_pack() {
    assert_eq!(
        plan_fetch(&[(0, 1001)], 1000, policy()),
        FetchPlan::FullPack
    );
    assert_eq!(
        plan_fetch(&[(1000, 1)], 1000, policy()),
        FetchPlan::FullPack
    );
    assert_eq!(
        plan_fetch(&[(u64::MAX, 2)], u64::MAX, policy()),
        FetchPlan::FullPack
    );
    assert_eq!(
        plan_fetch(&[(u64::MAX - 1, u64::MAX)], u64::MAX, policy()),
        FetchPlan::FullPack
    );
}

#[test]
fn arithmetic_holds_at_the_top_of_the_range() {
    let pack = u64::MAX;
    let got = plan_fetch(
        &[(u64::MAX - 10, 10), (0, 1)],
        pack,
        FetchPolicy {
            gap: u64::MAX,
            full_ratio: 100,
            max_runs: 64,
        },
    );
    assert_eq!(
        got,
        FetchPlan::Runs(vec![Run {
            first: 0,
            last: u64::MAX - 1,
            frames: vec![1, 0]
        }])
    );
}

/// A small deterministic generator, so the property test needs no dependency.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, below: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % below
    }
}

#[test]
fn every_planned_frame_is_covered_by_exactly_one_run() {
    let mut rng = Lcg(7);
    for round in 0..500 {
        let pack = 1_000_000 + rng.next(1_000_000);
        let count = rng.next(12) as usize;
        let needed: Vec<(u64, u64)> = (0..count)
            .map(|_| {
                let length = 1 + rng.next(2000);
                (rng.next(pack - length), length)
            })
            .collect();
        let policy = FetchPolicy {
            gap: rng.next(5000),
            full_ratio: 100,
            max_runs: 64,
        };
        let FetchPlan::Runs(got) = plan_fetch(&needed, pack, policy) else {
            continue;
        };
        let mut seen = vec![0u32; needed.len()];
        for pair in got.windows(2) {
            assert!(
                pair[0].last + 1 + policy.gap < pair[1].first,
                "round {round}: runs should have merged: {got:?}"
            );
        }
        for run in &got {
            assert!(run.first <= run.last && run.last < pack, "round {round}");
            for &i in &run.frames {
                let (offset, length) = needed[i];
                assert!(
                    run.first <= offset && offset + length - 1 <= run.last,
                    "round {round}: frame {i} sticks out of its run"
                );
                seen[i] += 1;
            }
        }
        assert!(seen.iter().all(|&n| n == 1), "round {round}: {seen:?}");
    }
}

// ---- the transport trait and its errors ----------------------------------------------------------------

struct NeverTransport;

impl Transport for NeverTransport {
    fn get(
        &self,
        request: Request,
    ) -> BoxFuture<'static, Result<lunepack_core::Response, TransportError>> {
        Box::pin(async move {
            Err(TransportError::new(
                TransportErrorKind::Unsupported,
                &request.url,
                None,
            ))
        })
    }
}

#[test]
fn the_async_transport_is_object_safe() {
    let boxed: Box<dyn Transport> = Box::new(NeverTransport);
    let shared: Arc<dyn Transport> = Arc::new(NeverTransport);
    fn assert_send_sync<T: Send + Sync + ?Sized>(_: &T) {}
    assert_send_sync(&*boxed);
    assert_send_sync(&*shared);
    let future = boxed.get(Request {
        url: "https://example.com/x".to_owned(),
        range: None,
        if_range: None,
    });
    fn assert_static<T: Send + 'static>(_: &T) {}
    assert_static(&future);
}

#[test]
fn the_blocking_transport_is_object_safe() {
    fn takes(_: &dyn lunepack_core::BlockingTransport) {}
    struct B;
    impl lunepack_core::BlockingTransport for B {
        fn get(
            &self,
            request: &Request,
            _cancel: &CancelToken,
        ) -> Result<lunepack_core::BlockingResponse, TransportError> {
            Err(TransportError::new(
                TransportErrorKind::Cancelled,
                &request.url,
                None,
            ))
        }
    }
    takes(&B);
}

#[test]
fn a_transport_error_never_shows_the_query_or_userinfo() {
    let url = "https://user:pw@example.com:8443/path/pack.lpk?token=s3cr3t#frag";
    let source: Box<dyn StdError + Send + Sync> = "refused".into();
    let err = TransportError::new(TransportErrorKind::Connect, url, Some(source));
    let shown = format!("{err} | {err:?} | {:#?}", err);
    for secret in ["s3cr3t", "user", "pw", "token", "8443", "path", "frag"] {
        assert!(!shown.contains(secret), "{secret} leaked: {shown}");
    }
    assert_eq!(err.origin(), "https://example.com");
    assert!(err.to_string().contains("https://example.com"));
    // The cause is kept.
    assert_eq!(err.source().unwrap().to_string(), "refused");
    let wrapped = Error::from(err);
    assert!(wrapped.to_string().contains("https://example.com"));
    assert!(!format!("{wrapped:?}").contains("s3cr3t"));
    assert!(wrapped.source().is_some());
}

#[test]
fn the_origin_of_odd_urls() {
    let origin = |url: &str| {
        TransportError::new(TransportErrorKind::Io, url, None)
            .origin()
            .to_owned()
    };
    assert_eq!(origin("HTTPS://Example.com/x"), "https://Example.com");
    assert_eq!(origin("http://[::1]:8080/x?q=1"), "http://[::1]");
    assert_eq!(origin("https://a@b@host/x"), "https://host");
    assert_eq!(origin("https://host?token=s3cr3t"), "https://host");
    // A backslash ends the authority, as in WHATWG URL parsing.
    assert_eq!(origin("https://host\\@evil/x"), "https://host");
    assert_eq!(origin("file:///tmp/pack"), "file://");
    assert_eq!(origin("file:/tmp/pack"), "file://");
    assert_eq!(origin("user:pw@host"), "<invalid url>");
    assert_eq!(origin("no scheme"), "<invalid url>");
    assert_eq!(origin("1http://x"), "<invalid url>");
    assert_eq!(origin(""), "<invalid url>");
    let long = format!("https://{}/x", "h".repeat(500));
    assert!(origin(&long).chars().count() <= 64);
    assert!(!origin("https://ho\nst/x").contains('\n'));
}

// ---- cancellation ----------------------------------------------------------------------------------

struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counted() -> (Arc<Counter>, Waker) {
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    (counter.clone(), Waker::from(counter))
}

#[test]
fn cancel_wakes_every_registered_waker_once() {
    let token = CancelToken::new();
    let (a, wa) = counted();
    let (b, wb) = counted();
    token.register_waker(&wa);
    token.register_waker(&wb);
    assert!(!token.is_cancelled());
    token.clone().cancel();
    assert!(token.is_cancelled());
    token.cancel();
    assert_eq!(a.0.load(Ordering::SeqCst), 1);
    assert_eq!(b.0.load(Ordering::SeqCst), 1);
}

#[test]
fn a_waker_registered_after_cancel_is_woken_at_once() {
    let token = CancelToken::new();
    token.cancel();
    let (c, w) = counted();
    token.register_waker(&w);
    assert_eq!(c.0.load(Ordering::SeqCst), 1);
}

#[test]
fn registering_the_same_waker_again_keeps_one_entry() {
    let token = CancelToken::new();
    let (c, w) = counted();
    for _ in 0..100 {
        token.register_waker(&w);
    }
    token.cancel();
    assert_eq!(c.0.load(Ordering::SeqCst), 1);
}

#[test]
fn clones_share_the_flag_across_threads() {
    let token = CancelToken::new();
    let other = token.clone();
    let (c, w) = counted();
    token.register_waker(&w);
    std::thread::spawn(move || other.cancel()).join().unwrap();
    assert!(token.is_cancelled());
    assert_eq!(c.0.load(Ordering::SeqCst), 1);
}

// ---- events and errors ---------------------------------------------------------------------------------

#[test]
fn progress_events_compare_and_clone() {
    let file = FileProgress {
        path: RelPath::parse("bin/app").unwrap(),
        done: 10,
        total: 20,
        source: Source::Range,
    };
    let event = Progress {
        phase: Phase::Download,
        done: 10,
        total: 100,
        file: Some(file.clone()),
    };
    assert_eq!(event.clone(), event);
    assert_ne!(
        event,
        Progress {
            phase: Phase::Stage,
            ..event.clone()
        }
    );
    assert_eq!(event.file, Some(file));
    // Reserved, but nameable.
    assert_ne!(Source::Patch, Source::FullPack);
    assert_ne!(Phase::Check, Phase::Scan);
    assert_ne!(Source::Unchanged, Source::Range);
}

#[test]
fn the_new_error_variants_keep_their_causes() {
    let range = Error::from(RangeError::ContentCoding);
    assert!(range.to_string().contains("content-encoding"));
    assert!(range.source().is_some());
    let cancelled = Error::Cancelled;
    assert_eq!(cancelled.to_string(), "cancelled");
    let transport = Error::from(TransportError::new(
        TransportErrorKind::Tls,
        "https://example.com/",
        None,
    ));
    assert!(matches!(transport, Error::Transport(_)));
}
