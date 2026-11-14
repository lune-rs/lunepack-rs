//! The testkit's own tests: the fakes pass the contract suites, and each fake rejects what it must.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use lunepack_core::error::{CodecError, SignatureError};
use lunepack_core::fetch::classify;
use lunepack_core::{
    BlockingResponse, BlockingTransport, ByteRange, CancelToken, Clock, Codec, CodecId,
    DecodeReport, Encoder, Error, FileKind, FrameView, Fs, FsErrorKind, Hasher, Head, RangeError,
    Request, ResponseInfo, Sha256Digest, SignatureAlg, Signer, StreamView, Transport,
    TransportError, TransportErrorKind, Validator, Verifier,
};
use lunepack_testkit::*;

fn fake_kats() -> Vec<HashKat> {
    // Known answers of the fake itself, pinned here so a change to the fake is noticed.
    vec![
        HashKat {
            input: b"",
            digest_hex: leak(FakeHasher.sha256(b"")),
        },
        HashKat {
            input: b"abc",
            digest_hex: leak(FakeHasher.sha256(b"abc")),
        },
    ]
}

fn leak(d: Sha256Digest) -> &'static str {
    Box::leak(d.to_hex().into_boxed_str())
}

#[test]
fn fake_hasher_passes_suite_with_fake_kats() {
    run_hasher_suite(&FakeHasher, &fake_kats());
}

#[test]
#[should_panic(expected = "KAT")]
fn fake_hasher_fails_the_real_sha256_kats() {
    run_hasher_suite(&FakeHasher, SHA256_KATS);
}

#[test]
fn fake_hasher_differs_from_sha256() {
    let abc = FakeHasher.sha256(b"abc");
    assert_ne!(
        abc.to_hex(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_ne!(FakeHasher.sha256(b""), FakeHasher.sha256(b"\0"));
}

fn fake_sign(seed: u8, message: &[u8]) -> ([u8; 32], [u8; 64]) {
    let pair = FakeKeyPair::from_seed(seed);
    (pair.public_key(), pair.sign(message))
}

#[test]
fn fake_verifier_passes_suite() {
    let pair = FakeKeyPair::from_seed(9);
    let message = b"known answer".to_vec();
    let kats = vec![VerifyKat {
        public_key: pair.public_key(),
        signature: pair.sign(&message),
        message,
    }];
    run_verifier_suite(&FakeVerifier, &fake_sign, &kats, &FAKE_INVALID_KEYS);
}

#[test]
#[should_panic(expected = "known answer 0 rejected")]
fn verifier_suite_catches_a_bad_known_answer() {
    let pair = FakeKeyPair::from_seed(9);
    let kats = vec![VerifyKat {
        public_key: pair.public_key(),
        signature: [0; 64],
        message: b"x".to_vec(),
    }];
    run_verifier_suite(&FakeVerifier, &fake_sign, &kats, &FAKE_INVALID_KEYS);
}

#[test]
fn fake_verifier_rejections_are_mismatches() {
    let pair = FakeKeyPair::from_seed(1);
    let sig = pair.sign(b"m");
    let err = FakeVerifier
        .verify(SignatureAlg::Ed25519, &pair.public_key(), b"n", &sig)
        .unwrap_err();
    assert!(matches!(err, Error::Signature(SignatureError::Mismatch)));
    assert_ne!(
        FakeKeyPair::from_seed(1).public_key(),
        FakeKeyPair::from_seed(2).public_key()
    );
}

#[test]
fn verifier_suite_catches_an_accept_everything_verifier() {
    struct AcceptAll;
    impl Verifier for AcceptAll {
        fn verify(
            &self,
            _: SignatureAlg,
            _: &[u8; 32],
            _: &[u8],
            _: &[u8; 64],
        ) -> Result<(), Error> {
            Ok(())
        }
        fn check_public_key(&self, _: SignatureAlg, _: &[u8; 32]) -> Result<(), Error> {
            Ok(())
        }
    }
    let caught = std::panic::catch_unwind(|| {
        run_verifier_suite(&AcceptAll, &fake_sign, &[], &FAKE_INVALID_KEYS)
    });
    assert!(
        caught.is_err(),
        "the suite must reject an accept-everything verifier"
    );
}

#[test]
fn fake_clock_set_advance_and_suite() {
    let clock = FakeClock::new(1_000);
    let handle = clock.clone();
    assert_eq!(clock.now_unix_secs(), 1_000);
    handle.advance_secs(5);
    assert_eq!(clock.now_unix_secs(), 1_005);
    handle.advance_400_days();
    assert_eq!(clock.now_unix_secs(), 1_005 + 400 * 86_400);
    handle.set_year_2100();
    assert_eq!(clock.now_unix_secs(), 4_102_444_800);
    assert_eq!(YEAR_2100_UNIX_SECS, 4_102_444_800);
    handle.advance_secs(u64::MAX);
    assert_eq!(clock.now_unix_secs(), u64::MAX, "advance saturates");

    run_clock_suite(&FakeClock::new(1), Some(&|s| Box::new(FakeClock::new(s))));
    run_clock_suite(&FakeClock::new(1), None);
}

const ALL: [CodecId; 5] = [
    CodecId::Stored,
    CodecId::Lzma2,
    CodecId::BcjX86Lzma2,
    CodecId::BcjArm64Lzma2,
    CodecId::Bcj2,
];

fn data() -> Vec<u8> {
    (0..1000u32).map(|i| (i * 7 % 256) as u8).collect()
}

fn decode(
    codec: &FakeCodec,
    enc: &FakeEncoded,
) -> (Result<lunepack_core::DecodeReport, Error>, Vec<u8>) {
    let views = enc.views(4096);
    let frame = FrameView {
        codec: enc.codec,
        output_size: enc.output_size,
        streams: &views,
    };
    let mut out = Vec::new();
    let result = codec.decode(&frame, &mut out);
    (result, out)
}

#[test]
fn fake_codec_round_trips_every_codec_id() {
    for id in ALL {
        let d = data();
        let enc = FakeCodec::encode(id, &d);
        assert_eq!(enc.streams.len(), if id == CodecId::Bcj2 { 4 } else { 1 });
        let (res, out) = decode(&FakeCodec::new(), &enc);
        let report = res.unwrap();
        assert_eq!(out, d, "{id:?}");
        let want: Vec<u64> = enc.streams.iter().map(|s| s.length as u64).collect();
        assert_eq!(report.consumed, want);
        let total: usize = enc.streams.iter().map(|s| s.length).sum();
        assert_eq!(total, enc.frame.len(), "streams cover the frame exactly");
    }
}

#[test]
fn stored_is_the_files_bytes_and_compressed_differs() {
    let d = data();
    assert_eq!(FakeCodec::encode(CodecId::Stored, &d).frame, d);
    assert_ne!(FakeCodec::encode(CodecId::Lzma2, &d).frame, d);
}

#[test]
fn fault_knobs() {
    let d = data();
    for id in ALL {
        let enc = FakeCodec::encode(id, &d);

        let (res, out) = decode(&FakeCodec::with_fault(Fault::ExtraBytes), &enc);
        assert!(res.is_ok());
        assert_eq!(out.len(), d.len() + 1, "{id:?} extra");

        let (res, out) = decode(&FakeCodec::with_fault(Fault::TooFewBytes), &enc);
        assert!(res.is_ok());
        assert_eq!(out.len(), d.len() - 1, "{id:?} too few");

        let (res, _) = decode(&FakeCodec::with_fault(Fault::WrongConsumed), &enc);
        let honest = decode(&FakeCodec::new(), &enc).0.unwrap();
        assert_ne!(res.unwrap().consumed, honest.consumed, "{id:?} consumed");

        let (res, out) = decode(&FakeCodec::with_fault(Fault::ErrorMidStream), &enc);
        assert!(matches!(res, Err(Error::Codec(CodecError::Corrupt(_)))));
        assert!(out.len() < d.len(), "{id:?} partial output only");
    }
}

#[test]
fn fake_codec_rejects_bad_frames() {
    let d = data();
    // Missing end marker, wrong decoded size, wrong stream count, dict size on a stored stream.
    let mut enc = FakeCodec::encode(CodecId::Lzma2, &d);
    *enc.frame.last_mut().unwrap() ^= 1;
    assert!(decode(&FakeCodec::new(), &enc).0.is_err());

    let mut enc = FakeCodec::encode(CodecId::Lzma2, &d);
    enc.streams[0].decoded_size += 1;
    assert!(decode(&FakeCodec::new(), &enc).0.is_err());

    let enc = FakeCodec::encode(CodecId::Bcj2, &d);
    let views = enc.views(4096);
    let frame = FrameView {
        codec: CodecId::Bcj2,
        output_size: enc.output_size,
        streams: &views[..3],
    };
    assert!(FakeCodec::new().decode(&frame, &mut Vec::new()).is_err());

    let enc = FakeCodec::encode(CodecId::Stored, &d);
    let mut views = enc.views(4096);
    views[0].dict_size = Some(4096);
    let frame = FrameView {
        codec: CodecId::Stored,
        output_size: enc.output_size,
        streams: &views,
    };
    assert!(FakeCodec::new().decode(&frame, &mut Vec::new()).is_err());
}

#[test]
fn write_error_is_reported_as_codec_write() {
    struct Failing;
    impl std::io::Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let enc = FakeCodec::encode(CodecId::Lzma2, &data());
    let views = enc.views(4096);
    let frame = FrameView {
        codec: enc.codec,
        output_size: enc.output_size,
        streams: &views,
    };
    let err = FakeCodec::new().decode(&frame, &mut Failing).unwrap_err();
    assert!(matches!(err, Error::Codec(CodecError::Write(_))));
}

#[test]
fn fake_codec_passes_the_codec_suite() {
    run_codec_suite(&FakeCodec::new(), &FakeCodec::new(), &FakeHasher);
}

/// A decoder that trusts what the streams really hold and ignores the signed per-stream sizes
/// (an F6 violation), by rewriting `decoded_size` to the toy encoding's real sizes.
struct IgnoresStreamSizes;

impl Codec for IgnoresStreamSizes {
    fn decode(
        &self,
        frame: &FrameView<'_>,
        out: &mut dyn std::io::Write,
    ) -> Result<DecodeReport, Error> {
        let streams: Vec<StreamView<'_>> = frame
            .streams
            .iter()
            .map(|s| StreamView {
                decoded_size: (s.input.len() - usize::from(s.dict_size.is_some())) as u64,
                ..*s
            })
            .collect();
        FakeCodec::new().decode(
            &FrameView {
                streams: &streams,
                ..*frame
            },
            out,
        )
    }
}

/// A decoder that allocates whatever it likes: it ignores the dictionary the descriptor signs.
struct IgnoresDictionary;

impl Codec for IgnoresDictionary {
    fn decode(
        &self,
        frame: &FrameView<'_>,
        out: &mut dyn std::io::Write,
    ) -> Result<DecodeReport, Error> {
        let streams: Vec<StreamView<'_>> = frame
            .streams
            .iter()
            .map(|s| StreamView {
                dict_size: s.dict_size.map(|_| 1 << 24),
                ..*s
            })
            .collect();
        FakeCodec::new().decode(
            &FrameView {
                streams: &streams,
                ..*frame
            },
            out,
        )
    }
}

fn suite_panics(codec: &dyn Codec) -> String {
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_codec_suite(codec, &FakeCodec::new(), &FakeHasher)
    }));
    match caught {
        Ok(()) => panic!("the suite accepted a broken decoder"),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default(),
    }
}

#[test]
fn codec_suite_catches_a_decoder_that_ignores_stream_sizes() {
    let message = suite_panics(&IgnoresStreamSizes);
    assert!(message.contains("lying stream sizes decoded"), "{message}");
}

#[test]
fn codec_suite_catches_a_decoder_that_ignores_the_dictionary() {
    let message = suite_panics(&IgnoresDictionary);
    assert!(
        message.contains("decoded with a dictionary of 4096"),
        "{message}"
    );
}

#[test]
fn codec_suite_catches_a_decoder_that_writes_after_a_write_error() {
    // Retries every failed write: 12 must see a write after the failure.
    let message = suite_panics(&FakeCodecRetrying);
    assert!(message.contains("writes after the failure"), "{message}");
}

struct FakeCodecRetrying;

impl Codec for FakeCodecRetrying {
    fn decode(
        &self,
        frame: &FrameView<'_>,
        out: &mut dyn std::io::Write,
    ) -> Result<DecodeReport, Error> {
        FakeCodec::with_fault(Fault::RetryAfterWriteError).decode(frame, out)
    }
}

#[test]
fn fake_encoder_emits_valid_descriptors_and_refuses_empty_input() {
    let enc = Encoder::encode(&FakeCodec::new(), CodecId::Bcj2, &[7]).unwrap();
    let streams = enc.streams.unwrap();
    assert_eq!(streams.len(), 4);
    assert!(streams.iter().all(|s| s.length >= 1));
    assert_eq!(streams[3].dict_size, None);
    assert_eq!(streams[0].dict_size, Some(4096));
    assert!(Encoder::encode(&FakeCodec::new(), CodecId::Lzma2, &[]).is_err());
    assert!(FakeCodec::new().encode_memory(CodecId::Lzma2, 1 << 20) >= 1 << 20);
}

#[test]
fn fake_signer_passes_the_signer_suite() {
    let signer = FakeSigner::new(7);
    run_signer_suite(&signer, &FakeVerifier, &signer.secret());
    assert_eq!(signer.alg(), SignatureAlg::Ed25519);
    assert_eq!(signer.public_key(), FakeKeyPair::from_seed(7).public_key());
    assert_ne!(signer.public_key(), FakeSigner::new(8).public_key());
}

struct LeakyDebug {
    pair: FakeKeyPair,
    secret: Vec<u8>,
}

impl std::fmt::Debug for LeakyDebug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LeakyDebug({:?})", self.secret)
    }
}

impl Signer for LeakyDebug {
    fn alg(&self) -> SignatureAlg {
        SignatureAlg::Ed25519
    }

    fn public_key(&self) -> [u8; 32] {
        self.pair.public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        Ok(self.pair.sign(message))
    }
}

#[test]
fn signer_suite_catches_a_debug_that_prints_the_secret() {
    let secret = FakeSigner::new(3).secret();
    let leaky = LeakyDebug {
        pair: FakeKeyPair::from_seed(3),
        secret: secret.clone(),
    };
    let caught = std::panic::catch_unwind(|| run_signer_suite(&leaky, &FakeVerifier, &secret));
    assert!(caught.is_err(), "a Debug that prints the secret passed");
}

#[test]
fn signer_suite_catches_a_non_deterministic_or_wrong_signer() {
    // Signs with a different key than it announces.
    #[derive(Debug)]
    struct WrongKey;
    impl Signer for WrongKey {
        fn alg(&self) -> SignatureAlg {
            SignatureAlg::Ed25519
        }
        fn public_key(&self) -> [u8; 32] {
            FakeKeyPair::from_seed(1).public_key()
        }
        fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
            Ok(FakeKeyPair::from_seed(2).sign(message))
        }
    }
    let caught = std::panic::catch_unwind(|| run_signer_suite(&WrongKey, &FakeVerifier, b"x"));
    assert!(caught.is_err());
}

// ---- transports (M4 step 2) --------------------------------------------------------------------------

/// A minimal HTTP/1.1 client over a raw `TcpStream`: the transport the loopback server is tested
/// with, since the real adapter lives in `lunepack-http`. Follows up to 5 redirects, lowercases
/// header names, keeps duplicates, reads the body by `content-length` or to the end of the
/// connection, sends no `Accept-Encoding`, and checks the cancel token before connecting and before
/// every read.
struct RawTcpTransport;

fn cancelled(url: &str) -> TransportError {
    TransportError::new(TransportErrorKind::Cancelled, url, None)
}

struct RawBody {
    stream: TcpStream,
    buffered: Vec<u8>,
    pos: usize,
    remaining: Option<u64>,
    cancel: CancelToken,
    url: String,
}

impl Read for RawBody {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::other(cancelled(&self.url)));
        }
        if buf.is_empty() || self.remaining == Some(0) {
            return Ok(0);
        }
        let n = if self.pos < self.buffered.len() {
            let n = buf.len().min(self.buffered.len() - self.pos);
            buf[..n].copy_from_slice(&self.buffered[self.pos..self.pos + n]);
            self.pos += n;
            n
        } else {
            self.stream.read(buf)?
        };
        if let Some(left) = self.remaining.as_mut() {
            if n == 0 {
                return Err(io::Error::other(TransportError::new(
                    TransportErrorKind::Io,
                    &self.url,
                    Some("connection closed before content-length bytes".into()),
                )));
            }
            *left = left.saturating_sub(n as u64);
        }
        Ok(n)
    }
}

impl BlockingTransport for RawTcpTransport {
    fn get(
        &self,
        request: &Request,
        cancel: &CancelToken,
    ) -> Result<BlockingResponse, TransportError> {
        let io_err = |e: io::Error| {
            TransportError::new(TransportErrorKind::Io, &request.url, Some(Box::new(e)))
        };
        let mut url = request.url.clone();
        for _ in 0..=5 {
            if cancel.is_cancelled() {
                return Err(cancelled(&request.url));
            }
            let rest = url
                .strip_prefix("http://")
                .ok_or_else(|| TransportError::new(TransportErrorKind::Unsupported, &url, None))?;
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            let path = if path.is_empty() { "/" } else { path };
            let mut stream = TcpStream::connect(authority).map_err(|e| {
                TransportError::new(TransportErrorKind::Connect, &url, Some(Box::new(e)))
            })?;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(io_err)?;
            let mut head = format!(
                "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: lunepack-test\r\n"
            );
            if let Some(range) = request.range {
                head.push_str(&format!("Range: {}\r\n", range.header_value()));
            }
            if let Some(validator) = &request.if_range {
                head.push_str(&format!("If-Range: {}\r\n", validator.header_value()));
            }
            head.push_str("Connection: close\r\n\r\n");
            stream.write_all(head.as_bytes()).map_err(io_err)?;

            // Read until the end of the response head.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let end = loop {
                if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at;
                }
                let n = stream.read(&mut tmp).map_err(io_err)?;
                if n == 0 {
                    return Err(TransportError::new(
                        TransportErrorKind::Protocol,
                        &url,
                        Some("connection closed inside the head".into()),
                    ));
                }
                buf.extend_from_slice(&tmp[..n]);
            };
            let text = String::from_utf8_lossy(&buf[..end]).into_owned();
            let mut lines = text.split("\r\n");
            let status: u16 = lines
                .next()
                .and_then(|l| l.split(' ').nth(1))
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| TransportError::new(TransportErrorKind::Protocol, &url, None))?;
            let headers: Vec<(String, Vec<u8>)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().as_bytes().to_vec()))
                .collect();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let location = headers
                    .iter()
                    .find(|(n, _)| n == "location")
                    .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
                    .unwrap_or_default();
                url = if location.starts_with("http://") {
                    location
                } else {
                    format!("http://{authority}{location}")
                };
                continue;
            }
            let remaining = headers
                .iter()
                .find(|(n, _)| n == "content-length")
                .and_then(|(_, v)| std::str::from_utf8(v).ok()?.parse::<u64>().ok());
            return Ok(BlockingResponse {
                head: Head { status, headers },
                body: Box::new(RawBody {
                    stream,
                    buffered: buf[end + 4..].to_vec(),
                    pos: 0,
                    remaining,
                    cancel: cancel.clone(),
                    url: request.url.clone(),
                }),
            });
        }
        Err(TransportError::new(
            TransportErrorKind::Unsupported,
            &request.url,
            Some("too many redirects".into()),
        ))
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
            return v;
        }
        assert!(Instant::now() < deadline, "future still pending after 10 s");
        std::thread::yield_now();
    }
}

const LARGE: &str = TransportFixture::LARGE;

fn url(name: &str) -> String {
    format!("{FAKE_BASE_URL}/{name}")
}

fn request(name: &str, range: Option<ByteRange>, if_range: Option<Validator>) -> Request {
    Request {
        url: url(name),
        range,
        if_range,
    }
}

fn first_100() -> Option<ByteRange> {
    Some(ByteRange {
        first: 0,
        last: Some(99),
    })
}

/// A whole response through the blocking fake: the head and the body (or the first body error).
fn fetch_blocking(
    t: &FakeBlockingTransport,
    request: &Request,
) -> (Head, Result<Vec<u8>, io::Error>) {
    let response = t.get(request, &CancelToken::new()).expect("a response");
    let mut body = Vec::new();
    let result = response.body.take(8 * 1024 * 1024).read_to_end(&mut body);
    (response.head, result.map(|_| body))
}

fn info_of(head: &Head) -> Result<ResponseInfo, RangeError> {
    ResponseInfo::from_head(head)
}

#[test]
fn the_blocking_fake_passes_the_blocking_suite() {
    let t = FakeBlockingTransport::fixture();
    run_blocking_transport_suite(&t, FAKE_BASE_URL, &|| t.requests());
}

#[test]
fn the_async_fake_passes_the_async_suite() {
    let t = FakeTransport::fixture();
    run_transport_suite(&t, FAKE_BASE_URL, &|| t.requests());
}

#[test]
fn the_loopback_server_passes_the_suite_through_a_raw_tcp_client() {
    let server = LoopbackServer::fixture().expect("bind");
    run_blocking_transport_suite(&RawTcpTransport, &server.base_url(), &|| {
        server.origin().requests()
    });
}

#[test]
fn the_suites_catch_a_transport_that_breaks_the_contract() {
    // A fake that ignores Range answers 200 to a range request: the suite must fail.
    let broken = std::panic::catch_unwind(|| {
        let t = FakeBlockingTransport::fixture().with_fault(TransportFault::IgnoreRange);
        run_blocking_transport_suite(&t, FAKE_BASE_URL, &|| t.requests());
    });
    assert!(
        broken.is_err(),
        "the suite passed a transport that ignores Range"
    );
    // ...and one that gzips.
    let broken = std::panic::catch_unwind(|| {
        let t = FakeTransport::fixture().with_fault(TransportFault::GzipEncoded);
        run_transport_suite(&t, FAKE_BASE_URL, &|| t.requests());
    });
    assert!(
        broken.is_err(),
        "the suite passed a transport that sends content-encoding"
    );
}

#[test]
fn the_suites_catch_a_transport_that_sends_accept_encoding() {
    let t = FakeBlockingTransport::fixture();
    let broken = std::panic::catch_unwind(|| {
        run_blocking_transport_suite(&t, FAKE_BASE_URL, &|| {
            let mut log = t.requests();
            for r in &mut log {
                r.accept_encoding = Some("gzip".to_owned());
            }
            log
        });
    });
    assert!(broken.is_err());
}

#[test]
fn every_fake_logs_what_it_was_sent() {
    let t = FakeBlockingTransport::fixture();
    let etag = Validator::from_etag(b"\"x\"").unwrap();
    let _ = fetch_blocking(&t, &request(LARGE, first_100(), Some(etag)));
    let log = t.requests();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].url, format!("/{LARGE}"));
    assert_eq!(log[0].range, first_100());
    assert_eq!(log[0].range_header.as_deref(), Some("bytes=0-99"));
    assert_eq!(log[0].if_range.as_deref(), Some("\"x\""));
    assert_eq!(log[0].accept_encoding, None);
    // A redirect logs both hops.
    t.origin().clear_requests();
    let _ = fetch_blocking(&t, &request(TransportFixture::ALIAS, None, None));
    assert_eq!(t.requests().len(), 2);
}

#[test]
fn faults_through_the_blocking_fake() {
    let len = TransportFixture::LARGE_LEN as u64;
    let with = |f: TransportFault| FakeBlockingTransport::fixture().with_fault(f);

    // IgnoreRange: 200 with everything.
    let t = with(TransportFault::IgnoreRange);
    let (head, body) = fetch_blocking(&t, &request(LARGE, first_100(), None));
    assert_eq!(head.status, 200);
    assert_eq!(body.unwrap().len() as u64, len);
    assert_eq!(
        classify(first_100(), &info_of(&head).unwrap(), len, 100),
        Ok(lunepack_core::Outcome::Full)
    );

    // WrongContentRange and NoContentRange are refused by the core's rules.
    let t = with(TransportFault::WrongContentRange);
    let (head, _) = fetch_blocking(&t, &request(LARGE, first_100(), None));
    assert_eq!(head.status, 206);
    assert!(matches!(
        classify(first_100(), &info_of(&head).unwrap(), len, 100),
        Err(RangeError::ContentRangeMismatch { .. })
    ));
    let t = with(TransportFault::NoContentRange);
    let (head, _) = fetch_blocking(&t, &request(LARGE, first_100(), None));
    assert_eq!(
        classify(first_100(), &info_of(&head).unwrap(), len, 100),
        Err(RangeError::ContentRangeMissing)
    );

    // TruncateAfter: content-length says more than arrives.
    let t = with(TransportFault::TruncateAfter(10));
    let (head, body) = fetch_blocking(&t, &request(LARGE, None, None));
    assert_eq!(body.unwrap().len(), 10);
    assert_eq!(info_of(&head).unwrap().content_length, Some(len));

    // Endless: more than the file, no end, no content-length.
    let t = with(TransportFault::Endless);
    let (head, body) = fetch_blocking(&t, &request(LARGE, None, None));
    assert_eq!(info_of(&head).unwrap().content_length, None);
    assert_eq!(
        body.unwrap().len(),
        8 * 1024 * 1024,
        "stopped only by the test's cap"
    );

    // ExtraBytes.
    let t = with(TransportFault::ExtraBytes(7));
    let (head, body) = fetch_blocking(&t, &request(LARGE, None, None));
    assert_eq!(info_of(&head).unwrap().content_length, None);
    assert_eq!(body.unwrap().len() as u64, len + 7);

    // Status.
    let t = with(TransportFault::Status(503));
    let (head, body) = fetch_blocking(&t, &request(LARGE, None, None));
    assert_eq!(head.status, 503);
    assert!(body.unwrap().is_empty());

    // GzipEncoded and DuplicateHeader are refused by the core's rules.
    let t = with(TransportFault::GzipEncoded);
    let (head, _) = fetch_blocking(&t, &request(LARGE, None, None));
    assert_eq!(info_of(&head), Err(RangeError::ContentCoding));
    let t = with(TransportFault::DuplicateHeader("etag"));
    let (head, _) = fetch_blocking(&t, &request(LARGE, None, None));
    assert_eq!(
        info_of(&head),
        Err(RangeError::DuplicateHeader { name: "etag" })
    );
    // A header the answer lacks is added twice.
    let t = with(TransportFault::DuplicateHeader("x-new"));
    let (head, _) = fetch_blocking(&t, &request(LARGE, None, None));
    assert_eq!(head.headers.iter().filter(|(n, _)| n == "x-new").count(), 2);

    // ErrorAfter: n good bytes, then an I/O error that carries a TransportError.
    let t = with(TransportFault::ErrorAfter(10));
    let response = t
        .get(&request(LARGE, None, None), &CancelToken::new())
        .unwrap();
    let mut body = response.body;
    let mut got = Vec::new();
    let err = body.read_to_end(&mut got).unwrap_err();
    assert_eq!(got.len(), 10);
    let inner = err
        .get_ref()
        .unwrap()
        .downcast_ref::<TransportError>()
        .unwrap();
    assert_eq!(inner.kind, TransportErrorKind::Io);
}

#[test]
fn change_etag_after_makes_the_old_validator_stale() {
    let t = FakeBlockingTransport::fixture().with_fault(TransportFault::ChangeETagAfter(1));
    let (head, _) = fetch_blocking(&t, &request(LARGE, None, None));
    let validator = info_of(&head).unwrap().validator.unwrap();
    let (head, body) = fetch_blocking(&t, &request(LARGE, first_100(), Some(validator.clone())));
    assert_eq!(head.status, 200, "the tag changed, so If-Range fails");
    assert_eq!(body.unwrap().len(), TransportFixture::LARGE_LEN);
    assert_ne!(info_of(&head).unwrap().validator, Some(validator));
}

#[test]
fn slow_chunks_deliver_one_byte_at_a_time_through_the_async_fake() {
    let t = FakeTransport::fixture().with_fault(TransportFault::SlowChunks);
    block_on(async {
        let mut response = t
            .get(request(TransportFixture::ONE_BYTE, None, None))
            .await
            .unwrap();
        assert_eq!(response.body.next_chunk().await.unwrap(), Some(vec![0x41]));
        assert_eq!(response.body.next_chunk().await.unwrap(), None);
        let mut response = t.get(request(LARGE, first_100(), None)).await.unwrap();
        let mut sizes = Vec::new();
        while let Some(chunk) = response.body.next_chunk().await.unwrap() {
            sizes.push(chunk.len());
        }
        assert_eq!(sizes, vec![1; 100]);
    });
}

#[test]
fn pending_forever_never_resolves_next_chunk() {
    let t = FakeTransport::fixture().with_fault(TransportFault::PendingForever);
    let mut cx = Context::from_waker(Waker::noop());
    let mut response = block_on(t.get(request(LARGE, None, None))).unwrap();
    let mut chunk = response.body.next_chunk();
    for _ in 0..1000 {
        assert!(matches!(chunk.as_mut().poll(&mut cx), Poll::Pending));
    }
}

#[test]
fn the_async_fake_reports_error_after_and_endless() {
    let t = FakeTransport::fixture().with_fault(TransportFault::ErrorAfter(10));
    block_on(async {
        let mut response = t.get(request(LARGE, None, None)).await.unwrap();
        let mut got = 0;
        let err = loop {
            match response.body.next_chunk().await {
                Ok(Some(chunk)) => got += chunk.len(),
                Ok(None) => panic!("the body ended without the error"),
                Err(e) => break e,
            }
        };
        assert_eq!((got, err.kind), (10, TransportErrorKind::Io));
    });
    let t = FakeTransport::fixture().with_fault(TransportFault::Endless);
    block_on(async {
        let mut response = t.get(request(LARGE, None, None)).await.unwrap();
        let mut got = 0usize;
        while got < 1_000_000 {
            got += response
                .body
                .next_chunk()
                .await
                .unwrap()
                .expect("endless")
                .len();
        }
    });
}

#[test]
fn the_blocking_fake_stops_a_read_when_cancelled() {
    let t = FakeBlockingTransport::fixture().with_fault(TransportFault::Endless);
    let cancel = CancelToken::new();
    let mut response = t.get(&request(LARGE, None, None), &cancel).unwrap();
    let mut buf = [0u8; 4096];
    assert!(response.body.read(&mut buf).unwrap() > 0);
    cancel.cancel();
    let err = response.body.read(&mut buf).unwrap_err();
    let inner = err
        .get_ref()
        .unwrap()
        .downcast_ref::<TransportError>()
        .unwrap();
    assert_eq!(inner.kind, TransportErrorKind::Cancelled);
    // And before the request.
    assert_eq!(
        t.get(&request(LARGE, None, None), &cancel)
            .unwrap_err()
            .kind,
        TransportErrorKind::Cancelled
    );
}

#[test]
fn fakes_refuse_urls_without_a_scheme_and_follow_at_most_five_redirects() {
    let t = FakeBlockingTransport::fixture();
    let err = t
        .get(
            &Request {
                url: "large.bin".to_owned(),
                range: None,
                if_range: None,
            },
            &CancelToken::new(),
        )
        .unwrap_err();
    assert_eq!(err.kind, TransportErrorKind::Unsupported);
    t.origin().redirect("/loop-a", "/loop-b");
    t.origin().redirect("/loop-b", "/loop-a");
    let err = t
        .get(&request("loop-a", None, None), &CancelToken::new())
        .unwrap_err();
    assert_eq!(err.kind, TransportErrorKind::Unsupported);
}

#[test]
fn the_fake_transports_are_object_safe_and_shareable() {
    let a: Arc<dyn Transport> = Arc::new(FakeTransport::fixture());
    let b: Arc<dyn BlockingTransport> = Arc::new(FakeBlockingTransport::fixture());
    let (a2, b2) = (a.clone(), b.clone());
    std::thread::spawn(move || {
        drop(a2.get(request(LARGE, None, None)));
        let _ = b2.get(&request(LARGE, None, None), &CancelToken::new());
    })
    .join()
    .unwrap();
}

// ---- the loopback server ------------------------------------------------------------------------------

fn raw(server: &LoopbackServer, name: &str, range: Option<ByteRange>) -> (Head, Vec<u8>) {
    let request = Request {
        url: server.url(name),
        range,
        if_range: None,
    };
    let mut response = RawTcpTransport
        .get(&request, &CancelToken::new())
        .expect("a response");
    let mut body = Vec::new();
    response.body.read_to_end(&mut body).expect("body");
    (response.head, body)
}

#[test]
fn the_loopback_server_binds_only_to_127_0_0_1() {
    let server = LoopbackServer::fixture().unwrap();
    assert!(server.addr().ip().is_loopback() && server.addr().is_ipv4());
    assert!(server.base_url().starts_with("http://127.0.0.1:"));
}

#[test]
fn the_loopback_server_answers_404_and_redirects_and_ranges() {
    let server = LoopbackServer::fixture().unwrap();
    let (head, _) = raw(&server, "nope.bin", None);
    assert_eq!(head.status, 404);
    let large = TransportFixture::bytes(LARGE).unwrap();
    let (head, body) = raw(&server, TransportFixture::ALIAS, None);
    assert_eq!((head.status, body), (200, large.clone()));
    let (head, body) = raw(
        &server,
        LARGE,
        Some(ByteRange {
            first: 10,
            last: Some(19),
        }),
    );
    assert_eq!((head.status, body), (206, large[10..20].to_vec()));
    // An unsatisfiable range.
    let (head, _) = raw(
        &server,
        LARGE,
        Some(ByteRange {
            first: large.len() as u64,
            last: None,
        }),
    );
    assert_eq!(head.status, 416);
    // A user-added file and redirect.
    server.origin().put("/new/file", b"hello".to_vec());
    server.origin().redirect("/old", "/new/file");
    assert_eq!(raw(&server, "old", None).1, b"hello");
}

#[test]
fn the_loopback_server_puts_faults_on_the_wire() {
    let server = LoopbackServer::fixture().unwrap();
    let len = TransportFixture::LARGE_LEN;

    // One byte per chunk still delivers the whole body.
    server.origin().set_faults(vec![TransportFault::SlowChunks]);
    let (_, body) = raw(&server, TransportFixture::ONE_BYTE, None);
    assert_eq!(body, [0x41]);
    let (_, body) = raw(
        &server,
        LARGE,
        Some(ByteRange {
            first: 0,
            last: Some(999),
        }),
    );
    assert_eq!(body.len(), 1000);

    // ExtraBytes: no content-length, the connection close ends a longer body.
    server
        .origin()
        .set_faults(vec![TransportFault::ExtraBytes(5)]);
    let (head, body) = raw(&server, LARGE, None);
    assert!(head.headers.iter().all(|(n, _)| n != "content-length"));
    assert_eq!(body.len(), len + 5);

    // Truncation and an error both end the body early while content-length promises more.
    for fault in [
        TransportFault::TruncateAfter(10),
        TransportFault::ErrorAfter(10),
    ] {
        server.origin().set_faults(vec![fault.clone()]);
        let request = Request {
            url: server.url(LARGE),
            range: None,
            if_range: None,
        };
        let mut response = RawTcpTransport.get(&request, &CancelToken::new()).unwrap();
        let mut body = Vec::new();
        let result = response.body.read_to_end(&mut body);
        assert!(
            result.is_err(),
            "{fault:?}: a short body must be an error, got {} bytes",
            body.len()
        );
        assert_eq!(body.len(), 10, "{fault:?}");
    }

    // Status and content-encoding.
    server
        .origin()
        .set_faults(vec![TransportFault::Status(503)]);
    assert_eq!(raw(&server, LARGE, None).0.status, 503);
    server
        .origin()
        .set_faults(vec![TransportFault::GzipEncoded]);
    assert_eq!(
        info_of(&raw(&server, LARGE, None).0),
        Err(RangeError::ContentCoding)
    );
    server
        .origin()
        .set_faults(vec![TransportFault::DuplicateHeader("etag")]);
    assert!(info_of(&raw(&server, LARGE, None).0).is_err());
}

#[test]
fn the_loopback_server_logs_requests() {
    let server = LoopbackServer::fixture().unwrap();
    raw(&server, LARGE, first_100());
    let log = server.origin().requests();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].url, format!("/{LARGE}"));
    assert_eq!(log[0].range, first_100());
    assert_eq!(log[0].accept_encoding, None);
}

#[test]
fn dropping_the_loopback_server_stops_it_within_a_second() {
    let server = LoopbackServer::fixture().unwrap();
    let addr = server.addr();
    // A connection that never sends a request, and an endless download nobody reads.
    let _stalled = TcpStream::connect(addr).unwrap();
    server.origin().set_faults(vec![TransportFault::Endless]);
    let mut endless = TcpStream::connect(addr).unwrap();
    write!(endless, "GET /{LARGE} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut buf = [0u8; 16];
    endless.read_exact(&mut buf).unwrap();
    let started = Instant::now();
    drop(server);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "stopping took {:?}",
        started.elapsed()
    );
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err(),
        "the port still accepts connections"
    );
}

// ---- MemFs (M4 step 3) -----------------------------------------------------------------------------------

fn mem() -> (MemFs, &'static Path) {
    let fs = MemFs::new();
    let root = Path::new("/mem");
    fs.create_dir_all(root).unwrap();
    fs.sync_dir(Path::new("/")).unwrap();
    (fs, root)
}

fn put(fs: &MemFs, path: &Path, bytes: &[u8], sync: bool) {
    let mut f = fs.create_new(path).unwrap();
    f.write_all(bytes).unwrap();
    if sync {
        f.sync().unwrap();
    }
}

fn after(fs: &MemFs, mode: RecoverMode, path: &Path) -> Option<Vec<u8>> {
    let image = fs.recover(mode);
    image
        .symlink_metadata(path)
        .unwrap()
        .map(|_| image.read_capped(path, 1 << 20).unwrap())
}

#[test]
fn memfs_passes_the_fs_suite_with_symlinks_everywhere() {
    let (fs, root) = mem();
    run_fs_suite_with(&fs, root, true);
    // The suite leaves nothing behind.
    assert!(fs.list_dir(root).unwrap().is_empty());
    // And on a second run over the same disk.
    run_fs_suite(&fs, root);
}

#[test]
fn the_fs_suite_catches_a_fs_that_follows_symlinks_on_create() {
    // A wrapper whose create_new follows a dangling symlink (writes through it) must fail the suite.
    struct Follows(MemFs);
    impl Fs for Follows {
        fn read_capped(&self, p: &Path, m: u64) -> Result<Vec<u8>, lunepack_core::FsError> {
            self.0.read_capped(p, m)
        }
        fn open_read(
            &self,
            p: &Path,
        ) -> Result<Box<dyn lunepack_core::ReadAt>, lunepack_core::FsError> {
            self.0.open_read(p)
        }
        fn create_new(
            &self,
            p: &Path,
        ) -> Result<Box<dyn lunepack_core::FileWrite>, lunepack_core::FsError> {
            // Lets a dangling symlink through as if the path were free.
            match self.0.create_new(p) {
                Err(e)
                    if e.kind == FsErrorKind::AlreadyExists
                        && self.0.read_capped(p, 1).is_err() =>
                {
                    Ok(Box::new(Sink))
                }
                other => other,
            }
        }
        fn open_append(
            &self,
            p: &Path,
        ) -> Result<Box<dyn lunepack_core::FileWrite>, lunepack_core::FsError> {
            self.0.open_append(p)
        }
        fn truncate(&self, p: &Path, l: u64) -> Result<(), lunepack_core::FsError> {
            self.0.truncate(p, l)
        }
        fn rename(&self, a: &Path, b: &Path) -> Result<(), lunepack_core::FsError> {
            self.0.rename(a, b)
        }
        fn remove_file(&self, p: &Path) -> Result<(), lunepack_core::FsError> {
            self.0.remove_file(p)
        }
        fn remove_dir_all_nofollow(&self, p: &Path) -> Result<(), lunepack_core::FsError> {
            self.0.remove_dir_all_nofollow(p)
        }
        fn create_dir_all(&self, p: &Path) -> Result<(), lunepack_core::FsError> {
            self.0.create_dir_all(p)
        }
        fn list_dir(
            &self,
            p: &Path,
        ) -> Result<Vec<lunepack_core::DirEntryInfo>, lunepack_core::FsError> {
            self.0.list_dir(p)
        }
        fn symlink_metadata(
            &self,
            p: &Path,
        ) -> Result<Option<lunepack_core::Meta>, lunepack_core::FsError> {
            self.0.symlink_metadata(p)
        }
        fn sync_dir(&self, p: &Path) -> Result<(), lunepack_core::FsError> {
            self.0.sync_dir(p)
        }
        fn copy_file(&self, a: &Path, b: &Path) -> Result<(), lunepack_core::FsError> {
            self.0.copy_file(a, b)
        }
        fn set_exec(&self, p: &Path, e: bool) -> Result<(), lunepack_core::FsError> {
            self.0.set_exec(p, e)
        }
        fn symlink(&self, t: &str, l: &Path) -> Result<(), lunepack_core::FsError> {
            self.0.symlink(t, l)
        }
        fn try_lock(
            &self,
            p: &Path,
        ) -> Result<Option<Box<dyn lunepack_core::LockGuard>>, lunepack_core::FsError> {
            self.0.try_lock(p)
        }
    }
    struct Sink;
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl lunepack_core::FileWrite for Sink {
        fn sync(&mut self) -> Result<(), lunepack_core::FsError> {
            Ok(())
        }
    }
    let (fs, root) = mem();
    let broken = std::panic::catch_unwind(|| run_fs_suite_with(&Follows(fs), root, true));
    assert!(
        broken.is_err(),
        "the suite passed a create_new that accepts a dangling symlink"
    );
}

#[test]
fn a_synced_file_survives_drop_volatile_and_an_unsynced_one_does_not() {
    let (fs, root) = mem();
    put(&fs, &root.join("synced"), b"durable", true);
    put(&fs, &root.join("unsynced"), b"volatile", false);
    fs.sync_dir(root).unwrap();
    // The entries are durable; the bytes of `unsynced` are not.
    assert_eq!(
        after(&fs, RecoverMode::DropVolatile, &root.join("synced")),
        Some(b"durable".to_vec())
    );
    assert_eq!(
        after(&fs, RecoverMode::DropVolatile, &root.join("unsynced")),
        Some(Vec::new())
    );
    // A file whose directory was never synced is gone, synced bytes or not.
    put(&fs, &root.join("no-dir-sync"), b"x", true);
    assert_eq!(
        after(&fs, RecoverMode::DropVolatile, &root.join("no-dir-sync")),
        None
    );
    assert_eq!(
        after(&fs, RecoverMode::KeepVolatile, &root.join("no-dir-sync")),
        Some(b"x".to_vec())
    );
}

#[test]
fn keep_volatile_keeps_everything_and_torn_volatile_keeps_a_prefix() {
    let (fs, root) = mem();
    put(&fs, &root.join("f"), b"0123456789", false);
    fs.sync_dir(root).unwrap();
    let f = root.join("f");
    assert_eq!(after(&fs, RecoverMode::DropVolatile, &f), Some(Vec::new()));
    assert_eq!(
        after(&fs, RecoverMode::KeepVolatile, &f),
        Some(b"0123456789".to_vec())
    );
    assert_eq!(
        after(&fs, RecoverMode::TornVolatile(3), &f),
        Some(b"012".to_vec())
    );
    assert_eq!(
        after(&fs, RecoverMode::TornVolatile(0), &f),
        Some(Vec::new())
    );
    assert_eq!(
        after(&fs, RecoverMode::TornVolatile(99), &f),
        Some(b"0123456789".to_vec())
    );
    // An append after a sync: the synced prefix stays, `n` more bytes survive.
    let mut w = fs.open_append(&f).unwrap();
    w.sync().unwrap();
    w.write_all(b"ABCDEF").unwrap();
    assert_eq!(
        after(&fs, RecoverMode::TornVolatile(2), &f),
        Some(b"0123456789AB".to_vec())
    );
    assert_eq!(
        after(&fs, RecoverMode::DropVolatile, &f),
        Some(b"0123456789".to_vec())
    );
    // A cut file keeps its synced bytes in the torn image.
    fs.truncate(&f, 4).unwrap();
    assert_eq!(
        after(&fs, RecoverMode::TornVolatile(1), &f),
        Some(b"0123456789".to_vec())
    );
    assert_eq!(
        after(&fs, RecoverMode::KeepVolatile, &f),
        Some(b"0123".to_vec())
    );
}

#[test]
fn a_rename_is_volatile_until_its_directory_is_synced() {
    let (fs, root) = mem();
    put(&fs, &root.join("old"), b"data", true);
    fs.sync_dir(root).unwrap();
    fs.rename(&root.join("old"), &root.join("new")).unwrap();
    assert_eq!(
        after(&fs, RecoverMode::DropVolatile, &root.join("old")),
        Some(b"data".to_vec())
    );
    assert_eq!(
        after(&fs, RecoverMode::DropVolatile, &root.join("new")),
        None
    );
    fs.sync_dir(root).unwrap();
    assert_eq!(
        after(&fs, RecoverMode::DropVolatile, &root.join("old")),
        None
    );
    assert_eq!(
        after(&fs, RecoverMode::DropVolatile, &root.join("new")),
        Some(b"data".to_vec())
    );
    // The same for a removal.
    fs.remove_file(&root.join("new")).unwrap();
    assert!(after(&fs, RecoverMode::DropVolatile, &root.join("new")).is_some());
    fs.sync_dir(root).unwrap();
    assert!(after(&fs, RecoverMode::DropVolatile, &root.join("new")).is_none());
}

/// The commit sequence of M4-D5: create_new, write, sync, sync_dir.
fn commit(fs: &MemFs, dir: &Path) -> Result<(), lunepack_core::FsError> {
    let mut f = fs.create_new(&dir.join("rec"))?;
    f.write_all(b"record")
        .map_err(|e| lunepack_core::FsError::from_io(dir, e))?;
    f.sync()?;
    fs.sync_dir(dir)
}

#[test]
fn crash_after_n_fails_op_n_and_everything_later() {
    let (probe, root) = mem();
    let before = probe.op_count();
    commit(&probe, root).unwrap();
    let ops = probe.op_count() - before;
    assert_eq!(ops, 4, "create_new, write, sync, sync_dir");

    for n in 0..ops {
        let (fs, root) = mem();
        let start = fs.op_count();
        fs.crash_after(start + n);
        let err = commit(&fs, root).unwrap_err();
        assert_eq!(err.kind, FsErrorKind::Crashed, "crash at op {n}");
        assert!(fs.is_crashed());
        assert_eq!(fs.op_count(), start + n, "the crashed op is not counted");
        // Everything after fails, reads included.
        assert_eq!(
            fs.read_capped(&root.join("rec"), 10).unwrap_err().kind,
            FsErrorKind::Crashed
        );
        assert_eq!(
            fs.create_dir_all(&root.join("x")).unwrap_err().kind,
            FsErrorKind::Crashed
        );
        assert_eq!(
            fs.try_lock(&root.join("l")).err().map(|e| e.kind),
            Some(FsErrorKind::Crashed)
        );
        // The disk after the crash: the record is durable only if sync_dir ran (n == 4 never crashes).
        let image = fs.recover(RecoverMode::DropVolatile);
        assert!(!image.is_crashed());
        assert_eq!(image.op_count(), 0);
        assert_eq!(
            image.symlink_metadata(&root.join("rec")).unwrap(),
            None,
            "op {n}"
        );
    }
    // Crash exactly after the last op: nothing fails, the record is durable.
    let (fs, root) = mem();
    fs.crash_after(fs.op_count() + ops);
    commit(&fs, root).unwrap();
    assert_eq!(
        after(&fs, RecoverMode::DropVolatile, &root.join("rec")),
        Some(b"record".to_vec())
    );
}

#[test]
fn a_writer_fails_with_a_crashed_fs_error_after_the_crash() {
    let (fs, root) = mem();
    let mut f = fs.create_new(&root.join("w")).unwrap();
    fs.crash_now();
    let err = f.write_all(b"x").unwrap_err();
    let inner = err
        .get_ref()
        .unwrap()
        .downcast_ref::<lunepack_core::FsError>()
        .unwrap();
    assert_eq!(inner.kind, FsErrorKind::Crashed);
    assert_eq!(f.sync().unwrap_err().kind, FsErrorKind::Crashed);
    assert!(f.flush().is_err());
}

#[test]
fn locks_are_per_path_and_a_killed_process_releases_them() {
    let (fs, root) = mem();
    let a = fs.process();
    let b = fs.process();
    let lock = root.join("lock");
    let held = a.try_lock(&lock).unwrap().expect("a takes it");
    assert!(b.try_lock(&lock).unwrap().is_none());
    assert!(fs.try_lock(&lock).unwrap().is_none());
    assert!(b.try_lock(&root.join("other")).unwrap().is_some());
    fs.kill_process(&a);
    let taken = b.try_lock(&lock).unwrap();
    assert!(taken.is_some(), "the dead process's lock is free");
    // The dead process's old guard dropping must not release b's lock.
    drop(held);
    assert!(fs.try_lock(&lock).unwrap().is_none());
    drop(taken);
    assert!(fs.try_lock(&lock).unwrap().is_some());
    // A missing directory is an error, a recovered disk holds no locks.
    assert_eq!(
        fs.try_lock(&root.join("nodir/lock")).err().map(|e| e.kind),
        Some(FsErrorKind::NotFound)
    );
    let _guard = fs.try_lock(&lock).unwrap().unwrap();
    assert!(
        fs.recover(RecoverMode::KeepVolatile)
            .try_lock(&lock)
            .unwrap()
            .is_some()
    );
}

#[test]
fn memfs_follows_relative_symlinks_and_stops_loops() {
    let (fs, root) = mem();
    fs.create_dir_all(&root.join("d/e")).unwrap();
    put(&fs, &root.join("d/file"), b"via link", true);
    fs.symlink("../file", &root.join("d/e/rel")).unwrap();
    assert_eq!(
        fs.read_capped(&root.join("d/e/rel"), 100).unwrap(),
        b"via link"
    );
    fs.symlink("/mem/d", &root.join("abs")).unwrap();
    assert_eq!(
        fs.read_capped(&root.join("abs/file"), 100).unwrap(),
        b"via link"
    );
    assert_eq!(
        fs.list_dir(&root.join("abs")).unwrap().len(),
        2,
        "list_dir follows a symlink to a directory"
    );
    fs.symlink("b", &root.join("a")).unwrap();
    fs.symlink("a", &root.join("b")).unwrap();
    assert_eq!(
        fs.read_capped(&root.join("a"), 1).unwrap_err().kind,
        FsErrorKind::Other
    );
    assert_eq!(
        fs.symlink_metadata(&root.join("a"))
            .unwrap()
            .map(|m| m.kind),
        Some(FileKind::Symlink)
    );
    // Symlinks are entries: volatile until the directory is synced, then durable.
    assert!(
        fs.recover(RecoverMode::DropVolatile)
            .symlink_metadata(&root.join("abs"))
            .unwrap()
            .is_none()
    );
    fs.sync_dir(root).unwrap();
    assert!(
        fs.recover(RecoverMode::DropVolatile)
            .symlink_metadata(&root.join("abs"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn memfs_errors_name_only_the_file() {
    let (fs, root) = mem();
    let err = fs
        .read_capped(&root.join("secret-dir/inner.txt"), 1)
        .unwrap_err();
    let shown = format!("{err} {err:?}");
    assert!(
        !shown.contains("secret-dir") && !shown.contains("/mem"),
        "{shown}"
    );
    let err = fs.read_capped(&root.join("only-name.txt"), 1).unwrap_err();
    assert!(format!("{err}").contains("only-name.txt"));
}
