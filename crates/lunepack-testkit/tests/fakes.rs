//! The testkit's own tests: the fakes pass the contract suites, and each fake rejects what it must.

use lunepack_core::error::{CodecError, SignatureError};
use lunepack_core::{
    Clock, Codec, CodecId, DecodeReport, Encoder, Error, FrameView, Hasher, Sha256Digest,
    SignatureAlg, Signer, StreamView, Verifier,
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
