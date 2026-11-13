//! Known answers for the LZMA codec (M3 step 3).
//!
//! - Encoder: four inputs from a fixed-seed xorshift, each encoded with every codec that applies,
//!   give pinned frame lengths and SHA-256s. They must hold on every host (macOS arm64, Linux and
//!   Windows x86_64 in CI): the encoder's bytes may not depend on the host (M3-D7).
//! - Decoder: one small committed frame per codec (produced by this encoder) decodes to a pinned
//!   output.
//! - The test executable itself round-trips through every codec its header selects (M3-D6).
//! - The dictionary follows the stream's length: 4096 for 3000 bytes, 16 MiB for 20 MiB.
//!
//! To regenerate the tables after a deliberate encoder change, run the ignored `print_*` tests with
//! `--ignored --nocapture` and paste their output.

use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::{Codec, CodecId, EncodedFrame, Encoder, FrameView, StreamView};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------------------------
// Inputs

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 32) as u8
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn random(len: usize, rng: &mut XorShift) -> Vec<u8> {
    (0..len).map(|_| rng.byte()).collect()
}

fn text(len: usize, rng: &mut XorShift) -> Vec<u8> {
    const WORDS: [&str; 16] = [
        "update",
        "release",
        "the",
        "a",
        "manifest",
        "signed",
        "frame",
        "of",
        "delta",
        "and",
        "installer",
        "is",
        "verified",
        "before",
        "placed",
        "file",
    ];
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        out.extend_from_slice(WORDS[rng.below(16) as usize].as_bytes());
        out.push(match rng.below(12) {
            0 => b'\n',
            1 => b',',
            _ => b' ',
        });
    }
    out.truncate(len);
    out
}

/// x86 code-like bytes: near calls and jumps with small displacements among common opcodes.
fn x86_like(len: usize, rng: &mut XorShift) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        match rng.below(8) {
            op @ (0 | 1) => {
                out.push(if op == 0 { 0xE8 } else { 0xE9 });
                let rel = rng.below(0x1_0000) as i32 - 0x8000;
                out.extend_from_slice(&rel.to_le_bytes());
            }
            2 => out.extend_from_slice(&[0x48, 0x89, 0xE5]),
            3 => out.push(0x55),
            4 => out.extend_from_slice(&[0x48, 0x83, 0xEC, rng.byte() & 0xF8]),
            5 => out.push(0xC3),
            6 => out.extend_from_slice(&[0x8B, 0x45, rng.byte()]),
            _ => out.push(rng.byte()),
        }
    }
    out.truncate(len);
    out
}

/// ARM64 code-like words: BL and ADRP (what the ARM64 BCJ filter converts) among common
/// instructions.
fn arm64_like(len: usize, rng: &mut XorShift) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 4);
    while out.len() < len {
        let word: u32 = match rng.below(6) {
            0 => 0x9400_0000 | rng.below(1 << 16) as u32,
            1 => 0x9000_0000 | ((rng.below(1 << 10) as u32) << 5) | rng.below(31) as u32,
            2 => 0xD65F_03C0,
            3 => 0xA9BF_7BFD,
            4 => 0x9100_03FD,
            _ => 0xF940_0000 | rng.below(1 << 22) as u32,
        };
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The four encoder-KAT inputs, in a fixed order from one seed.
fn kat_inputs() -> Vec<(&'static str, Vec<u8>, &'static [CodecId])> {
    const ALL_TEXT: &[CodecId] = &[CodecId::Lzma2];
    const X86: &[CodecId] = &[CodecId::Lzma2, CodecId::BcjX86Lzma2, CodecId::Bcj2];
    const ARM64: &[CodecId] = &[CodecId::Lzma2, CodecId::BcjArm64Lzma2];
    let mut rng = XorShift(0x2545_F491_4F6C_DD1D);
    vec![
        ("64 KiB random", random(64 * 1024, &mut rng), ALL_TEXT),
        ("256 KiB text", text(256 * 1024, &mut rng), ALL_TEXT),
        ("128 KiB x86-like", x86_like(128 * 1024, &mut rng), X86),
        (
            "128 KiB arm64-like",
            arm64_like(128 * 1024, &mut rng),
            ARM64,
        ),
    ]
}

/// The decoder-KAT inputs: small, so their frames stay under 2 KiB.
fn small_inputs() -> Vec<(CodecId, Vec<u8>)> {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    vec![
        (CodecId::Stored, text(48, &mut rng)),
        (CodecId::Lzma2, text(1024, &mut rng)),
        (CodecId::BcjX86Lzma2, x86_like(1024, &mut rng)),
        (CodecId::BcjArm64Lzma2, arm64_like(1024, &mut rng)),
        (CodecId::Bcj2, x86_like(1024, &mut rng)),
    ]
}

// ---------------------------------------------------------------------------------------------
// Helpers

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Stream descriptors of an encoded frame: `(length, decoded_size, dict_size)`.
fn stream_descs(enc: &EncodedFrame, input_len: u64) -> Vec<(u64, u64, Option<u32>)> {
    match &enc.streams {
        Some(streams) => streams
            .iter()
            .map(|s| (s.length, s.decoded_size, s.dict_size))
            .collect(),
        None => vec![(enc.bytes.len() as u64, input_len, enc.dict_size)],
    }
}

/// Decodes `bytes` directly with the codec; checks every stream was consumed exactly.
fn decode(
    codec: CodecId,
    bytes: &[u8],
    descs: &[(u64, u64, Option<u32>)],
    output_size: u64,
) -> Vec<u8> {
    let mut views = Vec::new();
    let mut at = 0usize;
    for &(length, decoded_size, dict_size) in descs {
        let end = at + usize::try_from(length).expect("length");
        views.push(StreamView {
            input: &bytes[at..end],
            decoded_size,
            dict_size,
        });
        at = end;
    }
    assert_eq!(at, bytes.len(), "{codec:?}: stream lengths cover the frame");
    let frame = FrameView {
        codec,
        output_size,
        streams: &views,
    };
    let mut out = Vec::new();
    let report = LzmaCodec
        .decode(&frame, &mut out)
        .unwrap_or_else(|e| panic!("{codec:?}: decode failed: {e}"));
    let lengths: Vec<u64> = descs.iter().map(|d| d.0).collect();
    assert_eq!(report.consumed, lengths, "{codec:?}: consumed");
    assert_eq!(out.len() as u64, output_size, "{codec:?}: output size");
    out
}

fn round_trip(codec: CodecId, input: &[u8]) -> EncodedFrame {
    let enc = LzmaCodec
        .encode(codec, input)
        .unwrap_or_else(|e| panic!("{codec:?}: encode failed: {e}"));
    assert_eq!(enc.codec, codec);
    let out = decode(
        codec,
        &enc.bytes,
        &stream_descs(&enc, input.len() as u64),
        input.len() as u64,
    );
    assert!(out == input, "{codec:?}: round trip differs");
    enc
}

// ---------------------------------------------------------------------------------------------
// (i) Encoder known answers

/// `(input, codec, frame length, frame SHA-256)`.
const ENCODER_KATS: &[(&str, &str, usize, &str)] = &[
    (
        "64 KiB random",
        "lzma2",
        65543,
        "bad71b91d3ac5392ece71aa6bead2d200d7d17c478a24eaada718eeadf224e0d",
    ),
    (
        "256 KiB text",
        "lzma2",
        39850,
        "899b83f856f96902150b36711c4252cd71d411659b6d8022a5c8ffcb2af2f704",
    ),
    (
        "128 KiB x86-like",
        "lzma2",
        74404,
        "2ead69db57dfb9a9fcc16c1a99da7810cb10db1edd6f054ce2970bb55b890fc0",
    ),
    (
        "128 KiB x86-like",
        "bcj-x86+lzma2",
        75671,
        "d7e8f78cab367f9fcab67971daf05b30e87f8b5b32f394afe2421c8d8cbb809a",
    ),
    (
        "128 KiB x86-like",
        "bcj2",
        67668,
        "fc0af3c2a1855acb257b0e56dcacad05d78338ce66d01369576fdd45353e2cc1",
    ),
    (
        "128 KiB arm64-like",
        "lzma2",
        57320,
        "ab4de6381d6d27b5b0e7dcd99282ecc823651da9583cf4a08a2008e164f557f1",
    ),
    (
        "128 KiB arm64-like",
        "bcj-arm64+lzma2",
        58279,
        "267c62d605a45c33606d8121e887e1366160cc055dfb86886f3ea450df0ca480",
    ),
];

fn encoder_table() -> Vec<(&'static str, &'static str, usize, String)> {
    let mut rows = Vec::new();
    for (name, input, codecs) in kat_inputs() {
        for &codec in codecs {
            let enc = round_trip(codec, &input);
            rows.push((name, codec.id(), enc.bytes.len(), sha256_hex(&enc.bytes)));
        }
    }
    rows
}

#[test]
fn encoder_output_matches_the_pinned_known_answers() {
    let actual = encoder_table();
    let expected: Vec<_> = ENCODER_KATS
        .iter()
        .map(|&(name, codec, len, sha)| (name, codec, len, sha.to_string()))
        .collect();
    assert_eq!(
        actual, expected,
        "encoder output differs from the pinned known answers on this host"
    );
}

#[test]
#[ignore = "prints the encoder KAT table; run by hand to regenerate"]
fn print_encoder_kats() {
    for (name, codec, len, sha) in encoder_table() {
        println!("    (\"{name}\", \"{codec}\", {len}, \"{sha}\"),");
    }
}

// ---------------------------------------------------------------------------------------------
// (ii) Decoder known answers

struct DecoderKat {
    codec: CodecId,
    /// The frame's bytes, as produced by this encoder.
    frame: &'static str,
    /// `(length, decoded_size, dict_size)` per stream.
    streams: &'static [(u64, u64, Option<u32>)],
    output_size: u64,
    output_sha256: &'static str,
}

const DECODER_KATS: &[DecoderKat] = &[
    DecoderKat {
        codec: CodecId::Stored,
        frame: "\
            6265666f7265206672616d650a76657269666965642066696c65206973207369676e6564206265666f72652066696c65\
        ",
        streams: &[(48, 48, None)],
        output_size: 48,
        output_sha256: "bfde1700c5af80e9b1c67e6a0e4705da08fa8599ae32b19d7d702b021d4299c0",
    },
    DecoderKat {
        codec: CodecId::Lzma2,
        frame: "\
            e003ff01465d00321949dc2e0ef8e18db8b88481945391bed7df4a17ba5d8680b159f3793d096589a210c82c92a185fb\
            6e53f61e994a01f6c4e9d3cedd9bf2d1cbe507317f3325e82e210598f2b0d5b3b6b8d8c9be9d9daf021a2997e6b1bcc6\
            282edc329fb23bb494a5d8cf31272ebf1356b53247b10f44a58811009e655cc24cfecae8c392cf9fba611842ba554881\
            7af648094aa171835dfee2ec4f7ffe3402a57e177c78b1e4ded3f5a50991a13909fb9732ab755da637555b1dbcb77cab\
            5efd1b4774acf33f80304655dc60f06c9f76238a6c42f2f07464092bc474a221572e2ee3f186ff9b9fe1a604df9d17ce\
            ef1db18d5a8d026740ce29c2919e4d5310beb2404baa7ed946423b37a75e3e7c7d6031e86310fe9dc521fb4f5234534b\
            052e2cc3d11b72867cf4620f515d483f75ba59eb1b2ad41ee644fbd23f8f721e47cae2b4674ca5ce3b52dfc30000\
        ",
        streams: &[(334, 1024, Some(4096))],
        output_size: 1024,
        output_sha256: "93673d1ab1e794eef6bd54121aed3ab65af26352b27d5c1888d574afefa3910f",
    },
    DecoderKat {
        codec: CodecId::BcjX86Lzma2,
        frame: "\
            e003ff03295d002a920ceb4cc3146c135d16c1aaed0f10b5168ed6d3ca38342c783b84f024b75ac997f7cae1237082c8\
            b86aadfee6bbf6e9669557c4b7de3f04ee248404049f680d729b9f8486ef3e561a61abb459a15a6125693c8ceda2bb97\
            f6c70cf51cf4ffe03d8b7e3ce69545dd3cdc6105a25ccb1d7db69f2135cf6c299d64b4e55f7968d6c525b4a65214a2ba\
            bee2acb9e03903931108ad9722992d847a21b1cf890459e8608472a3dfef73e200ec14c32fef0d6b625cbfdb2fcdc3dd\
            30b9914fda51b3f3f89d8dde7188be4a0be3f7abde2b558d679dff128257b609e1f4ec46b190a562dca23ad6ef924fcf\
            501516d9e53705394643ce98546953883bb2d823053e963e03baeeed16063620875964dedda4e7f2282f3bca1f9719f1\
            f34c6f20362c176f1a015b33b61daf31c75ea7c527a57fa1385f5bdb2aabe155c470fb90bb44ac146357e95430adc609\
            d227c92c2592893aabcf4f3ac7f9d2bcb096c669db624726732504988595e50bc7b7bb6e39c1865e9e2bf1e84c124f92\
            51d8cbf9218ba68c2da831d2b08f3fa5683a081ec1416b7d60305833c03cce14914f3a7da285594ee9f2b5fd1940997b\
            920f67032ddcfd6a51aed49d03ac313121851a30ada8455636ea96b96e6c1509aa1764468dfa065c615806800d08fa6c\
            5da219cee0488722d4db7409d0003b614389304aaa581fc975bf46da75e02ee2db670bf026977938d86c75e6966e6067\
            529a0242e65a341a0ffa052324a7896ce9c8dda6986adf773a81223860f03f9b6d10a2070ce4ebd31fb9c6512d6027e0\
            cd15fedd7f1e347baf1f83e2a5da7f173e26b6a0dc1b2ebaef30377309053f2d156e84d482b7c52922eaf4c9d7941df4\
            c29409ec1d7aeb7aa8113232868f14e20d21d1deccd4c97d3ea9b82e577edb0ed9a372614e758605ec15abd5b6ce326b\
            b4b244c76531c6f4ba6907945fbee241a0e9d0eb328b00855e4edbb296d242321f999d335de205469c0d9ef79a6777ca\
            15deacfa337fe9b22976b2c5fdb8add6fb881ad5762eddd1503fa239d63479ca902e0e863209ab01274b55a276eeb750\
            e84fc2c78659894ed40e3368f80b18b65c2f5b02db407c92c76b5ee57eb0df89fdada65562204e678c61063a265b9b00\
            00\
        ",
        streams: &[(817, 1024, Some(4096))],
        output_size: 1024,
        output_sha256: "f167fad41709bd0a4e8132754e3f425ef7c91098aa1757fd3bd4457dc13e9976",
    },
    DecoderKat {
        codec: CodecId::BcjArm64Lzma2,
        frame: "\
            e003ff02755d00051ebc997385787fab84063d0ec405f55fc2ae2dc79c3814cf51864086c200f160c5d0d7820691741f\
            3f55e7a2361a43d6f23f05cbf85d17a6349129481136a33950762fff5c9fd565ae58e7c86464a8a9992b769e497d8cca\
            3ddb9dff4d45143295ca504b7712f60146b3825b998719112d9e659f09ae4933d82196d996c5a61dd11678d94e5368cf\
            ce5e8d76402e0f1f9ae3f54bc03068fa1469abd846b4278e7d8e9d4294512c71aa39f25147f37b816e63605dfe5a1508\
            98116f047c084c5974f808f6770411c3633d6dc2c0031353b41e6a0fc6f2cc4c904ceb5185c6702b2206bf465be56b0f\
            b5b9b95a3b08dde8e449ea6759fc0f1a99a3a926499aaad4246729430e342f2237e8de91f7ace00ef70b1234439a6cac\
            1b3002b46704bc673f4ed2410e6a3293b631af06e686b3bc43389643ca89cb271c985d226d733a8ac7f0814e7ac51391\
            93fc1ef73d77fed222a87510c4f4e40f9b627036c909730c0a47aab9c8ea9e25fd96c1ab3f660557de4bdadbfae14c48\
            9c24bef9961ea15e5c88634e378226881b6065870a7e5a52139fd76352dcde296c343a5e72470b30627ba927c3a339b7\
            501ec803eab4fdf2d9a78b97d03c7a483c6ca27034fa5ef3181eb64ae50d2f2b9345c1a614d65d3f8cae2e535c45b2cb\
            83ed2261a5917d0fe1a5de4e3d62322addca39a80c045c774c56ac4ee62a659c629e6bfa4c86df1f05aebf0c8c75bed3\
            34c83520f62c0ac54ec20ab65c68fcc485b87d7c01ad01424cc23c11127b09399da66eb0a76572b23476c4bbc700e2a6\
            ccd2225482274d907b46822db836e998a335a44e1f3cab4d8668b39e593ef9d04748d4f99b1c2b7c453a1b7462ea0a9e\
            2a2a5596d8ddd1d98b88c01600\
        ",
        streams: &[(637, 1024, Some(4096))],
        output_size: 1024,
        output_sha256: "23d16bdd825bbe7428957b4664dca439ca21eb63cc6d43d4ce74f4d894d8bc1c",
    },
    DecoderKat {
        codec: CodecId::Bcj2,
        frame: "\
            e003fb02e75d002420d98f0766cf79c5bceeef19ff76d51b3e7feba278f33873e2bdbf570f93d53d5f2088f029b300b3\
            63f3e46a98a69cb1310cc84c520f331006a3b0aa139182575686fe9bcf418a6e37ef317fe957d91953a1c501fcdc4c95\
            d249e59efed5d81261ec58ea9f4945e8e6841d49b55cf29b522aecb0db4b77edf24609cc55847eb9568d9cc551fd80f3\
            ca15b605f0733f5b649ef025f5c8d458bb10d646c83283ab7f7e7aef8321ca53c09145cad3f50dfe93eda490f13b4844\
            b7dcc87ace5e384e4b34702f7ab6c7209b0f799fd8e2ca7d80907d052e444f79a331dec3743c6e2c15844aaa99dc8b21\
            4b7652b6cb163526d032c20826500aaaae8468e61c2c4eaba059f9e7946438e8b2e68f51d1d6596abc6e1fb4fa7ac15c\
            87b8401bd7191a88800a8c1e0d36d4e89525569ad5b2b572c04a63d264a8cb474a46b22193d224eddffd69f8a3276289\
            214ba5fc0794c84a14623d881c88505ac1ebd9105dd63a2236b5f8580ee9e36882caa46655cc50d285c6573392762eac\
            67dacccac8200bf99c4e8d29ae38235b1f36e613083b657e4525bc5a835fc5d2e0ae10275cbb73079b618e669ccc8b23\
            ac2cb8a08b75fbcd7291b25a6de843370b3db121d56582f2faee3a6cfa51ea84d895258aff881166cecdb09b1394c677\
            df0b9d8227127a4aa30adb1fd961955600aaeb2d113098171a5213867f25a35f511ca64e5700078125f742aa109ce1a7\
            2561ca817cd351627b0edcac611793eca3891b8a23595ab4be58bc24ee59053afe202b1b22dcdcdf6d2da0eedf3be380\
            e49c2a40012fd9dee9f70bf93101b7aa76eebffb60f42a6c0fdf1807a0636c7cb8a53d8224c5c078a9d4d20415271df5\
            a38fd463a871f8dc478f9f7d60d82da5e5ed01d1b186466874e441a424385a3366ca0bbccbad2ce4576167a261333690\
            b5078b908c22f14df693e08c861e1f78d0e2068acffa811645f64e883ce0166695624798c91d554f18c1f575d38e137d\
            3ba60d9296d25763328eac0262fe71f76f517dad8ab0e4df8b0e3a94000000010003000000e400000000000000000000\
            2724d8000000\
        ",
        streams: &[
            (751, 1020, Some(4096)),
            (8, 4, Some(4096)),
            (1, 0, Some(4096)),
            (14, 14, None),
        ],
        output_size: 1024,
        output_sha256: "264b5bb8c9e9b03fcefdcbd0fe671bcce3943948323b4486063e445446bf3b74",
    },
];

#[test]
fn committed_frames_decode_to_their_pinned_output() {
    assert_eq!(DECODER_KATS.len(), 5, "one frame per codec id");
    for (kat, (codec, input)) in DECODER_KATS.iter().zip(small_inputs()) {
        assert_eq!(kat.codec, codec);
        let frame = unhex(kat.frame);
        assert!(frame.len() <= 2048, "{codec:?}: committed frame over 2 KiB");
        let out = decode(kat.codec, &frame, kat.streams, kat.output_size);
        assert_eq!(sha256_hex(&out), kat.output_sha256, "{codec:?}: output");
        // The table was produced from these inputs.
        assert!(
            out == input,
            "{codec:?}: the frame is not of the generator's input"
        );
    }
}

#[test]
#[ignore = "prints the decoder KAT table; run by hand to regenerate"]
fn print_decoder_kats() {
    for (codec, input) in small_inputs() {
        let enc = round_trip(codec, &input);
        let descs = stream_descs(&enc, input.len() as u64);
        let frame = hex(&enc.bytes);
        let lines: Vec<&str> = frame
            .as_bytes()
            .chunks(96)
            .map(|c| std::str::from_utf8(c).expect("ascii"))
            .collect();
        println!("    DecoderKat {{");
        println!("        codec: CodecId::{codec:?},");
        println!("        frame: \"\\");
        for line in &lines {
            println!("            {line}\\");
        }
        println!("        \",");
        println!("        streams: &{descs:?},");
        println!("        output_size: {},", input.len());
        println!("        output_sha256: \"{}\",", sha256_hex(&input));
        println!("    }},");
    }
}

// ---------------------------------------------------------------------------------------------
// (iii) The test executable

fn u16_at(b: &[u8], at: usize, big_endian: bool) -> Option<u16> {
    let bytes: [u8; 2] = b.get(at..at + 2)?.try_into().ok()?;
    Some(if big_endian {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    })
}

fn u32_at(b: &[u8], at: usize, big_endian: bool) -> Option<u32> {
    let bytes: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
    Some(if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

#[derive(PartialEq)]
enum Arch {
    X86,
    Arm64,
    Other,
}

fn macho_arch(cputype: u32) -> Arch {
    match cputype {
        7 | 0x0100_0007 => Arch::X86,
        0x0100_000C => Arch::Arm64,
        _ => Arch::Other,
    }
}

/// The architectures an executable's header names (M3-D6's header rules).
fn header_arches(b: &[u8]) -> Vec<Arch> {
    if b.starts_with(b"MZ") {
        let pe = u32_at(b, 0x3C, false).map(|o| o as usize);
        if let Some(pe) = pe.filter(|&pe| b.get(pe..pe + 4) == Some(b"PE\0\0")) {
            return match u16_at(b, pe + 4, false) {
                Some(0x014C | 0x8664) => vec![Arch::X86],
                Some(0xAA64) => vec![Arch::Arm64],
                _ => vec![Arch::Other],
            };
        }
    }
    if b.starts_with(b"\x7FELF") {
        let big_endian = b.get(5) == Some(&2);
        return match u16_at(b, 18, big_endian) {
            Some(3 | 62) => vec![Arch::X86],
            Some(183) => vec![Arch::Arm64],
            _ => vec![Arch::Other],
        };
    }
    if let Some(0xFEED_FACE | 0xFEED_FACF) = u32_at(b, 0, false) {
        return vec![macho_arch(u32_at(b, 4, false).unwrap_or(0))];
    }
    if let Some(magic @ (0xCAFE_BABE | 0xCAFE_BABF)) = u32_at(b, 0, true) {
        let n = u32_at(b, 4, true).unwrap_or(0) as usize;
        let entry = if magic == 0xCAFE_BABE { 20 } else { 32 };
        if (1..=20).contains(&n) {
            return (0..n)
                .filter_map(|i| u32_at(b, 8 + i * entry, true))
                .map(macho_arch)
                .collect();
        }
    }
    vec![Arch::Other]
}

/// M3-D6: the candidate codecs for an executable's architectures, in the fixed order.
fn header_codecs(b: &[u8]) -> Vec<CodecId> {
    let arches = header_arches(b);
    let x86 = arches.contains(&Arch::X86);
    let arm64 = arches.contains(&Arch::Arm64);
    let mut codecs = Vec::new();
    if x86 {
        codecs.push(CodecId::BcjX86Lzma2);
    }
    if arm64 {
        codecs.push(CodecId::BcjArm64Lzma2);
    }
    if x86 {
        codecs.push(CodecId::Bcj2);
    }
    if codecs.is_empty() {
        codecs.push(CodecId::Lzma2);
    }
    codecs
}

#[test]
fn the_test_executable_round_trips_through_its_header_codecs() {
    let path = std::env::current_exe().expect("current_exe");
    let exe = std::fs::read(&path).expect("read the test executable");
    let codecs = header_codecs(&exe);
    let expected: &[CodecId] = if cfg!(target_arch = "x86_64") || cfg!(target_arch = "x86") {
        &[CodecId::BcjX86Lzma2, CodecId::Bcj2]
    } else if cfg!(target_arch = "aarch64") {
        &[CodecId::BcjArm64Lzma2]
    } else {
        &[CodecId::Lzma2]
    };
    assert_eq!(codecs, expected, "the header names the host's architecture");
    for codec in codecs {
        let enc = round_trip(codec, &exe);
        assert!(
            enc.bytes.len() < exe.len(),
            "{codec:?}: the executable did not shrink"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// (iv) Dictionary size from the stream's length

#[test]
fn a_3000_byte_input_uses_a_4096_byte_dictionary() {
    let input = text(3000, &mut XorShift(7));
    for codec in [CodecId::Lzma2, CodecId::BcjX86Lzma2, CodecId::BcjArm64Lzma2] {
        assert_eq!(round_trip(codec, &input).dict_size, Some(4096), "{codec:?}");
    }
}

/// Random bytes: the fastest 20 MiB for 9e's match finder (about 25 s unoptimised, 7 s with
/// `--release`).
#[test]
fn a_20_mib_input_uses_a_16_mib_dictionary() {
    let input = random(20 << 20, &mut XorShift(11));
    assert_eq!(round_trip(CodecId::Lzma2, &input).dict_size, Some(16 << 20));
}
