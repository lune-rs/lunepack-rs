//! The codec contract suite over the LZMA codec, as both decoder and encoder.

use lunepack_codec_lzma::LzmaCodec;
use lunepack_testkit::{FakeHasher, run_codec_suite};

#[test]
fn lzma_codec_passes_the_codec_suite() {
    run_codec_suite(&LzmaCodec, &LzmaCodec, &FakeHasher);
}
