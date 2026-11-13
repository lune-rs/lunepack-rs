//! A deterministic, non-cryptographic hasher for tests.

use lunepack_core::{HashState, Hasher, Sha256Digest};

/// A 32-byte hash that is NOT SHA-256 and not secure: four seeded FNV-1a 64 lanes over the whole
/// input and its length. Test-only. It exists so no core test can pass by assuming real SHA-256
/// output; code that must be correct against real digests is covered by the crypto adapter's tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeHasher;

const SEEDS: [u64; 4] = [
    0xcbf2_9ce4_8422_2325,
    0x9e37_79b9_7f4a_7c15,
    0xd6e8_feb8_6659_fd93,
    0xa076_1d64_78bd_642f,
];
const PRIME: u64 = 0x0000_0100_0000_01b3;

struct FakeHashState {
    lanes: [u64; 4],
    len: u64,
}

impl FakeHashState {
    fn new() -> Self {
        FakeHashState {
            lanes: SEEDS,
            len: 0,
        }
    }
}

impl HashState for FakeHashState {
    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            for (i, lane) in self.lanes.iter_mut().enumerate() {
                *lane = (*lane ^ u64::from(byte.wrapping_add(i as u8))).wrapping_mul(PRIME);
            }
        }
        self.len = self.len.wrapping_add(data.len() as u64);
    }

    fn finalize(self: Box<Self>) -> Sha256Digest {
        let mut out = [0u8; 32];
        for (i, lane) in self.lanes.iter().enumerate() {
            let mixed = (lane ^ self.len)
                .wrapping_mul(PRIME)
                .rotate_left(17 + i as u32);
            out[i * 8..i * 8 + 8].copy_from_slice(&mixed.to_be_bytes());
        }
        Sha256Digest::from_bytes(out)
    }
}

impl Hasher for FakeHasher {
    fn sha256_start(&self) -> Box<dyn HashState> {
        Box::new(FakeHashState::new())
    }
}
