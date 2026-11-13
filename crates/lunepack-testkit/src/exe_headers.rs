//! Deterministic synthetic executables: a minimal, valid-enough header of each format the packager
//! classifies, followed by filler shaped like the architecture's code. Not runnable programs; they
//! exist so tests and benchmarks can exercise header detection and the BCJ filters without
//! shipping binaries.

/// xorshift64*: a fixed-seed source, so every call gives the same bytes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Bytes shaped like x86 code: short runs of filler broken by `E8`/`E9` and a small little-endian
/// relative offset, which is what the x86 BCJ filter rewrites.
pub fn x86_like(len: usize) -> Vec<u8> {
    let mut rng = Rng(0x86_86_86_86_86_86_86_86);
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        let filler = (rng.next() >> 60) as usize + 1;
        for _ in 0..filler {
            out.push(0x48 + ((rng.next() >> 61) as u8));
        }
        out.push(if rng.next() & 1 == 0 { 0xE8 } else { 0xE9 });
        let rel = ((rng.next() >> 48) as i32 % 4096) - 2048;
        out.extend_from_slice(&rel.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Bytes shaped like ARM64 code: little-endian 4-byte words, every other one a `BL` with a small
/// word offset, which is what the ARM64 BCJ filter rewrites. `len` is rounded down to a multiple of
/// 4.
pub fn arm64_like(len: usize) -> Vec<u8> {
    let mut rng = Rng(0xA64A_64A6_4A64_A64A);
    let mut out = Vec::with_capacity(len + 4);
    let mut i = 0u64;
    while out.len() + 4 <= len {
        let word: u32 = if i & 1 == 0 {
            // BL: opcode 100101, imm26.
            0x9400_0000 | ((rng.next() >> 50) as u32 & 0x0003_FFFF)
        } else {
            // A data-processing-looking word.
            0x9100_0000 | ((rng.next() >> 40) as u32 & 0x00FF_FFFF)
        };
        out.extend_from_slice(&word.to_le_bytes());
        i += 1;
    }
    out
}

fn with_filler(mut header: Vec<u8>, len: usize, arm64: bool) -> Vec<u8> {
    let rest = len.saturating_sub(header.len());
    header.extend(if arm64 {
        arm64_like(rest)
    } else {
        x86_like(rest)
    });
    // `arm64_like` rounds down; top up so the total is exact.
    header.resize(len.max(header.len()), 0);
    header
}

/// Size of the PE header [`pe`] writes (DOS stub, `PE\0\0`, machine).
pub const PE_HEADER_LEN: usize = 0x88;
/// Size of the ELF header [`elf`] writes.
pub const ELF_HEADER_LEN: usize = 64;
/// Size of the Mach-O header [`macho`] writes.
pub const MACHO_HEADER_LEN: usize = 32;

/// A PE image: `MZ`, `e_lfanew = 0x80`, `PE\0\0` and `machine`, then filler of the matching
/// architecture. `len` is the total length, at least [`PE_HEADER_LEN`].
pub fn pe(machine: u16, len: usize) -> Vec<u8> {
    let mut h = vec![0u8; PE_HEADER_LEN];
    h[..2].copy_from_slice(b"MZ");
    h[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    h[0x80..0x84].copy_from_slice(b"PE\0\0");
    h[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    with_filler(h, len, machine == 0xAA64)
}

/// A 64-bit ELF header with `e_machine = machine` in the given byte order, then filler. `len` is
/// the total length, at least [`ELF_HEADER_LEN`].
pub fn elf(machine: u16, big_endian: bool, len: usize) -> Vec<u8> {
    let mut h = vec![0u8; ELF_HEADER_LEN];
    h[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    h[4] = 2; // ELFCLASS64
    h[5] = if big_endian { 2 } else { 1 };
    h[6] = 1; // EV_CURRENT
    let m = if big_endian {
        machine.to_be_bytes()
    } else {
        machine.to_le_bytes()
    };
    h[18..20].copy_from_slice(&m);
    with_filler(h, len, machine == 183)
}

/// A thin Mach-O header (64-bit magic when `cputype` has the 64-bit ABI flag) in the given byte
/// order, then filler. `len` is the total length, at least [`MACHO_HEADER_LEN`].
pub fn macho(cputype: u32, big_endian: bool, len: usize) -> Vec<u8> {
    let mut h = vec![0u8; MACHO_HEADER_LEN];
    let last = if cputype & 0x0100_0000 != 0 {
        0xCF
    } else {
        0xCE
    };
    let magic = if big_endian {
        [0xFE, 0xED, 0xFA, last]
    } else {
        [last, 0xFA, 0xED, 0xFE]
    };
    h[..4].copy_from_slice(&magic);
    let c = if big_endian {
        cputype.to_be_bytes()
    } else {
        cputype.to_le_bytes()
    };
    h[4..8].copy_from_slice(&c);
    with_filler(h, len, cputype == 0x0100_000C)
}

/// A fat (universal) Mach-O header listing `cputypes`, then filler. `len` is the total length, at
/// least the header (`8 + 20 * cputypes.len()`). Filler is ARM64-like unless a slice is x86.
pub fn fat(cputypes: &[u32], len: usize) -> Vec<u8> {
    let header_len = 8 + 20 * cputypes.len();
    let mut h = Vec::with_capacity(header_len);
    h.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    h.extend_from_slice(&(cputypes.len() as u32).to_be_bytes());
    let total = len.max(header_len);
    for &c in cputypes {
        h.extend_from_slice(&c.to_be_bytes());
        h.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        h.extend_from_slice(&(header_len as u32).to_be_bytes()); // offset
        h.extend_from_slice(&((total - header_len) as u32).to_be_bytes()); // size
        h.extend_from_slice(&12u32.to_be_bytes()); // align 2^12
    }
    let x86 = cputypes.iter().any(|&c| c == 7 || c == 0x0100_0007);
    with_filler(h, len, !x86)
}
