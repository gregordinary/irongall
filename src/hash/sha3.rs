//! SHA3-256 and SHA3-512 (FIPS 202 §6.1): the Keccak-f\[1600\] permutation
//! in a sponge, which the two use with different rates and output lengths.

use super::BlockBuffer;

hash_function! {
    /// SHA3-256 (FIPS 202 §6.1), with a 32-byte digest.
    Sha3_256(Sponge<136>) -> [u8; 32],
    new: Sponge::new(),
    output: write_lanes,
}

hash_function! {
    /// SHA3-512 (FIPS 202 §6.1), with a 64-byte digest.
    Sha3_512(Sponge<72>) -> [u8; 64],
    new: Sponge::new(),
    output: write_lanes,
}

/// The sponge construction over Keccak-f\[1600\] (FIPS 202 §4), absorbing
/// `R` bytes at a time: its rate, which is 1600 bits less twice the digest's
/// length.
#[derive(Debug, Clone)]
struct Sponge<const R: usize> {
    /// The 25 lanes of the state, lane (x, y) at `x + 5 * y`, each read from
    /// eight bytes little-endian (FIPS 202 §3.1.2, and Appendix B.1 for the
    /// byte order).
    state: [u64; 25],
    buffer: BlockBuffer<R>,
}

impl<const R: usize> Sponge<R> {
    fn new() -> Sponge<R> {
        Sponge {
            state: [0; 25],
            buffer: BlockBuffer::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer
            .update(data, |block| absorb(&mut self.state, block));
    }

    /// The state once the padded input has been absorbed. Each digest here is
    /// shorter than the rate, so its bytes are the state's first, and no
    /// further permutation is needed to squeeze them.
    fn finish(mut self) -> [u64; 25] {
        self.buffer
            .finish_sha3(|block| absorb(&mut self.state, block));
        self.state
    }
}

/// XORs a block into the first lanes of the state, and permutes it.
fn absorb<const R: usize>(state: &mut [u64; 25], block: &[u8; R]) {
    for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
        *lane ^= u64::from_le_bytes(*bytes);
    }
    keccak_f(state);
}

/// The little-endian bytes of `lanes`, as many as `output` holds.
fn write_lanes<const N: usize>(lanes: &[u64; 25], output: &mut [u8; N]) {
    for (bytes, lane) in output.as_chunks_mut::<8>().0.iter_mut().zip(lanes) {
        *bytes = lane.to_le_bytes();
    }
}

/// The round constants of ι, one for each of the 24 rounds (FIPS 202
/// §3.2.5): the bits Algorithm 5 gives, placed at bit positions 2^j - 1.
pub(super) const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// The rotation of each lane by ρ (FIPS 202 §3.2.2, Table 2), lane (x, y)
/// at `x + 5 * y`.
///
/// One row for each y from 0 to 4, and in each, x from 0 to 4. Table 2 puts
/// x = 3 and y = 3 first, so its rows and columns are in another order.
#[rustfmt::skip]
pub(super) const ROTATIONS: [u32; 25] = [
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
];

/// Keccak-f\[1600\]: the 24 rounds of θ, ρ, π, χ, and ι (FIPS 202 §3.3 and
/// §3.4).
#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "`x` and `y` run over 0..5, so `x + 5 * y`, the coordinates \
              `(x + 1) % 5`, `(x + 2) % 5`, `(x + 4) % 5`, and \
              `(2 * x + 3 * y) % 5` index within the 5 columns and 25 lanes"
)]
fn keccak_f(a: &mut [u64; 25]) {
    for round_constant in ROUND_CONSTANTS {
        // θ: each lane takes the parities of the two columns beside its own,
        // one of them rotated.
        let mut c = [0; 5];
        for (x, parity) in c.iter_mut().enumerate() {
            *parity = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // ρ and π: each lane rotated, and moved from (x, y) to
        // (y, 2x + 3y).
        let mut b = [0; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROTATIONS[x + 5 * y]);
            }
        }
        // χ: each lane combined with the next two in its row.
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // ι.
        a[0] ^= round_constant;
    }
}
