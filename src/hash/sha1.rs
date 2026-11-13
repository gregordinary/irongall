//! SHA-1 (FIPS 180-4 §6.1).

use super::{BlockBuffer, HashFunction, ch, maj, write_words};

/// SHA-1 (FIPS 180-4 §6.1), with a 20-byte digest.
///
/// Not collision resistant; see the [module documentation](super).
#[derive(Debug, Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buffer: BlockBuffer<64>,
}

impl Default for Sha1 {
    fn default() -> Sha1 {
        <Sha1 as HashFunction>::new()
    }
}

impl HashFunction for Sha1 {
    type Output = [u8; 20];

    fn new() -> Sha1 {
        Sha1 {
            state: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            buffer: BlockBuffer::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer
            .update(data, |block| compress(&mut self.state, block));
    }

    fn finalize(mut self) -> [u8; 20] {
        self.buffer
            .finish::<8>(|block| compress(&mut self.state, block));
        let mut output = [0; 20];
        write_words(&self.state, &mut output);
        output
    }
}

/// The message schedule for one block (FIPS 180-4 §6.1.2, step 1).
#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "`t` runs over 16..80, so every index is within the 80-word schedule"
)]
fn schedule(block: &[u8; 64]) -> [u32; 80] {
    let mut w = [0; 80];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
    w
}

/// Folds one block into the state (FIPS 180-4 §6.1.2, steps 2 to 4).
fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (t, w) in schedule(block).into_iter().enumerate() {
        let (f, k) = match t {
            0..20 => (ch(b, c, d), 0x5A82_7999),
            20..40 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..60 => (maj(b, c, d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    for (word, value) in state.iter_mut().zip([a, b, c, d, e]) {
        *word = word.wrapping_add(value);
    }
}
