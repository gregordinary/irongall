//! SHA2-384 and SHA2-512 (FIPS 180-4 §6.4 and §6.5), which differ only in
//! their initial state and in how much of the final state they output.

use super::{BlockBuffer, HashFunction, ch, maj, write_wide_words};

/// SHA2-384 (FIPS 180-4 §6.5), with a 48-byte digest.
#[derive(Debug, Clone)]
pub struct Sha384(Engine);

impl Default for Sha384 {
    fn default() -> Sha384 {
        <Sha384 as HashFunction>::new()
    }
}

impl HashFunction for Sha384 {
    type Output = [u8; 48];

    fn new() -> Sha384 {
        Sha384(Engine::new([
            0xCBBB_9D5D_C105_9ED8,
            0x629A_292A_367C_D507,
            0x9159_015A_3070_DD17,
            0x152F_ECD8_F70E_5939,
            0x6733_2667_FFC0_0B31,
            0x8EB4_4A87_6858_1511,
            0xDB0C_2E0D_64F9_8FA7,
            0x47B5_481D_BEFA_4FA4,
        ]))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> [u8; 48] {
        let mut output = [0; 48];
        write_wide_words(&self.0.finish(), &mut output);
        output
    }
}

/// SHA2-512 (FIPS 180-4 §6.4), with a 64-byte digest.
#[derive(Debug, Clone)]
pub struct Sha512(Engine);

impl Default for Sha512 {
    fn default() -> Sha512 {
        <Sha512 as HashFunction>::new()
    }
}

impl HashFunction for Sha512 {
    type Output = [u8; 64];

    fn new() -> Sha512 {
        Sha512(Engine::new([
            0x6A09_E667_F3BC_C908,
            0xBB67_AE85_84CA_A73B,
            0x3C6E_F372_FE94_F82B,
            0xA54F_F53A_5F1D_36F1,
            0x510E_527F_ADE6_82D1,
            0x9B05_688C_2B3E_6C1F,
            0x1F83_D9AB_FB41_BD6B,
            0x5BE0_CD19_137E_2179,
        ]))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> [u8; 64] {
        let mut output = [0; 64];
        write_wide_words(&self.0.finish(), &mut output);
        output
    }
}

/// The computation SHA2-384 and SHA2-512 share.
#[derive(Debug, Clone)]
struct Engine {
    state: [u64; 8],
    buffer: BlockBuffer<128>,
    /// The input length in bytes, modulo 2^64. The padding records a 128-bit
    /// length, but no input reaches 2^64 bytes.
    length: u64,
}

impl Engine {
    fn new(state: [u64; 8]) -> Engine {
        Engine {
            state,
            buffer: BlockBuffer::new(),
            length: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        self.buffer
            .update(data, |block| compress(&mut self.state, block));
    }

    fn finish(mut self) -> [u64; 8] {
        let bits = u128::from(self.length).wrapping_mul(8).to_be_bytes();
        self.buffer
            .finish(&bits, |block| compress(&mut self.state, block));
        self.state
    }
}

/// The round constants (FIPS 180-4 §4.2.3).
///
/// Laid out in rows as the standard prints them, so the table can be read
/// against it.
#[rustfmt::skip]
const K: [u64; 80] = [
    0x428A_2F98_D728_AE22, 0x7137_4491_23EF_65CD, 0xB5C0_FBCF_EC4D_3B2F, 0xE9B5_DBA5_8189_DBBC,
    0x3956_C25B_F348_B538, 0x59F1_11F1_B605_D019, 0x923F_82A4_AF19_4F9B, 0xAB1C_5ED5_DA6D_8118,
    0xD807_AA98_A303_0242, 0x1283_5B01_4570_6FBE, 0x2431_85BE_4EE4_B28C, 0x550C_7DC3_D5FF_B4E2,
    0x72BE_5D74_F27B_896F, 0x80DE_B1FE_3B16_96B1, 0x9BDC_06A7_25C7_1235, 0xC19B_F174_CF69_2694,
    0xE49B_69C1_9EF1_4AD2, 0xEFBE_4786_384F_25E3, 0x0FC1_9DC6_8B8C_D5B5, 0x240C_A1CC_77AC_9C65,
    0x2DE9_2C6F_592B_0275, 0x4A74_84AA_6EA6_E483, 0x5CB0_A9DC_BD41_FBD4, 0x76F9_88DA_8311_53B5,
    0x983E_5152_EE66_DFAB, 0xA831_C66D_2DB4_3210, 0xB003_27C8_98FB_213F, 0xBF59_7FC7_BEEF_0EE4,
    0xC6E0_0BF3_3DA8_8FC2, 0xD5A7_9147_930A_A725, 0x06CA_6351_E003_826F, 0x1429_2967_0A0E_6E70,
    0x27B7_0A85_46D2_2FFC, 0x2E1B_2138_5C26_C926, 0x4D2C_6DFC_5AC4_2AED, 0x5338_0D13_9D95_B3DF,
    0x650A_7354_8BAF_63DE, 0x766A_0ABB_3C77_B2A8, 0x81C2_C92E_47ED_AEE6, 0x9272_2C85_1482_353B,
    0xA2BF_E8A1_4CF1_0364, 0xA81A_664B_BC42_3001, 0xC24B_8B70_D0F8_9791, 0xC76C_51A3_0654_BE30,
    0xD192_E819_D6EF_5218, 0xD699_0624_5565_A910, 0xF40E_3585_5771_202A, 0x106A_A070_32BB_D1B8,
    0x19A4_C116_B8D2_D0C8, 0x1E37_6C08_5141_AB53, 0x2748_774C_DF8E_EB99, 0x34B0_BCB5_E19B_48A8,
    0x391C_0CB3_C5C9_5A63, 0x4ED8_AA4A_E341_8ACB, 0x5B9C_CA4F_7763_E373, 0x682E_6FF3_D6B2_B8A3,
    0x748F_82EE_5DEF_B2FC, 0x78A5_636F_4317_2F60, 0x84C8_7814_A1F0_AB72, 0x8CC7_0208_1A64_39EC,
    0x90BE_FFFA_2363_1E28, 0xA450_6CEB_DE82_BDE9, 0xBEF9_A3F7_B2C6_7915, 0xC671_78F2_E372_532B,
    0xCA27_3ECE_EA26_619C, 0xD186_B8C7_21C0_C207, 0xEADA_7DD6_CDE0_EB1E, 0xF57D_4F7F_EE6E_D178,
    0x06F0_67AA_7217_6FBA, 0x0A63_7DC5_A2C8_98A6, 0x113F_9804_BEF9_0DAE, 0x1B71_0B35_131C_471B,
    0x28DB_77F5_2304_7D84, 0x32CA_AB7B_40C7_2493, 0x3C9E_BE0A_15C9_BEBC, 0x431D_67C4_9C10_0D4C,
    0x4CC5_D4BE_CB3E_42B6, 0x597F_299C_FC65_7E2A, 0x5FCB_6FAB_3AD6_FAEC, 0x6C44_198C_4A47_5817,
];

/// The message schedule for one block (FIPS 180-4 §6.4.2, step 1).
#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "`t` runs over 16..80, so every index is within the 80-word schedule"
)]
fn schedule(block: &[u8; 128]) -> [u64; 80] {
    let mut w = [0; 80];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*bytes);
    }
    for t in 16..80 {
        let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
        let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
        w[t] = s1
            .wrapping_add(w[t - 7])
            .wrapping_add(s0)
            .wrapping_add(w[t - 16]);
    }
    w
}

/// Folds one block into the state (FIPS 180-4 §6.4.2, steps 2 to 4).
fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, w) in K.into_iter().zip(schedule(block)) {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch(e, f, g))
            .wrapping_add(k)
            .wrapping_add(w);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let t2 = s0.wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}
