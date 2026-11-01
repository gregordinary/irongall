//! Integers modulo L, the order of Ed25519's base point (RFC 8032 §5.1),
//! which multiply points.
//!
//! Verification needs two: S, which a signature carries and which must
//! already be below L, and k, a SHA2-512 digest reduced modulo L.

use crate::bignum::{self, Limb};

/// L = 2^252 + 27742317777372353535851937790883648493, in 64-bit limbs,
/// least significant first.
const ORDER: [Limb; 4] = [0x5812_631A_5CF5_D3ED, 0x14DE_F9DE_A2F7_9CD6, 0, 1 << 60];

/// The number of bits a scalar may have: L is below 2^253.
const BITS: usize = 253;

/// An integer below L.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Scalar([Limb; 4]);

impl Scalar {
    /// The integer a 32-octet little-endian string encodes, or `None` if it
    /// is not below L.
    pub(super) fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
        let mut limbs = [0; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *limb = Limb::from_le_bytes(*chunk);
        }
        bignum::less_than(&limbs, &ORDER).then_some(Scalar(limbs))
    }

    /// The integer a 64-octet little-endian string encodes, reduced modulo L.
    pub(super) fn reduce(bytes: &[u8; 64]) -> Scalar {
        let mut residue = [0; 4];
        for bit in bytes
            .iter()
            .rev()
            .flat_map(|&octet| (0..8).rev().map(move |bit| (octet >> bit) & 1 == 1))
        {
            bignum::double_add(&mut residue, bit, &ORDER);
        }
        Scalar(residue)
    }

    /// The scalar's bits, the most significant of the 253 first.
    pub(super) fn bits(&self) -> impl Iterator<Item = bool> + '_ {
        self.0
            .iter()
            .rev()
            .flat_map(|&limb| (0..64).rev().map(move |bit| (limb >> bit) & 1 == 1))
            .skip(256 - BITS)
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::{ORDER, Scalar};
    use crate::test_support::Rng;

    fn order() -> BigUint {
        (BigUint::from(1u8) << 252u32)
            + "27742317777372353535851937790883648493"
                .parse::<BigUint>()
                .unwrap()
    }

    fn value(scalar: Scalar) -> BigUint {
        BigUint::from_slice(
            &scalar
                .0
                .iter()
                .flat_map(|limb| [*limb as u32, (*limb >> 32) as u32])
                .collect::<alloc::vec::Vec<u32>>(),
        )
    }

    #[test]
    fn order_is_l() {
        assert_eq!(value(Scalar(ORDER)), order());
    }

    #[test]
    fn reduction_matches_num_bigint() {
        let mut rng = Rng::new(30);
        let l = order();
        let mut checked = 0;
        let mut cases: alloc::vec::Vec<[u8; 64]> = [[0; 64], [0xFF; 64]].into();
        for multiple in [1u8, 2, 8, 15, 16] {
            let mut bytes = (&l * multiple).to_bytes_le();
            bytes.resize(64, 0);
            cases.push(bytes.clone().try_into().unwrap());
            // One below and one above.
            let below = &l * multiple - 1u8;
            let mut below = below.to_bytes_le();
            below.resize(64, 0);
            cases.push(below.try_into().unwrap());
            let mut above = (&l * multiple + 1u8).to_bytes_le();
            above.resize(64, 0);
            cases.push(above.try_into().unwrap());
        }
        for _ in 0..500 {
            cases.push(rng.bytes(64).try_into().unwrap());
        }
        for bytes in cases {
            let reduced = Scalar::reduce(&bytes);
            assert_eq!(value(reduced), BigUint::from_bytes_le(&bytes) % &l);
            let bits: alloc::vec::Vec<bool> = reduced.bits().collect();
            assert_eq!(bits.len(), 253);
            let from_bits = bits.iter().fold(BigUint::from(0u8), |total, &bit| {
                (total << 1) + u8::from(bit)
            });
            assert_eq!(from_bits, value(reduced));
            checked += 1;
        }
        assert_eq!(checked, 517);
    }

    #[test]
    fn canonical_bytes_are_below_l() {
        let l = order();
        let encode = |value: &BigUint| -> [u8; 32] {
            let mut bytes = value.to_bytes_le();
            bytes.resize(32, 0);
            bytes.try_into().unwrap()
        };
        let largest = Scalar::from_canonical_bytes(&encode(&(&l - 1u8))).unwrap();
        assert_eq!(value(largest), &l - 1u8);
        assert_eq!(Scalar::from_canonical_bytes(&[0; 32]), Some(Scalar([0; 4])));
        for refused in [
            l.clone(),
            &l + 1u8,
            &l * 2u8,
            (BigUint::from(1u8) << 256u32) - 1u8,
        ] {
            assert_eq!(Scalar::from_canonical_bytes(&encode(&refused)), None);
        }
    }
}
