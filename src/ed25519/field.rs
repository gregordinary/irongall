//! Arithmetic modulo p = 2^255 - 19, the field Ed25519's curve is defined
//! over (RFC 8032 §5.1).
//!
//! An element is five limbs of 51 bits, least significant first, so that a
//! product of two limbs, even after the multiplication by 19 that folds
//! 2^255 back to the bottom, fits in 128 bits with room to sum five of them.
//! Every operation returns limbs below 2^52, and accepts any element whose
//! limbs are: the bounds each function relies on are stated beside its
//! arithmetic, and the tests run with overflow checks on, so a bound that
//! does not hold fails them.
//!
//! An element is not kept below p. Its value is reduced fully only where it
//! is encoded, and equality compares encodings.

use core::ops::{Add, Mul, Neg, Sub};

/// The 51 bits a limb holds once its carry has moved up.
const LOW_51: u64 = (1 << 51) - 1;

/// 4 p, in limbs of 51 bits and more: each above 2^52, so subtracting a limb
/// below 2^52 from one never borrows.
const FOUR_P: [u64; 5] = [
    0x1F_FFFF_FFFF_FFB4,
    0x1F_FFFF_FFFF_FFFC,
    0x1F_FFFF_FFFF_FFFC,
    0x1F_FFFF_FFFF_FFFC,
    0x1F_FFFF_FFFF_FFFC,
];

/// An element of the field: `l0 + l1 2^51 + l2 2^102 + l3 2^153 + l4 2^204`,
/// each limb below 2^52.
#[derive(Debug, Clone, Copy)]
pub(super) struct FieldElement([u64; 5]);

impl FieldElement {
    /// Zero.
    pub(super) const ZERO: FieldElement = FieldElement([0; 5]);

    /// One.
    pub(super) const ONE: FieldElement = FieldElement([1, 0, 0, 0, 0]);

    /// d, the curve's constant: -121665/121666 (RFC 8032 §5.1).
    pub(super) const D: FieldElement = FieldElement([
        0x3_4DCA_1359_78A3,
        0x1_A828_3B15_6EBD,
        0x5_E7A2_6001_C029,
        0x7_39C6_63A0_3CBB,
        0x5_2036_CEE2_B6FF,
    ]);

    /// 2 d, which point addition multiplies by (RFC 8032 §5.1.4).
    pub(super) const D2: FieldElement = FieldElement([
        0x6_9B94_26B2_F159,
        0x3_5050_762A_DD7A,
        0x3_CF44_C003_8052,
        0x6_738C_C740_7977,
        0x2_406D_9DC5_6DFF,
    ]);

    /// A square root of -1: 2^((p - 1)/4) (RFC 8032 §5.1.3).
    pub(super) const SQRT_M1: FieldElement = FieldElement([
        0x6_1B27_4A0E_A0B0,
        0x0_D5A5_FC8F_189D,
        0x7_EF5E_9CBD_0C60,
        0x7_8595_A680_4C9E,
        0x2_B832_4804_FC1D,
    ]);

    /// The element with the given limbs, each below 2^52, for constants.
    pub(super) const fn from_limbs(limbs: [u64; 5]) -> FieldElement {
        FieldElement(limbs)
    }

    /// The element a 32-octet little-endian string encodes, or `None` unless
    /// the string is the element's canonical encoding: a value below p, so
    /// with bit 255 clear (RFC 8032 §5.1.2).
    pub(super) fn from_bytes(bytes: &[u8; 32]) -> Option<FieldElement> {
        let [w0, w1, w2, w3] = words(bytes);
        let element = FieldElement([
            w0 & LOW_51,
            ((w0 >> 51) | (w1 << 13)) & LOW_51,
            ((w1 >> 38) | (w2 << 26)) & LOW_51,
            ((w2 >> 25) | (w3 << 39)) & LOW_51,
            (w3 >> 12) & LOW_51,
        ]);
        // Bit 255 is not read, and a value of p or more encodes as another
        // string, so the encoding comes back unchanged exactly when it is
        // canonical.
        (element.to_bytes() == *bytes).then_some(element)
    }

    /// The canonical encoding: the value reduced below p, little-endian, in
    /// 32 octets with bit 255 clear (RFC 8032 §5.1.2).
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "carried limbs: l0 below 2^51 + 2^17, the others below 2^51, so every sum is far \
                  below 2^64"
    )]
    pub(super) fn to_bytes(self) -> [u8; 32] {
        let FieldElement([l0, l1, l2, l3, l4]) = FieldElement::carry(self.0);
        // The value is below 2^255 + 2^17, so below 2 p, and it is p or more
        // exactly when adding 19 carries out of bit 255.
        let q = (l0 + 19) >> 51;
        let q = (l1 + q) >> 51;
        let q = (l2 + q) >> 51;
        let q = (l3 + q) >> 51;
        let q = (l4 + q) >> 51;
        // Subtracting q p is adding 19 q and dropping the 2^255 q that
        // carries out of the top limb.
        let l0 = l0 + 19 * q;
        let l1 = l1 + (l0 >> 51);
        let l2 = l2 + (l1 >> 51);
        let l3 = l3 + (l2 >> 51);
        let l4 = l4 + (l3 >> 51);
        let [l0, l1, l2, l3, l4] = [l0, l1, l2, l3, l4].map(|limb| limb & LOW_51);
        let words = [
            l0 | (l1 << 51),
            (l1 >> 13) | (l2 << 38),
            (l2 >> 26) | (l3 << 25),
            (l3 >> 39) | (l4 << 12),
        ];
        let mut bytes = [0; 32];
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *chunk = word.to_le_bytes();
        }
        bytes
    }

    /// Whether the element, reduced below p, is odd: the sign RFC 8032
    /// §5.1.2 encodes an x-coordinate by.
    pub(super) fn is_odd(self) -> bool {
        let [low, ..] = self.to_bytes();
        low & 1 == 1
    }

    /// The element squared.
    pub(super) fn square(self) -> FieldElement {
        self * self
    }

    /// The element raised to 2^k: squared k times.
    fn pow2k(self, k: u32) -> FieldElement {
        (0..k).fold(self, |power, _| power.square())
    }

    /// The element's inverse, `x^(p - 2)` (RFC 8032 §5.1.1), or zero for zero.
    pub(super) fn invert(self) -> FieldElement {
        let (power, x11) = self.pow22501();
        // x^(2^255 - 32) x^11 = x^(2^255 - 21) = x^(p - 2).
        power.pow2k(5) * x11
    }

    /// The element raised to `(p - 5)/8 = 2^252 - 3`, the power square roots
    /// are computed with (RFC 8032 §5.1.3).
    pub(super) fn pow_p58(self) -> FieldElement {
        let (power, _) = self.pow22501();
        // x^(2^252 - 4) x = x^(2^252 - 3).
        power.pow2k(2) * self
    }

    /// `x^(2^250 - 1)` and `x^11`, the two powers both exponentiations are
    /// built from. Each step's exponent is in the comment beside it; the
    /// chain is the one Bernstein's reference implementation uses.
    fn pow22501(self) -> (FieldElement, FieldElement) {
        let x2 = self.square(); // 2
        let x9 = x2.pow2k(2) * self; // 9
        let x11 = x9 * x2; // 11
        let x2_5_0 = x11.square() * x9; // 2^5 - 1
        let x2_10_0 = x2_5_0.pow2k(5) * x2_5_0; // 2^10 - 1
        let x2_20_0 = x2_10_0.pow2k(10) * x2_10_0; // 2^20 - 1
        let x2_40_0 = x2_20_0.pow2k(20) * x2_20_0; // 2^40 - 1
        let x2_50_0 = x2_40_0.pow2k(10) * x2_10_0; // 2^50 - 1
        let x2_100_0 = x2_50_0.pow2k(50) * x2_50_0; // 2^100 - 1
        let x2_200_0 = x2_100_0.pow2k(100) * x2_100_0; // 2^200 - 1
        let x2_250_0 = x2_200_0.pow2k(50) * x2_50_0; // 2^250 - 1
        (x2_250_0, x11)
    }

    /// The element with limbs below 2^63 carried into limbs below 2^52: each
    /// limb's bits above 51 move into the next, and the top limb's into the
    /// bottom one, times 19, since 2^255 = 19 (mod p).
    ///
    /// The carries are below 2^13, so the bottom limb ends below 2^51 + 2^17
    /// and every other below 2^51.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "limbs below 2^63 and carries below 2^13: every sum is below 2^64"
    )]
    fn carry(limbs: [u64; 5]) -> FieldElement {
        let [l0, l1, l2, l3, l4] = limbs;
        let l1 = l1 + (l0 >> 51);
        let l2 = l2 + (l1 >> 51);
        let l3 = l3 + (l2 >> 51);
        let l4 = l4 + (l3 >> 51);
        let l0 = (l0 & LOW_51) + 19 * (l4 >> 51);
        FieldElement([l0, l1 & LOW_51, l2 & LOW_51, l3 & LOW_51, l4 & LOW_51])
    }
}

/// The four 64-bit words of a 32-octet little-endian string.
fn words(bytes: &[u8; 32]) -> [u64; 4] {
    let mut words = [0; 4];
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    words
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &FieldElement) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for FieldElement {}

impl Add for FieldElement {
    type Output = FieldElement;

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "limbs below 2^52, so their sums are below 2^53"
    )]
    fn add(self, other: FieldElement) -> FieldElement {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = other.0;
        FieldElement::carry([a0 + b0, a1 + b1, a2 + b2, a3 + b3, a4 + b4])
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;

    /// `a + 4 p - b`, which is `a - b` modulo p without a borrow.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "each limb of 4 p is above 2^52 and so above the limb of b subtracted from it, and \
                  the result is below 2^54"
    )]
    fn sub(self, other: FieldElement) -> FieldElement {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = other.0;
        let [p0, p1, p2, p3, p4] = FOUR_P;
        FieldElement::carry([
            a0 + p0 - b0,
            a1 + p1 - b1,
            a2 + p2 - b2,
            a3 + p3 - b3,
            a4 + p4 - b4,
        ])
    }
}

impl Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        FieldElement::ZERO - self
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    /// The schoolbook product, a term `a_i b_j` at `2^(51 (i + j))` folded
    /// down to `2^(51 (i + j - 5))` times 19 where `i + j` reaches 5.
    ///
    /// With limbs below 2^52, a limb times 19 is below 2^57, each product
    /// below 2^109, and the widest column, the lowest, is below 77 times
    /// 2^104, which is 2^111. The carries out of the columns, at most
    /// 2^111 / 2^51, keep the top column below 2^107, so its carry back to
    /// the bottom, times 19, is below 2^61.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "the column bounds in the documentation: below 2^111 in 128 bits"
    )]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the low 51 bits of a column, and a carry below 2^57"
    )]
    fn mul(self, other: FieldElement) -> FieldElement {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = other.0;
        let [b1_19, b2_19, b3_19, b4_19] = [b1, b2, b3, b4].map(|limb| limb * 19);
        let m = |a: u64, b: u64| u128::from(a) * u128::from(b);
        let c0 = m(a0, b0) + m(a1, b4_19) + m(a2, b3_19) + m(a3, b2_19) + m(a4, b1_19);
        let c1 = m(a0, b1) + m(a1, b0) + m(a2, b4_19) + m(a3, b3_19) + m(a4, b2_19);
        let c2 = m(a0, b2) + m(a1, b1) + m(a2, b0) + m(a3, b4_19) + m(a4, b3_19);
        let c3 = m(a0, b3) + m(a1, b2) + m(a2, b1) + m(a3, b0) + m(a4, b4_19);
        let c4 = m(a0, b4) + m(a1, b3) + m(a2, b2) + m(a3, b1) + m(a4, b0);
        let c1 = c1 + (c0 >> 51);
        let c2 = c2 + (c1 >> 51);
        let c3 = c3 + (c2 >> 51);
        let c4 = c4 + (c3 >> 51);
        let low = |column: u128| column as u64 & LOW_51;
        let top = (c4 >> 51) as u64;
        FieldElement::carry([low(c0) + 19 * top, low(c1), low(c2), low(c3), low(c4)])
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use num_bigint::BigUint;

    use super::{FieldElement, LOW_51};
    use crate::test_support::Rng;

    /// p, as a `num-bigint` value.
    fn p() -> BigUint {
        (BigUint::from(1u8) << 255u32) - BigUint::from(19u8)
    }

    /// An element's value, not reduced.
    fn value(element: FieldElement) -> BigUint {
        element
            .0
            .iter()
            .rev()
            .fold(BigUint::from(0u8), |total, &limb| (total << 51) + limb)
    }

    /// The element with the value `value`, which must be below p.
    fn element(value: &BigUint) -> FieldElement {
        let mut bytes = value.to_bytes_le();
        bytes.resize(32, 0);
        FieldElement::from_bytes(&bytes.try_into().unwrap()).unwrap()
    }

    /// Elements to compute with: edge values, and random ones whose limbs
    /// reach the 2^52 an operation may return.
    fn elements(rng: &mut Rng) -> Vec<FieldElement> {
        let mut elements: Vec<FieldElement> = [
            BigUint::from(0u8),
            BigUint::from(1u8),
            BigUint::from(2u8),
            BigUint::from(19u8),
            p() - 1u8,
            p() - 2u8,
            (BigUint::from(1u8) << 254u32) - 1u8,
            BigUint::from(1u8) << 254,
            BigUint::from(LOW_51),
            BigUint::from(1u8) << 51,
        ]
        .iter()
        .map(element)
        .collect();
        // Limbs at their bound, and above p.
        elements.push(FieldElement([(1 << 52) - 1; 5]));
        elements.push(FieldElement([(1 << 51) + (1 << 17) - 1, 0, 0, 0, 0]));
        for _ in 0..200 {
            let limbs = [0; 5].map(|_: u64| rng.next_u64() >> rng.below(13).saturating_add(12));
            elements.push(FieldElement(limbs));
        }
        elements
    }

    #[test]
    fn arithmetic_matches_num_bigint() {
        let mut rng = Rng::new(10);
        let elements = elements(&mut rng);
        let p = p();
        let mut checked = 0;
        for (i, &a) in elements.iter().enumerate() {
            let b = elements[(i * 7 + 3) % elements.len()];
            let (x, y) = (value(a), value(b));
            for (name, result, expected) in [
                ("add", a + b, (&x + &y) % &p),
                ("sub", a - b, (&x + &p * 4u8 - &y) % &p),
                ("neg", -a, (&p * 4u8 - &x) % &p),
                ("mul", a * b, (&x * &y) % &p),
                ("square", a.square(), (&x * &x) % &p),
            ] {
                assert!(result.0.iter().all(|&limb| limb < 1 << 52), "{name}");
                assert_eq!(value(result) % &p, expected, "{name} of {a:?} and {b:?}");
                checked += 1;
            }
        }
        assert_eq!(checked, 1060);
    }

    #[test]
    fn exponentiation_matches_num_bigint() {
        let mut rng = Rng::new(11);
        let p = p();
        let mut checked = 0;
        for a in elements(&mut rng) {
            let x = value(a) % &p;
            assert_eq!(value(a.invert()) % &p, x.modpow(&(&p - 2u8), &p));
            assert_eq!(value(a.pow_p58()) % &p, x.modpow(&((&p - 5u8) / 8u8), &p));
            if x != BigUint::from(0u8) {
                assert_eq!(a * a.invert(), FieldElement::ONE);
            }
            checked += 1;
        }
        assert_eq!(checked, 212);
    }

    #[test]
    fn encodings_are_canonical() {
        let mut rng = Rng::new(12);
        let p = p();
        let mut checked = 0;
        for a in elements(&mut rng) {
            let mut expected = (value(a) % &p).to_bytes_le();
            expected.resize(32, 0);
            let bytes = a.to_bytes();
            assert_eq!(bytes[..], expected[..], "{a:?}");
            assert_eq!(FieldElement::from_bytes(&bytes), Some(a));
            assert_eq!(a.is_odd(), bytes[0] & 1 == 1);
            checked += 1;
        }
        assert_eq!(checked, 212);
        // Every value from p to 2^255 - 1 is a non-canonical encoding, of
        // the values 0 to 18, and so is anything with bit 255 set.
        for excess in 0u8..19 {
            let mut bytes = (&p + excess).to_bytes_le();
            assert_eq!(bytes.len(), 32);
            assert_eq!(
                FieldElement::from_bytes(bytes.as_slice().try_into().unwrap()),
                None
            );
            bytes = BigUint::from(excess).to_bytes_le();
            bytes.resize(32, 0);
            let canonical: [u8; 32] = bytes.try_into().unwrap();
            assert!(FieldElement::from_bytes(&canonical).is_some());
            let mut high = canonical;
            high[31] |= 0x80;
            assert_eq!(FieldElement::from_bytes(&high), None);
        }
    }

    #[test]
    fn constants_are_what_they_name() {
        let p = p();
        let d = element(&BigUint::from(121_665u32));
        assert_eq!(
            FieldElement::D * element(&BigUint::from(121_666u32)),
            -d,
            "d = -121665/121666"
        );
        assert_eq!(
            value(FieldElement::D) % &p,
            "37095705934669439343138083508754565189542113879843219016388785533085940283555"
                .parse::<BigUint>()
                .unwrap(),
            "d as RFC 8032 §5.1 prints it"
        );
        assert_eq!(FieldElement::D2, FieldElement::D + FieldElement::D);
        assert_eq!(
            value(FieldElement::SQRT_M1) % &p,
            BigUint::from(2u8).modpow(&((&p - 1u8) / 4u8), &p)
        );
        assert_eq!(FieldElement::SQRT_M1.square(), -FieldElement::ONE);
    }
}
