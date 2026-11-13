//! Arithmetic on numbers of many limbs: the modular exponentiation RSA
//! verification is made of, and the comparison and reduction Ed25519's
//! scalars need.
//!
//! A number is a sequence of 64-bit limbs, least significant first. Every
//! residue is held in exactly as many limbs as the modulus, and below it.
//! Multiplication is Montgomery's (Montgomery, "Modular Multiplication Without
//! Trial Division", 1985), with the reduction interleaved into the product
//! limb by limb, so no division is ever performed.
//!
//! Nothing here runs in constant time. Everything a verification computes
//! over is public.

use alloc::vec;
use alloc::vec::Vec;

/// A limb: one 64-bit digit of a number.
pub(crate) type Limb = u64;

/// An odd modulus greater than one, prepared for Montgomery arithmetic.
///
/// With `s` the number of limbs, `R` is `2^(64 s)`: the Montgomery form of a
/// residue `x` is `x R mod n`, and multiplying two such forms divides by `R`
/// once, which keeps the result in that form.
#[derive(Debug, Clone)]
pub(crate) struct Modulus {
    /// The modulus, its most significant limb nonzero.
    limbs: Vec<Limb>,
    /// `-n^-1 mod 2^64`, from the least significant limb of `n`.
    inverse: Limb,
    /// `R^2 mod n`: multiplying a residue by it gives its Montgomery form.
    r_squared: Vec<Limb>,
    /// The modulus's length in octets, without leading zeros.
    octets: usize,
}

impl Modulus {
    /// The modulus with the big-endian value `big_endian`, or `None` unless
    /// the value is odd and greater than one, which Montgomery reduction
    /// needs.
    pub(crate) fn new(big_endian: &[u8]) -> Option<Modulus> {
        let limbs = limbs(big_endian);
        let low = *limbs.first()?;
        if low & 1 == 0 || limbs == [1] {
            return None;
        }
        let mut modulus = Modulus {
            inverse: negated_inverse(low),
            r_squared: Vec::new(),
            octets: bits(&limbs).div_ceil(8),
            limbs,
        };
        modulus.r_squared = modulus.r_squared();
        Some(modulus)
    }

    /// The modulus's length in octets, without leading zeros.
    pub(crate) fn octet_length(&self) -> usize {
        self.octets
    }

    /// The modulus's width in bits.
    pub(crate) fn bits(&self) -> usize {
        bits(&self.limbs)
    }

    /// `base^exponent mod n`, big-endian in as many octets as the modulus, or
    /// `None` if `base` is not below the modulus.
    pub(crate) fn pow(&self, base: &[u8], exponent: u64) -> Option<Vec<u8>> {
        let base = self.residue(base)?;
        let base = self.multiply(&base, &self.r_squared);
        let power = self.pow_montgomery(&base, exponent);
        // Multiplying by one divides by R, leaving the Montgomery form.
        Some(self.octets(&self.multiply(&power, &self.one())))
    }

    /// `R^2 mod n`.
    ///
    /// `2 R mod n` is the Montgomery form of 2, and raising it to `64 s` in
    /// that form gives the form of `2^(64 s) = R`, which is `R^2 mod n`. The
    /// form of 2 comes from the highest power of two below the modulus,
    /// doubled the 65 or fewer times that take it to `2^(64 s + 1)`.
    fn r_squared(&self) -> Vec<Limb> {
        let width = self.limbs.len().saturating_mul(64);
        let top = bits(&self.limbs).saturating_sub(1);
        // Below the modulus, which is odd, so not a power of two.
        let mut two = vec![0; self.limbs.len()];
        if let Some(limb) = two.get_mut(top / 64) {
            *limb = 1 << (top % 64);
        }
        for _ in top..=width {
            self.double(&mut two);
        }
        self.pow_montgomery(&two, u64::try_from(width).unwrap_or(u64::MAX))
    }

    /// `base^exponent` in Montgomery form, for `base` in Montgomery form, by
    /// squaring and multiplying from the exponent's most significant bit.
    fn pow_montgomery(&self, base: &[Limb], exponent: u64) -> Vec<Limb> {
        let Some(top) = exponent.checked_ilog2() else {
            // The Montgomery form of one: one times R.
            return self.multiply(&self.one(), &self.r_squared);
        };
        let mut power = base.to_vec();
        for bit in (0..top).rev() {
            power = self.multiply(&power, &power);
            if exponent
                .checked_shr(bit)
                .is_some_and(|shifted| shifted & 1 == 1)
            {
                power = self.multiply(&power, base);
            }
        }
        power
    }

    /// `a b R^-1 mod n`, for residues `a` and `b`.
    ///
    /// Each round adds `a b_i` to the running total `t`, then the multiple of
    /// `n` that clears the total's least significant limb, and drops that
    /// limb. With `a` below `n`, `t` stays below `a + n`, so below `2 n`,
    /// which is `s` limbs and one bit (`top`), and the sum before a round's
    /// division is below `2 n 2^64`, so its two carries out of the top limb
    /// are never both set. One subtraction at the end brings `t` below `n`.
    fn multiply(&self, a: &[Limb], b: &[Limb]) -> Vec<Limb> {
        let n = &self.limbs;
        let a_low = a.first().copied().unwrap_or(0);
        let mut t = vec![0; n.len()];
        let mut top = false;
        for &b_i in b {
            let t_low = t.first().copied().unwrap_or(0);
            let m = multiply_add(a_low, b_i, t_low, 0)
                .0
                .wrapping_mul(self.inverse);
            let mut carry_a = 0;
            let mut carry_n = 0;
            // Where each limb of the sum goes once it is divided by 2^64: one
            // place down. The sum's least significant limb is zero.
            let mut below: Option<&mut Limb> = None;
            for ((t_j, &a_j), &n_j) in t.iter_mut().zip(a).zip(n) {
                let (low, high) = multiply_add(a_j, b_i, *t_j, carry_a);
                carry_a = high;
                let (low, high) = multiply_add(m, n_j, low, carry_n);
                carry_n = high;
                if let Some(below) = below {
                    *below = low;
                }
                below = Some(t_j);
            }
            let (low, carry_1) = Limb::from(top).overflowing_add(carry_a);
            let (low, carry_2) = low.overflowing_add(carry_n);
            if let Some(below) = below {
                *below = low;
            }
            top = carry_1 || carry_2;
        }
        if top || !less_than(&t, n) {
            subtract(&mut t, n);
        }
        t
    }

    /// `2 x mod n`, in place, for a residue `x`.
    fn double(&self, x: &mut [Limb]) {
        double_add(x, false, &self.limbs);
    }

    /// The residue one.
    fn one(&self) -> Vec<Limb> {
        let mut one = vec![0; self.limbs.len()];
        if let Some(low) = one.first_mut() {
            *low = 1;
        }
        one
    }

    /// The residue with the big-endian value `big_endian`, in as many limbs
    /// as the modulus, or `None` if it is not below the modulus.
    fn residue(&self, big_endian: &[u8]) -> Option<Vec<Limb>> {
        let mut x = limbs(big_endian);
        if x.len() > self.limbs.len() {
            return None;
        }
        x.resize(self.limbs.len(), 0);
        less_than(&x, &self.limbs).then_some(x)
    }

    /// A residue's big-endian octets, as many as the modulus has.
    fn octets(&self, x: &[Limb]) -> Vec<u8> {
        // The residue is below the modulus, so the octets skipped are zero.
        let skip = x.len().saturating_mul(8).saturating_sub(self.octets);
        x.iter()
            .rev()
            .flat_map(|limb| limb.to_be_bytes())
            .skip(skip)
            .collect()
    }
}

/// The number of significant bits in the big-endian value `big_endian`.
///
/// Read from the octets, without converting them to limbs, so asking it of
/// a key's modulus costs nothing however often it is asked.
pub(crate) fn bit_length(big_endian: &[u8]) -> usize {
    let Some(at) = big_endian.iter().position(|&octet| octet != 0) else {
        return 0;
    };
    let unused = big_endian.get(at).map_or(0, |octet| octet.leading_zeros());
    big_endian
        .len()
        .saturating_sub(at)
        .saturating_mul(8)
        .saturating_sub(usize::try_from(unused).unwrap_or(0))
}

/// The big-endian value `big_endian`, if it fits in 64 bits.
pub(crate) fn to_u64(big_endian: &[u8]) -> Option<u64> {
    match limbs(big_endian).as_slice() {
        [] => Some(0),
        [value] => Some(*value),
        _ => None,
    }
}

/// The limbs of the big-endian value `big_endian`, without the zero limbs a
/// leading run of zero octets would make.
fn limbs(big_endian: &[u8]) -> Vec<Limb> {
    let mut limbs: Vec<Limb> = big_endian
        .rchunks(8)
        .map(|chunk| {
            let mut octets = [0; 8];
            for (slot, octet) in octets.iter_mut().rev().zip(chunk.iter().rev()) {
                *slot = *octet;
            }
            Limb::from_be_bytes(octets)
        })
        .collect();
    while limbs.last() == Some(&0) {
        limbs.pop();
    }
    limbs
}

/// The number of significant bits in a number given as limbs.
fn bits(limbs: &[Limb]) -> usize {
    let Some(position) = limbs.iter().rposition(|&limb| limb != 0) else {
        return 0;
    };
    let unused = limbs.get(position).map_or(64, |limb| limb.leading_zeros());
    position
        .saturating_add(1)
        .saturating_mul(64)
        .saturating_sub(usize::try_from(unused).unwrap_or(0))
}

/// `a b + c + d`, as its low and high limbs.
///
/// The result never exceeds `(2^64 - 1)^2 + 2 (2^64 - 1) = 2^128 - 1`, so it
/// fits in the 128 bits it is computed in.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the two halves of a 128-bit value"
)]
fn multiply_add(a: Limb, b: Limb, c: Limb, d: Limb) -> (Limb, Limb) {
    let wide = u128::from(a)
        .wrapping_mul(u128::from(b))
        .wrapping_add(u128::from(c))
        .wrapping_add(u128::from(d));
    (wide as Limb, wide.wrapping_shr(64) as Limb)
}

/// `2 x + bit mod n`, in place, for `x` below `n` and of as many limbs.
///
/// One step of Horner's rule: reducing a number of any length, its bits fed
/// in from the most significant, is this step once per bit.
pub(crate) fn double_add(x: &mut [Limb], bit: bool, n: &[Limb]) {
    let mut carry = bit;
    for limb in x.iter_mut() {
        let rotated = limb.rotate_left(1);
        *limb = (rotated & !1) | Limb::from(carry);
        carry = rotated & 1 == 1;
    }
    // `2 x + 1` is below `2 n`, so one subtraction reduces it, and a carry out
    // of the top limb is the borrow that subtraction cancels.
    if carry || !less_than(x, n) {
        subtract(x, n);
    }
}

/// Whether `a` is below `b`, for numbers of the same number of limbs.
pub(crate) fn less_than(a: &[Limb], b: &[Limb]) -> bool {
    a.iter().rev().lt(b.iter().rev())
}

/// `a - b`, in place, modulo `2^(64 s)` for `s` limbs.
fn subtract(a: &mut [Limb], b: &[Limb]) {
    let mut borrow = false;
    for (a_j, &b_j) in a.iter_mut().zip(b) {
        let (difference, borrow_1) = a_j.overflowing_sub(b_j);
        let (difference, borrow_2) = difference.overflowing_sub(Limb::from(borrow));
        *a_j = difference;
        borrow = borrow_1 || borrow_2;
    }
}

/// `-x^-1 mod 2^64`, for an odd `x`.
///
/// Newton's iteration `y (2 - x y)` doubles the number of correct low bits of
/// the inverse. An odd `x` is its own inverse modulo 8, which gives three, and
/// five iterations take them past 64.
fn negated_inverse(x: Limb) -> Limb {
    let mut y = x;
    for _ in 0..5 {
        y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    }
    y.wrapping_neg()
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use num_bigint::BigUint;

    use super::{Modulus, bit_length, negated_inverse, to_u64};
    use crate::test_support::Rng;

    /// Checks `pow` against `num-bigint` for one case.
    fn check(modulus: &[u8], base: &[u8], exponent: u64) {
        let n = BigUint::from_bytes_be(modulus);
        let expected = BigUint::from_bytes_be(base).modpow(&BigUint::from(exponent), &n);
        let octets = bit_length(modulus).div_ceil(8);
        let mut expected = expected.to_bytes_be();
        // `num-bigint` writes zero as one zero octet, and nothing else with a
        // leading zero.
        if expected == [0] {
            expected.clear();
        }
        let mut padded = alloc::vec![0; octets - expected.len()];
        padded.extend(expected);
        let actual = Modulus::new(modulus).unwrap().pow(base, exponent).unwrap();
        assert_eq!(
            actual, padded,
            "modulus {modulus:02x?}, base {base:02x?}, exponent {exponent}"
        );
    }

    /// An odd value of `octets` octets, its first octet nonzero.
    fn odd(rng: &mut Rng, octets: usize) -> Vec<u8> {
        let mut value = rng.bytes(octets);
        value[0] |= 1 << rng.below(8);
        *value.last_mut().unwrap() |= 1;
        value
    }

    /// A value below `modulus`.
    fn below(rng: &mut Rng, modulus: &[u8]) -> Vec<u8> {
        let mut value = rng.bytes(modulus.len());
        value[0] %= modulus[0];
        value
    }

    #[test]
    fn negated_inverse_inverts() {
        let mut rng = Rng::new(1);
        for x in [1, 3, u64::MAX, u64::MAX - 2]
            .into_iter()
            .chain((0..1000).map(|_| rng.next_u64() | 1))
        {
            assert_eq!(x.wrapping_mul(negated_inverse(x)), u64::MAX, "{x}");
        }
    }

    #[test]
    fn exponentiation_matches_num_bigint() {
        let mut rng = Rng::new(2);
        let mut checked = 0;
        // Every length up to three limbs, then lengths either side of limb
        // boundaries, up to one octet past the widest modulus RSA
        // verification accepts.
        for octets in (1..=24).chain([63, 64, 65, 127, 128, 129, 255, 256, 257, 384, 512, 1025]) {
            for _ in 0..4 {
                let modulus = odd(&mut rng, octets);
                for exponent in [0, 1, 2, 3, 17, 65537, (1 << 33) - 1, rng.next_u64()] {
                    let base = below(&mut rng, &modulus);
                    check(&modulus, &base, exponent);
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 1152);
    }

    #[test]
    fn products_are_reduced() {
        // A product must be the residue itself, below the modulus, and not
        // merely congruent to it: the next multiplication relies on that, and
        // the final one out of Montgomery form would hide it. Moduli whose
        // top bit is set are where an unreduced product is likeliest.
        let mut rng = Rng::new(3);
        let mut checked = 0;
        for octets in [8, 16, 64, 256, 512] {
            for _ in 0..8 {
                let mut modulus = odd(&mut rng, octets);
                modulus[0] |= 0x80;
                let n = BigUint::from_bytes_be(&modulus);
                let prepared = Modulus::new(&modulus).unwrap();
                let r = BigUint::from(1u8) << (64 * prepared.limbs.len());
                let value = |limbs: &[u64]| {
                    BigUint::from_bytes_le(
                        &limbs
                            .iter()
                            .flat_map(|limb| limb.to_le_bytes())
                            .collect::<Vec<u8>>(),
                    )
                };
                for _ in 0..64 {
                    let a = prepared.residue(&below(&mut rng, &modulus)).unwrap();
                    let b = prepared.residue(&below(&mut rng, &modulus)).unwrap();
                    let product = value(&prepared.multiply(&a, &b));
                    assert!(product < n);
                    assert_eq!(&product * &r % &n, value(&a) * value(&b) % &n);
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 2560);
    }

    #[test]
    fn exponentiation_edge_values() {
        let mut checked = 0;
        for modulus in [
            alloc::vec![3],
            alloc::vec![0xFF; 8],
            alloc::vec![0xFF; 256],
            [&[1][..], &[0; 255], &[1]].concat(),
            [&[0x80][..], &[0; 254], &[1]].concat(),
        ] {
            let mut largest = modulus.clone();
            *largest.last_mut().unwrap() -= 1;
            for base in [
                Vec::new(),
                alloc::vec![0],
                alloc::vec![1],
                alloc::vec![2],
                largest,
            ] {
                for exponent in [0, 1, 2, 3, 65537, u64::MAX] {
                    check(&modulus, &base, exponent);
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 150);
    }

    #[test]
    fn leading_zeros_do_not_count() {
        let modulus = [0, 0, 0x01, 0x00, 0x01];
        let modulus = Modulus::new(&modulus).unwrap();
        // 2^17 mod 65537, in the modulus's three octets.
        assert_eq!(
            modulus.pow(&[0, 0, 0, 0, 0, 2], 17),
            Some(alloc::vec![0x00, 0xFF, 0xFF])
        );
        assert_eq!(bit_length(&[0, 0, 0x01, 0x00, 0x01]), 17);
        assert_eq!(bit_length(&[0, 0]), 0);
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(
            to_u64(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1]),
            Some((1 << 56) + 1)
        );
        assert_eq!(to_u64(&[1, 0, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(to_u64(&[]), Some(0));
    }

    /// The bit length read from the octets is the one the limbs hold.
    #[test]
    fn bit_length_reads_the_octets() {
        let mut rng = Rng::new(4);
        let mut checked = 0;
        for octets in 0..=80 {
            for _ in 0..16 {
                let mut value = rng.bytes(octets);
                // Leading zero octets, then a first octet of any width.
                let zeros = rng.below(octets + 1);
                value[..zeros].fill(0);
                if let Some(first) = value.get_mut(zeros) {
                    *first >>= rng.below(8);
                }
                assert_eq!(
                    bit_length(&value),
                    super::bits(&super::limbs(&value)),
                    "{value:02x?}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 1296);
    }

    #[test]
    fn refusals() {
        // Even, one, zero, and empty moduli.
        for modulus in [&[0x10, 0x00][..], &[1], &[0, 1], &[0], &[]] {
            assert!(Modulus::new(modulus).is_none(), "{modulus:02x?}");
        }
        // A base equal to the modulus, above it, or wider than it.
        let modulus = Modulus::new(&[0x01, 0x00, 0x01]).unwrap();
        for base in [
            &[0x01, 0x00, 0x01][..],
            &[0x01, 0x00, 0x02],
            &[1, 0, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert_eq!(modulus.pow(base, 3), None, "{base:02x?}");
        }
    }
}
