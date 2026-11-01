//! Points of edwards25519, the twisted Edwards curve
//! `-x^2 + y^2 = 1 + d x^2 y^2` Ed25519 is defined over (RFC 8032 §5.1).
//!
//! A point is held in the extended coordinates of RFC 8032 §5.1.4: `(X, Y,
//! Z, T)` with `x = X/Z`, `y = Y/Z`, and `x y = T/Z`. The addition and
//! doubling formulas there are complete on this curve, so neither needs a
//! case for the identity or for equal points.

use super::field::FieldElement;
use super::scalar::Scalar;

/// A point of the curve.
#[derive(Debug, Clone, Copy)]
pub(super) struct Point {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl Point {
    /// The identity, (0, 1).
    const IDENTITY: Point = Point {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// B, the base point (RFC 8032 §5.1): the point with y = 4/5 and an even
    /// x.
    pub(super) const BASE: Point = Point {
        x: FieldElement::from_limbs([
            0x6_2D60_8F25_D51A,
            0x4_12A4_B4F6_592A,
            0x7_5B71_71A4_B31D,
            0x1_FF60_5271_18FE,
            0x2_1693_6D3C_D6E5,
        ]),
        y: FieldElement::from_limbs([
            0x6_6666_6666_6658,
            0x4_CCCC_CCCC_CCCC,
            0x1_9999_9999_9999,
            0x3_3333_3333_3333,
            0x6_6666_6666_6666,
        ]),
        z: FieldElement::ONE,
        t: FieldElement::from_limbs([
            0x6_8AB3_A5B7_DDA3,
            0x0_0EEA_2A5E_ADBB,
            0x2_AF8D_F483_C27E,
            0x3_32B3_7527_4732,
            0x6_7875_F0FD_78B7,
        ]),
    };

    /// The point a 32-octet string encodes, or `None` if it encodes none
    /// (RFC 8032 §5.1.3).
    ///
    /// Only the canonical encoding of a point decodes: a y-coordinate of p or
    /// more fails, as does the sign bit set on an x-coordinate of zero.
    pub(super) fn decode(bytes: &[u8; 32]) -> Option<Point> {
        let mut y = *bytes;
        let [.., top] = &mut y;
        let x_0 = *top >> 7 == 1;
        *top &= 0x7F;
        let y = FieldElement::from_bytes(&y)?;
        // x^2 = (y^2 - 1)/(d y^2 + 1) = u/v, and x = u v^3 (u v^7)^((p-5)/8)
        // is a square root of it if it has one, or of -u/v if that has one.
        let yy = y.square();
        let u = yy - FieldElement::ONE;
        let v = FieldElement::D * yy + FieldElement::ONE;
        let v3 = v.square() * v;
        let v7 = v3.square() * v;
        let mut x = u * v3 * (u * v7).pow_p58();
        let vxx = v * x.square();
        if vxx == -u {
            x = x * FieldElement::SQRT_M1;
        } else if vxx != u {
            return None;
        }
        if x == FieldElement::ZERO && x_0 {
            return None;
        }
        if x.is_odd() != x_0 {
            x = -x;
        }
        Some(Point {
            x,
            y,
            z: FieldElement::ONE,
            t: x * y,
        })
    }

    /// The point's encoding (RFC 8032 §5.1.2): y, with the parity of x in
    /// bit 255.
    pub(super) fn encode(&self) -> [u8; 32] {
        let z_inverse = self.z.invert();
        let x = self.x * z_inverse;
        let mut bytes = (self.y * z_inverse).to_bytes();
        let [.., top] = &mut bytes;
        *top |= u8::from(x.is_odd()) << 7;
        bytes
    }

    /// The sum of two points (RFC 8032 §5.1.4).
    pub(super) fn add(&self, other: &Point) -> Point {
        let a = (self.y - self.x) * (other.y - other.x);
        let b = (self.y + self.x) * (other.y + other.x);
        let c = self.t * FieldElement::D2 * other.t;
        let d = self.z * (other.z + other.z);
        let (e, f, g, h) = (b - a, d - c, d + c, b + a);
        Point {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }

    /// The point doubled (RFC 8032 §5.1.4).
    pub(super) fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let zz = self.z.square();
        let c = zz + zz;
        let h = a + b;
        let e = h - (self.x + self.y).square();
        let g = a - b;
        let f = c + g;
        Point {
            x: e * f,
            y: g * h,
            t: e * h,
            z: f * g,
        }
    }

    /// The point's negation: (-x, y).
    pub(super) fn negate(&self) -> Point {
        Point {
            x: -self.x,
            t: -self.t,
            ..*self
        }
    }

    /// Whether the point's order divides the cofactor, 8: whether it is one
    /// of the eight points of the curve's small subgroup.
    pub(super) fn has_small_order(&self) -> bool {
        self.double().double().double().is_identity()
    }

    /// Whether the point is the identity: x = 0 and y = 1.
    fn is_identity(&self) -> bool {
        self.x == FieldElement::ZERO && self.y == self.z
    }
}

/// `[s]B + [k]P`, both multiplications at once: one doubling per bit, and
/// for each bit set in either scalar the addition of B, P, or their sum
/// (Straus's method).
pub(super) fn double_scalar_multiply(s: &Scalar, k: &Scalar, p: &Point) -> Point {
    let both = Point::BASE.add(p);
    s.bits().zip(k.bits()).fold(Point::IDENTITY, |sum, bits| {
        let sum = sum.double();
        match bits {
            (true, true) => sum.add(&both),
            (true, false) => sum.add(&Point::BASE),
            (false, true) => sum.add(p),
            (false, false) => sum,
        }
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use num_bigint::BigUint;

    use super::{Point, double_scalar_multiply};
    use crate::ed25519::field::FieldElement;
    use crate::ed25519::scalar::Scalar;
    use crate::test_support::{Rng, hex};

    /// The canonical encodings of the eight points of small order.
    const SMALL_ORDER: [&str; 8] = [
        // The identity, (0, 1).
        "0100000000000000000000000000000000000000000000000000000000000000",
        // (0, -1), of order 2.
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // (sqrt(-1), 0) and its negation, of order 4.
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        // The four of order 8.
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ];

    fn bytes(text: &str) -> [u8; 32] {
        hex(text).try_into().unwrap()
    }

    /// `[scalar]P` by doubling and adding, the scalar given as its bytes,
    /// little-endian; independent of [`double_scalar_multiply`].
    fn multiply(p: &Point, scalar: &[u8]) -> Point {
        scalar
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |bit| byte >> bit & 1 == 1))
            .fold(Point::IDENTITY, |sum, bit| {
                let sum = sum.double();
                if bit { sum.add(p) } else { sum }
            })
    }

    /// L, the order of the base point, little-endian.
    fn order() -> Vec<u8> {
        let l = (BigUint::from(1u8) << 252u32)
            + "27742317777372353535851937790883648493"
                .parse::<BigUint>()
                .unwrap();
        l.to_bytes_le()
    }

    #[test]
    fn base_point() {
        let encoded = bytes("5866666666666666666666666666666666666666666666666666666666666666");
        let decoded = Point::decode(&encoded).unwrap();
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(Point::BASE.encode(), encoded);
        for (constant, decoded) in [
            (Point::BASE.x, decoded.x),
            (Point::BASE.y, decoded.y),
            (Point::BASE.t, decoded.t),
        ] {
            assert_eq!(constant, decoded);
        }
        // y = 4/5, and x as RFC 8032 §5.1 prints it.
        let five = FieldElement::ONE + FieldElement::ONE + FieldElement::ONE + FieldElement::ONE;
        assert_eq!(Point::BASE.y * (five + FieldElement::ONE), five);
        let mut x = "15112221349535400772501151409588531511454012693041857206046113283949847762202"
            .parse::<BigUint>()
            .unwrap()
            .to_bytes_le();
        x.resize(32, 0);
        assert_eq!(Point::BASE.x.to_bytes()[..], x[..]);
        // [L]B is the identity, and B is not of small order.
        assert!(multiply(&Point::BASE, &order()).is_identity());
        assert!(!Point::BASE.has_small_order());
    }

    #[test]
    fn small_order_points() {
        let mut checked = 0;
        for encoding in SMALL_ORDER {
            let point = Point::decode(&bytes(encoding)).unwrap();
            assert_eq!(point.encode(), bytes(encoding));
            assert!(point.has_small_order(), "{encoding}");
            // Added to B, each makes a point that is not of small order, and
            // whose multiple by L is of small order, the identity only when
            // the point added was.
            let mixed = Point::BASE.add(&point);
            assert!(!mixed.has_small_order());
            let torsion = multiply(&mixed, &order());
            assert!(torsion.has_small_order());
            assert_eq!(torsion.is_identity(), point.is_identity());
            checked += 1;
        }
        assert_eq!(checked, 8);
    }

    #[test]
    fn decoding_refuses_non_canonical_encodings() {
        // The y-coordinates 0 to 18 have a second encoding, y + p, which the
        // decoder must refuse whether or not y has a point.
        let p = (BigUint::from(1u8) << 255u32) - 19u8;
        let mut points = 0;
        for y in 0u8..19 {
            let mut canonical = BigUint::from(y).to_bytes_le();
            canonical.resize(32, 0);
            let canonical: [u8; 32] = canonical.try_into().unwrap();
            let mut alias: [u8; 32] = (&p + y).to_bytes_le().try_into().unwrap();
            for sign in [0, 0x80] {
                let mut with_sign = canonical;
                with_sign[31] |= sign;
                alias[31] = (alias[31] & 0x7F) | sign;
                assert!(
                    Point::decode(&alias).is_none(),
                    "y = p + {y}, sign {sign:#x}"
                );
                if let Some(point) = Point::decode(&with_sign) {
                    assert_eq!(point.encode(), with_sign);
                    points += 1;
                }
            }
        }
        // At least the two points with y = 0, and the identity, whose
        // encoding with the sign bit set is refused.
        assert!(points >= 3, "{points}");
        // x = 0 with the sign bit set: the identity and (0, -1).
        for encoding in [
            "0100000000000000000000000000000000000000000000000000000000000080",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            assert!(Point::decode(&bytes(encoding)).is_none(), "{encoding}");
        }
    }

    #[test]
    fn decoding_agrees_with_the_curve_equation() {
        // A random string decodes exactly when its y gives a square x^2;
        // when it does, the point is on the curve and encodes back to it.
        let mut rng = Rng::new(20);
        let mut decoded = 0;
        for _ in 0..400 {
            let encoding: [u8; 32] = rng.bytes(32).try_into().unwrap();
            if let Some(point) = Point::decode(&encoding) {
                assert_eq!(point.encode(), encoding);
                let (x, y) = (point.x, point.y);
                assert_eq!(
                    y.square() - x.square(),
                    FieldElement::ONE + FieldElement::D * x.square() * y.square()
                );
                assert_eq!(point.t, x * y);
                decoded += 1;
            }
        }
        // About half of all y-coordinates have points.
        assert!((150..250).contains(&decoded), "{decoded}");
    }

    #[test]
    fn double_scalar_multiplication() {
        let mut rng = Rng::new(21);
        let order = order();
        let mut checked = 0;
        for i in 0..40 {
            // P is a multiple of B, so it has order L, as B does, and
            // multiplying either by a scalar or by the scalar reduced modulo L
            // gives the same point.
            let p = multiply(&Point::BASE, &rng.bytes(32));
            let (s, k) = match i {
                0 => (alloc::vec![0; 32], alloc::vec![0; 32]),
                1 => (order.clone(), order.clone()),
                2 => (alloc::vec![0xFF; 32], alloc::vec![1]),
                _ => (rng.bytes(32), rng.bytes(32)),
            };
            let expected = multiply(&Point::BASE, &s).add(&multiply(&p, &k));
            let reduce = |bytes: &[u8]| {
                let mut wide = [0; 64];
                wide[..bytes.len()].copy_from_slice(bytes);
                Scalar::reduce(&wide)
            };
            let actual = double_scalar_multiply(&reduce(&s), &reduce(&k), &p);
            assert_eq!(actual.encode(), expected.encode(), "case {i}");
            checked += 1;
        }
        assert_eq!(checked, 40);
    }

    #[test]
    fn negation() {
        let p = multiply(&Point::BASE, &[7]);
        assert!(p.add(&p.negate()).is_identity());
        let mut flipped = p.encode();
        flipped[31] ^= 0x80;
        assert_eq!(p.negate().encode(), flipped);
    }
}
