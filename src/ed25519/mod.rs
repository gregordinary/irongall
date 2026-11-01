//! Ed25519 signature verification (RFC 8032 §5.1.7), as OpenPGP signs with
//! it: the Ed25519 algorithm (RFC 9580 §5.2.3.4), and EdDSALegacy over the
//! Ed25519Legacy curve (§5.2.3.3). Both sign a digest of the signed data
//! with PureEdDSA (§12.7), and differ only in how they carry the key and the
//! signature, which the key and signature packets undo.
//!
//! RFC 8032 leaves a verifier some latitude, and implementations differ on
//! signatures nobody makes honestly. irongall refuses:
//!
//! - an S of L or more, which §5.1.7 requires: otherwise adding L to S makes
//!   a second valid signature from any first one;
//! - an encoding of A or R that is not canonical, which §5.1.3's decoding
//!   requires: R is compared as an encoding, against the canonical encoding
//!   of the point the equation computes, so only the canonical R matches;
//! - an A of small order, a key anyone can sign for: when A is the
//!   identity, `R = B` and `S = 1` verify for every message;
//! - an R of small order, which no honest signer produces.
//!
//! The equation is the cofactorless `[S]B = R + [k]A`, with k reduced modulo
//! L, which §5.1.7 allows in place of the cofactored one. libsodium applies
//! the same rules. So does ed25519-dalek's `verify_strict`, which the tests
//! compare against, except that it accepts a key encoded with a y-coordinate
//! of p or more. Honestly made signatures verify under every variant; the
//! rules decide only which deliberately malformed ones are refused.
//!
//! Nothing here runs in constant time: everything verification computes
//! over is public.

mod field;
mod point;
mod scalar;

#[cfg(test)]
mod tests;

use crate::hash::{Digest, HashFunction, Sha512};
use point::Point;
use scalar::Scalar;

/// Why an Ed25519 signature does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ed25519Error {
    /// The key is not a point a signature can be verified with: it is not
    /// the canonical encoding of a point, or the point is of small order.
    InvalidKey,
    /// The signature is not one the key made over the digest.
    BadSignature,
}

/// Verifies that `signature`, in its native encoding (RFC 8032 §5.1.6), is
/// the signature of the key `key`, in its native encoding (§5.1.5), over
/// `digest`.
///
/// A digest of any length is the message signed. RFC 9580 forbids accepting
/// an OpenPGP signature over a digest shorter than 256 bits, and
/// [`Signature::verify`](crate::signature::Signature::verify) applies that
/// floor, since it is OpenPGP's rule and not Ed25519's.
pub(crate) fn verify(
    key: &[u8; 32],
    digest: &Digest,
    signature: &[u8; 64],
) -> Result<(), Ed25519Error> {
    verify_message(key, digest.as_bytes(), signature)
}

/// Checks that `key`, in its native encoding, is a key irongall verifies
/// with: the canonical encoding of a point not of small order.
///
/// [`verify`] refuses any other key whatever the signature, and the policy
/// accepts no other key, through this one check.
pub(crate) fn check_key(key: &[u8; 32]) -> Result<(), Ed25519Error> {
    decode_key(key).map(drop)
}

/// The point `key` encodes, if it is a key irongall verifies with (see
/// [`check_key`]).
fn decode_key(key: &[u8; 32]) -> Result<Point, Ed25519Error> {
    let a = Point::decode(key).ok_or(Ed25519Error::InvalidKey)?;
    if a.has_small_order() {
        return Err(Ed25519Error::InvalidKey);
    }
    Ok(a)
}

/// Verifies `signature` over `message` (RFC 8032 §5.1.7), under the rules
/// in the module's documentation.
fn verify_message(
    key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), Ed25519Error> {
    let a = decode_key(key)?;
    let (Some(r), Some(s)) = (signature.first_chunk::<32>(), signature.last_chunk::<32>()) else {
        return Err(Ed25519Error::BadSignature);
    };
    let s = Scalar::from_canonical_bytes(s).ok_or(Ed25519Error::BadSignature)?;
    let mut hash = Sha512::new();
    hash.update(r);
    hash.update(key);
    hash.update(message);
    let k = Scalar::reduce(&hash.finalize());
    // [S]B - [k]A, which is R if the signature is valid.
    let computed = point::double_scalar_multiply(&s, &k, &a.negate());
    if computed.encode() != *r || computed.has_small_order() {
        return Err(Ed25519Error::BadSignature);
    }
    Ok(())
}
