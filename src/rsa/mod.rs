//! RSA signature verification: RSASSA-PKCS1-v1_5 (RFC 8017 §8.2.2), as
//! OpenPGP signs with it (RFC 9580 §5.2.3.1).
//!
//! [`PublicKey`] verifies a signature over a [`Digest`] the caller computed,
//! so a format outside OpenPGP that signs the same way can verify through it:
//!
//! ```no_run
//! use irongall::hash::{Digest, HashFunction as _, Sha256};
//! use irongall::rsa::PublicKey;
//!
//! # fn material() -> (Vec<u8>, Vec<u8>, Vec<u8>) { unimplemented!() }
//! // The key's modulus and public exponent, and the signature, as
//! // big-endian integers.
//! let (modulus, exponent, signature) = material();
//! let key = PublicKey::new(&modulus, &exponent)?;
//! key.verify(&Digest::Sha256(Sha256::digest(b"the signed data")), &signature)?;
//! # Ok::<(), irongall::rsa::RsaError>(())
//! ```
//!
//! It verifies what the signature computes, not what the digest is worth. It
//! accepts a digest of any function [`Digest`] names, SHA-1 among them, and
//! which functions a format may rest on is that format's decision; the
//! [`policy`](crate::policy) module makes it for OpenPGP.
//!
//! The signature is verified by construction and comparison: the encoding a
//! valid signature must recover, `0x00 0x01 0xFF.. 0x00 DigestInfo digest`, is
//! built from the digest, and compared whole against the value the signature
//! recovers. The recovered block is never parsed, so no laxity in reading it
//! can admit a forgery, as Bleichenbacher's 2006 attack on lenient parsers
//! did.
//!
//! The signature is read as an integer, as OpenPGP carries it, whose leading
//! zero octets are not significant: it verifies whether or not it is written
//! with them, and so does one shorter than the modulus. RFC 8017 §8.2.2
//! refuses a signature whose length in octets is not the modulus's, so a
//! format that holds a signature to that length, or that names a signature
//! by its octets, checks the length before verifying.
//!
//! The key is bounded on both sides. RFC 9580 §12.4 forbids verifying with a
//! modulus narrower than 2048 bits. The work of one verification grows with
//! the square of the modulus's width and linearly with the exponent's, and an
//! input chooses both, so a modulus wider than 8192 bits and an exponent above
//! 2^33 - 1 are refused too. These are ring's bounds, and no key GnuPG
//! generates exceeds them.

#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use core::fmt;

use crate::bignum::{self, Modulus};
use crate::hash::Digest;

/// The narrowest modulus irongall verifies with, in bits (RFC 9580 §12.4).
const MINIMUM_MODULUS_BITS: usize = 2048;

/// The widest modulus irongall verifies with, in bits.
const MAXIMUM_MODULUS_BITS: usize = 8192;

/// The largest public exponent irongall verifies with.
const MAXIMUM_EXPONENT: u64 = (1 << 33) - 1;

/// Why an RSA key is refused, or a signature does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RsaError {
    /// The modulus is narrower than 2048 bits, which RFC 9580 §12.4 forbids
    /// verifying with.
    ModulusTooShort,
    /// The modulus is wider than 8192 bits.
    ModulusTooLong,
    /// The public exponent is larger than 2^33 - 1.
    ExponentTooLarge,
    /// The key is not an RSA public key: its modulus is even, or its exponent
    /// is even or less than 3 (RFC 8017 §3.1).
    InvalidKey,
    /// The signature is not one the key made over the digest.
    BadSignature,
}

impl fmt::Display for RsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RsaError::ModulusTooShort => "an RSA modulus narrower than 2048 bits",
            RsaError::ModulusTooLong => "an RSA modulus wider than 8192 bits",
            RsaError::ExponentTooLarge => "an RSA public exponent larger than 2^33 - 1",
            RsaError::InvalidKey => "key material that is not an RSA public key",
            RsaError::BadSignature => "a signature the key did not make over the digest",
        })
    }
}

impl core::error::Error for RsaError {}

/// An RSA public key irongall verifies with: a modulus of 2048 to 8192 bits,
/// and an odd public exponent from 3 to 2^33 - 1.
///
/// The key is checked once, when it is made, and prepared for the arithmetic
/// every verification with it repeats.
#[derive(Clone)]
pub struct PublicKey {
    /// The modulus, whose length in octets sets the length of the encoding a
    /// signature must recover.
    modulus: Modulus,
    exponent: u64,
}

impl PublicKey {
    /// The key with the modulus `modulus` and the public exponent
    /// `exponent`, each a big-endian integer whose leading zeros are not
    /// significant.
    ///
    /// # Errors
    ///
    /// The first of these that applies, in this order:
    /// [`RsaError::ModulusTooShort`] or [`RsaError::ModulusTooLong`] for a
    /// modulus narrower than 2048 bits or wider than 8192,
    /// [`RsaError::InvalidKey`] for an even modulus,
    /// [`RsaError::ExponentTooLarge`] for an exponent larger than 2^33 - 1,
    /// whether even or odd, and [`RsaError::InvalidKey`] for an exponent
    /// that is even or less than 3.
    pub fn new(modulus: &[u8], exponent: &[u8]) -> Result<PublicKey, RsaError> {
        let exponent = check_key(modulus, exponent)?;
        let modulus = Modulus::new(modulus).ok_or(RsaError::InvalidKey)?;
        Ok(PublicKey { modulus, exponent })
    }

    /// Verifies that `signature`, a big-endian integer whose leading zeros
    /// are not significant, is the key's RSASSA-PKCS1-v1_5 signature over
    /// `digest`.
    ///
    /// # Errors
    ///
    /// [`RsaError::BadSignature`] for a signature the key did not make over
    /// `digest`, one that is not below the modulus among them.
    pub fn verify(&self, digest: &Digest, signature: &[u8]) -> Result<(), RsaError> {
        // RFC 8017 §5.2.2 refuses a signature that is not below the modulus.
        let recovered = self
            .modulus
            .pow(signature, self.exponent)
            .ok_or(RsaError::BadSignature)?;
        if recovered == encoding(digest, self.modulus.octet_length()) {
            Ok(())
        } else {
            Err(RsaError::BadSignature)
        }
    }
}

/// Names the key by its width and exponent. The modulus, and the arithmetic
/// prepared from it, would fill a screen and identify nothing a reader
/// compares by eye.
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("bits", &self.modulus.bits())
            .field("exponent", &self.exponent)
            .finish_non_exhaustive()
    }
}

/// Checks that `modulus` and `exponent`, big-endian, are a key irongall
/// verifies with: the modulus within the bounds the module's documentation
/// gives and odd, then the exponent within its bound, odd, and at least 3.
/// Returns the exponent, or the error of the first check it fails.
///
/// [`PublicKey::new`] refuses any other key, and the policy accepts no other
/// key, through this one check.
pub(crate) fn check_key(modulus: &[u8], exponent: &[u8]) -> Result<u64, RsaError> {
    let bits = bignum::bit_length(modulus);
    if bits < MINIMUM_MODULUS_BITS {
        return Err(RsaError::ModulusTooShort);
    }
    if bits > MAXIMUM_MODULUS_BITS {
        return Err(RsaError::ModulusTooLong);
    }
    // Leading zeros are not significant, so the last octet is the lowest.
    if modulus.last().is_none_or(|&low| low & 1 == 0) {
        return Err(RsaError::InvalidKey);
    }
    // An exponent past the bound is too large whatever else it is, as one
    // too wide for 64 bits must be, since its parity is not read.
    let exponent = bignum::to_u64(exponent).ok_or(RsaError::ExponentTooLarge)?;
    if exponent > MAXIMUM_EXPONENT {
        return Err(RsaError::ExponentTooLarge);
    }
    if exponent < 3 || exponent & 1 == 0 {
        return Err(RsaError::InvalidKey);
    }
    Ok(exponent)
}

/// The EMSA-PKCS1-v1_5 encoding of `digest` in `length` octets (RFC 9580
/// §12.1.3): `0x00 0x01`, `0xFF` octets to fill, `0x00`, then the digest's
/// DigestInfo, the prefix of Table 24 followed by the digest.
///
/// `length` is at least 256, since the modulus is at least 2048 bits, which
/// leaves at least 170 octets of `0xFF` beside the longest DigestInfo.
fn encoding(digest: &Digest, length: usize) -> Vec<u8> {
    let prefix = digest_info_prefix(digest);
    let digest = digest.as_bytes();
    let fill = length
        .saturating_sub(prefix.len())
        .saturating_sub(digest.len())
        .saturating_sub(3);
    let mut encoding = Vec::with_capacity(length);
    encoding.extend_from_slice(&[0x00, 0x01]);
    encoding.resize(fill.saturating_add(2), 0xFF);
    encoding.push(0x00);
    encoding.extend_from_slice(prefix);
    encoding.extend_from_slice(digest);
    encoding
}

/// The DER encoding of a DigestInfo for `digest`'s algorithm, up to the
/// digest itself (RFC 9580 Table 24).
fn digest_info_prefix(digest: &Digest) -> &'static [u8] {
    // Every algorithm a digest can be of is one irongall implements, and so
    // has one.
    digest.algorithm().digest_info_prefix().unwrap_or_default()
}
