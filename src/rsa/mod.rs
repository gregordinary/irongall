//! RSA signature verification: RSASSA-PKCS1-v1_5 (RFC 8017 §8.2.2), as
//! OpenPGP signs with it (RFC 9580 §5.2.3.1).
//!
//! The signature is verified by construction and comparison: the encoding a
//! valid signature must recover, `0x00 0x01 0xFF.. 0x00 DigestInfo digest`, is
//! built from the digest, and compared whole against the value the signature
//! recovers. The recovered block is never parsed, so no laxity in reading it
//! can admit a forgery, as Bleichenbacher's 2006 attack on lenient parsers
//! did.
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

use crate::bignum::{self, Modulus};
use crate::hash::Digest;

/// The narrowest modulus irongall verifies with, in bits (RFC 9580 §12.4).
const MINIMUM_MODULUS_BITS: usize = 2048;

/// The widest modulus irongall verifies with, in bits.
const MAXIMUM_MODULUS_BITS: usize = 8192;

/// The largest public exponent irongall verifies with.
const MAXIMUM_EXPONENT: u64 = (1 << 33) - 1;

/// Why an RSA signature does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RsaError {
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

/// Verifies that `signature`, an RSA signature value as OpenPGP carries it
/// (an integer, big-endian), is the key's signature over `digest`.
///
/// `modulus` and `exponent` are the key's, big-endian. Leading zeros in any
/// of the three are not significant.
pub(crate) fn verify(
    modulus: &[u8],
    exponent: &[u8],
    digest: &Digest,
    signature: &[u8],
) -> Result<(), RsaError> {
    let exponent = check_key(modulus, exponent)?;
    let bits = bignum::bit_length(modulus);
    let modulus = Modulus::new(modulus).ok_or(RsaError::InvalidKey)?;
    // RFC 8017 §5.2.2 refuses a signature that is not below the modulus.
    let recovered = modulus
        .pow(signature, exponent)
        .ok_or(RsaError::BadSignature)?;
    if recovered == encoding(digest, bits.div_ceil(8)) {
        Ok(())
    } else {
        Err(RsaError::BadSignature)
    }
}

/// Checks that `modulus` and `exponent`, big-endian, are a key irongall
/// verifies with: the modulus odd and within the bounds the module's
/// documentation gives, the exponent odd, at least 3, and within its bound.
/// Returns the exponent.
///
/// [`verify`] refuses any other key whatever the signature, and the policy
/// accepts no other key, through this one check.
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
    let exponent = bignum::to_u64(exponent).ok_or(RsaError::ExponentTooLarge)?;
    if exponent < 3 || exponent & 1 == 0 {
        return Err(RsaError::InvalidKey);
    }
    if exponent > MAXIMUM_EXPONENT {
        return Err(RsaError::ExponentTooLarge);
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
    match digest {
        Digest::Sha1(_) => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04,
            0x14,
        ],
        Digest::Sha224(_) => &[
            0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00, 0x04, 0x1C,
        ],
        Digest::Sha256(_) => &[
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        Digest::Sha384(_) => &[
            0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        Digest::Sha512(_) => &[
            0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        Digest::Sha3_256(_) => &[
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x08, 0x05, 0x00, 0x04, 0x20,
        ],
        Digest::Sha3_512(_) => &[
            0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x0A, 0x05, 0x00, 0x04, 0x40,
        ],
    }
}
