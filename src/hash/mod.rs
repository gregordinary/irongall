//! The hash functions OpenPGP fingerprints and signatures are computed with:
//! [`Sha1`] and the SHA-2 functions [`Sha224`], [`Sha256`], [`Sha384`] and
//! [`Sha512`], as FIPS 180-4 specifies them, and the SHA-3 functions
//! [`Sha3_256`] and [`Sha3_512`], as FIPS 202 specifies them.
//!
//! Each takes its input incrementally, in pieces of any size, so data is
//! hashed as it streams rather than held whole. The [`HashFunction`] trait
//! carries the methods:
//!
//! ```
//! use irongall::hash::{HashFunction as _, Sha256};
//!
//! let mut hash = Sha256::new();
//! hash.update(b"Open");
//! hash.update(b"PGP");
//! assert_eq!(hash.finalize(), Sha256::digest(b"OpenPGP"));
//! ```
//!
//! SHA-1 is not collision resistant (RFC 9580 §13.1). It is here because
//! version 4 fingerprints and key IDs are defined over it; use it only where a
//! format requires it.
//!
//! The implementations are portable code without processor-specific
//! acceleration, which would need `unsafe`. Their timing is not a design
//! goal: everything irongall hashes is public.
//!
//! [`Digest`] is a digest tagged with the function that computed it, the form
//! a verifier takes it in. [`HashAlgorithm`] is the number a signature names
//! its hash algorithm by, which may be one this module does not implement.

/// Defines a hash function that runs an engine from an initial state, and
/// outputs as much of the state the engine finishes in as its digest takes:
/// the public type, its `Default`, and its [`HashFunction`] implementation.
macro_rules! hash_function {
    (
        $(#[$doc:meta])*
        $name:ident($engine:ty) -> [u8; $length:literal],
        new: $new:expr,
        output: $output:path $(,)?
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone)]
        pub struct $name($engine);

        impl Default for $name {
            fn default() -> $name {
                <$name as $crate::hash::HashFunction>::new()
            }
        }

        impl $crate::hash::HashFunction for $name {
            type Output = [u8; $length];

            fn new() -> $name {
                $name($new)
            }

            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }

            fn finalize(self) -> [u8; $length] {
                let mut output = [0; $length];
                $output(&self.0.finish(), &mut output);
                output
            }
        }
    };
}

mod sha1;
mod sha256;
mod sha3;
mod sha512;

#[cfg(test)]
mod tests;

pub use sha1::Sha1;
pub use sha3::{Sha3_256, Sha3_512};
pub use sha256::{Sha224, Sha256};
pub use sha512::{Sha384, Sha512};

use crate::wire::wire_number;

wire_number! {
    /// A hash algorithm (RFC 9580 §9.5).
    ///
    /// Every octet is an algorithm a signature can name; the constants name
    /// the ones RFC 9580 assigns.
    pub struct HashAlgorithm;
    unnamed = "hash algorithm";
    /// MD5 (1).
    const MD5 = 1, "MD5";
    /// SHA-1 (2).
    const SHA1 = 2, "SHA-1";
    /// RIPEMD-160 (3).
    const RIPEMD160 = 3, "RIPEMD-160";
    /// SHA2-256 (8).
    const SHA256 = 8, "SHA2-256";
    /// SHA2-384 (9).
    const SHA384 = 9, "SHA2-384";
    /// SHA2-512 (10).
    const SHA512 = 10, "SHA2-512";
    /// SHA2-224 (11).
    const SHA224 = 11, "SHA2-224";
    /// SHA3-256 (12).
    const SHA3_256 = 12, "SHA3-256";
    /// SHA3-512 (14).
    const SHA3_512 = 14, "SHA3-512";
}

/// What RFC 9580 gives of a hash algorithm it assigns (§9.5, Tables 23 and
/// 24).
#[derive(Debug)]
struct Description {
    algorithm: HashAlgorithm,
    /// The length of its digest, in octets.
    digest_length: usize,
    /// The size of the salt a version 6 signature made with it carries, if
    /// RFC 9580 gives one; a version 6 signature cannot use another.
    v6_salt_size: Option<u8>,
    /// Its name in a `Hash` armor header.
    text_name: &'static str,
    /// The DER encoding of an RSA signature's DigestInfo for it, up to the
    /// digest, if irongall implements it.
    digest_info: Option<&'static [u8]>,
}

/// Each hash algorithm RFC 9580 assigns, as it describes it: the one place
/// a new algorithm's facts are written.
const DESCRIPTIONS: [Description; 9] = [
    Description {
        algorithm: HashAlgorithm::MD5,
        digest_length: 16,
        v6_salt_size: None,
        text_name: "MD5",
        digest_info: None,
    },
    Description {
        algorithm: HashAlgorithm::SHA1,
        digest_length: 20,
        v6_salt_size: None,
        text_name: "SHA1",
        digest_info: Some(&[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04,
            0x14,
        ]),
    },
    Description {
        algorithm: HashAlgorithm::RIPEMD160,
        digest_length: 20,
        v6_salt_size: None,
        text_name: "RIPEMD160",
        digest_info: None,
    },
    Description {
        algorithm: HashAlgorithm::SHA256,
        digest_length: 32,
        v6_salt_size: Some(16),
        text_name: "SHA256",
        digest_info: Some(&[
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]),
    },
    Description {
        algorithm: HashAlgorithm::SHA384,
        digest_length: 48,
        v6_salt_size: Some(24),
        text_name: "SHA384",
        digest_info: Some(&[
            0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ]),
    },
    Description {
        algorithm: HashAlgorithm::SHA512,
        digest_length: 64,
        v6_salt_size: Some(32),
        text_name: "SHA512",
        digest_info: Some(&[
            0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ]),
    },
    Description {
        algorithm: HashAlgorithm::SHA224,
        digest_length: 28,
        v6_salt_size: Some(16),
        text_name: "SHA224",
        digest_info: Some(&[
            0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00, 0x04, 0x1C,
        ]),
    },
    Description {
        algorithm: HashAlgorithm::SHA3_256,
        digest_length: 32,
        v6_salt_size: Some(16),
        text_name: "SHA3-256",
        digest_info: Some(&[
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x08, 0x05, 0x00, 0x04, 0x20,
        ]),
    },
    Description {
        algorithm: HashAlgorithm::SHA3_512,
        digest_length: 64,
        v6_salt_size: Some(32),
        text_name: "SHA3-512",
        digest_info: Some(&[
            0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x0A, 0x05, 0x00, 0x04, 0x40,
        ]),
    },
];

impl HashAlgorithm {
    /// What RFC 9580 gives of the algorithm, or `None` for one it does not
    /// assign.
    fn description(self) -> Option<&'static Description> {
        DESCRIPTIONS
            .iter()
            .find(|description| description.algorithm == self)
    }

    /// The length of the algorithm's digest in octets, or `None` for an
    /// algorithm RFC 9580 does not assign.
    pub(crate) fn digest_length(self) -> Option<usize> {
        self.description()
            .map(|description| description.digest_length)
    }

    /// The size of the salt a version 6 signature made with the algorithm
    /// carries (RFC 9580 §9.5), or `None` for an algorithm RFC 9580 gives no
    /// salt size, which a version 6 signature cannot use.
    pub(crate) fn v6_salt_size(self) -> Option<u8> {
        self.description()
            .and_then(|description| description.v6_salt_size)
    }

    /// The algorithm whose text name (RFC 9580 §9.5, Table 23) is `name`, as
    /// a `Hash` armor header lists it, or `None` for a name the table does
    /// not give. Names are matched exactly, case included.
    pub(crate) fn from_text_name(name: &str) -> Option<HashAlgorithm> {
        DESCRIPTIONS
            .iter()
            .find(|description| description.text_name == name)
            .map(|description| description.algorithm)
    }

    /// The DER encoding of an RSA signature's DigestInfo for the algorithm,
    /// up to the digest itself (RFC 9580 §12.1.3, Table 24), or `None` for
    /// one irongall does not implement.
    pub(crate) fn digest_info_prefix(self) -> Option<&'static [u8]> {
        self.description()
            .and_then(|description| description.digest_info)
    }
}

/// A digest, of one of the functions in this module, tagged with the function
/// that computed it.
///
/// A verifier takes its digest in this form, so a digest of the wrong length
/// for its algorithm, or of an algorithm irongall does not implement, cannot
/// reach it. [`rsa::PublicKey::verify`](crate::rsa::PublicKey::verify) is one:
///
/// ```
/// use irongall::hash::{Digest, HashFunction as _, Sha256};
///
/// let digest = Digest::Sha256(Sha256::digest(b"OpenPGP"));
/// assert_eq!(digest.as_bytes().len(), 32);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Digest {
    /// A SHA-1 digest.
    Sha1([u8; 20]),
    /// A SHA2-224 digest.
    Sha224([u8; 28]),
    /// A SHA2-256 digest.
    Sha256([u8; 32]),
    /// A SHA2-384 digest.
    Sha384([u8; 48]),
    /// A SHA2-512 digest.
    Sha512([u8; 64]),
    /// A SHA3-256 digest.
    Sha3_256([u8; 32]),
    /// A SHA3-512 digest.
    Sha3_512([u8; 64]),
}

impl Digest {
    /// The algorithm that computed the digest.
    pub(crate) fn algorithm(&self) -> HashAlgorithm {
        match self {
            Digest::Sha1(_) => HashAlgorithm::SHA1,
            Digest::Sha224(_) => HashAlgorithm::SHA224,
            Digest::Sha256(_) => HashAlgorithm::SHA256,
            Digest::Sha384(_) => HashAlgorithm::SHA384,
            Digest::Sha512(_) => HashAlgorithm::SHA512,
            Digest::Sha3_256(_) => HashAlgorithm::SHA3_256,
            Digest::Sha3_512(_) => HashAlgorithm::SHA3_512,
        }
    }

    /// The digest's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Digest::Sha1(bytes) => bytes,
            Digest::Sha224(bytes) => bytes,
            Digest::Sha256(bytes) => bytes,
            Digest::Sha384(bytes) => bytes,
            Digest::Sha512(bytes) => bytes,
            Digest::Sha3_256(bytes) => bytes,
            Digest::Sha3_512(bytes) => bytes,
        }
    }
}

/// A hash computation in progress, under an algorithm a signature chose: the
/// hash context RFC 9580 §5.2.4 feeds a signature's data into.
#[derive(Debug, Clone)]
pub(crate) enum Context {
    /// SHA-1.
    Sha1(Sha1),
    /// SHA2-224.
    Sha224(Sha224),
    /// SHA2-256.
    Sha256(Sha256),
    /// SHA2-384.
    Sha384(Sha384),
    /// SHA2-512.
    Sha512(Sha512),
    /// SHA3-256.
    Sha3_256(Sha3_256),
    /// SHA3-512.
    Sha3_512(Sha3_512),
}

impl Context {
    /// A context for `algorithm`, or `None` for an algorithm this module does
    /// not implement.
    pub(crate) fn new(algorithm: HashAlgorithm) -> Option<Context> {
        Some(match algorithm {
            HashAlgorithm::SHA1 => Context::Sha1(Sha1::new()),
            HashAlgorithm::SHA224 => Context::Sha224(Sha224::new()),
            HashAlgorithm::SHA256 => Context::Sha256(Sha256::new()),
            HashAlgorithm::SHA384 => Context::Sha384(Sha384::new()),
            HashAlgorithm::SHA512 => Context::Sha512(Sha512::new()),
            HashAlgorithm::SHA3_256 => Context::Sha3_256(Sha3_256::new()),
            HashAlgorithm::SHA3_512 => Context::Sha3_512(Sha3_512::new()),
            _ => return None,
        })
    }

    /// Appends `data` to the input.
    pub(crate) fn update(&mut self, data: &[u8]) {
        #[cfg(test)]
        crate::test_support::work::hashed(data.len());
        match self {
            Context::Sha1(hash) => hash.update(data),
            Context::Sha224(hash) => hash.update(data),
            Context::Sha256(hash) => hash.update(data),
            Context::Sha384(hash) => hash.update(data),
            Context::Sha512(hash) => hash.update(data),
            Context::Sha3_256(hash) => hash.update(data),
            Context::Sha3_512(hash) => hash.update(data),
        }
    }

    /// The digest of everything [`update`](Self::update) was given.
    pub(crate) fn finalize(self) -> Digest {
        match self {
            Context::Sha1(hash) => Digest::Sha1(hash.finalize()),
            Context::Sha224(hash) => Digest::Sha224(hash.finalize()),
            Context::Sha256(hash) => Digest::Sha256(hash.finalize()),
            Context::Sha384(hash) => Digest::Sha384(hash.finalize()),
            Context::Sha512(hash) => Digest::Sha512(hash.finalize()),
            Context::Sha3_256(hash) => Digest::Sha3_256(hash.finalize()),
            Context::Sha3_512(hash) => Digest::Sha3_512(hash.finalize()),
        }
    }
}

/// A hash function, computed incrementally.
///
/// The trait is sealed: the seven functions in this module are its only
/// implementations.
pub trait HashFunction: Clone + sealed::Sealed {
    /// The digest: a byte array of the function's output length, such as
    /// `[u8; 32]` for SHA2-256.
    type Output: AsRef<[u8]> + Copy;

    /// The function's state before any input.
    fn new() -> Self;

    /// Appends `data` to the input.
    fn update(&mut self, data: &[u8]);

    /// The digest of everything [`update`](Self::update) was given.
    fn finalize(self) -> Self::Output;

    /// The digest of `data`.
    fn digest(data: &[u8]) -> Self::Output {
        let mut hash = Self::new();
        hash.update(data);
        hash.finalize()
    }
}

mod sealed {
    /// The bound that keeps [`HashFunction`](super::HashFunction) to this
    /// module's implementations, so the trait can gain methods later without
    /// breaking an implementation outside the crate. It is public so that a
    /// public trait can name it, and unnameable because its module is private.
    pub trait Sealed {}

    impl Sealed for super::Sha1 {}
    impl Sealed for super::Sha224 {}
    impl Sealed for super::Sha256 {}
    impl Sealed for super::Sha384 {}
    impl Sealed for super::Sha512 {}
    impl Sealed for super::Sha3_256 {}
    impl Sealed for super::Sha3_512 {}
}

/// The input a hash function holds between updates: the part of a block not
/// yet compressed.
///
/// The SHA-1 and SHA-2 functions share this framing and the padding that ends
/// it, and differ in their block size, the width of the length that closes the
/// padding, and the compression function each block is passed to. The SHA-3
/// functions share the framing, with the sponge's rate as the block size, and
/// pad otherwise.
#[derive(Debug, Clone)]
struct BlockBuffer<const N: usize> {
    block: [u8; N],
    /// How many leading bytes of `block` hold input. Always less than `N`.
    filled: usize,
    /// How many bytes it has taken in all, modulo 2^64, which the SHA-1 and
    /// SHA-2 padding ends with. No input reaches 2^64 bytes.
    length: u64,
}

impl<const N: usize> BlockBuffer<N> {
    const fn new() -> BlockBuffer<N> {
        BlockBuffer {
            block: [0; N],
            filled: 0,
            length: 0,
        }
    }

    /// Takes `data`, passing each block it completes to `compress`.
    fn update(&mut self, data: &[u8], mut compress: impl FnMut(&[u8; N])) {
        // A `usize` is at most 64 bits wide on every target.
        let taken = u64::try_from(data.len()).unwrap_or(u64::MAX);
        self.length = self.length.wrapping_add(taken);
        let mut data = data;
        if self.filled != 0 {
            // The held block's free space is never empty, since `filled < N`.
            let free = self.block.get_mut(self.filled..).unwrap_or_default();
            let (head, rest) = data.split_at_checked(free.len()).unwrap_or((data, &[]));
            for (slot, byte) in free.iter_mut().zip(head) {
                *slot = *byte;
            }
            self.filled = self.filled.saturating_add(head.len());
            if self.filled < N {
                return;
            }
            compress(&self.block);
            data = rest;
        }
        let (blocks, tail) = data.as_chunks::<N>();
        for block in blocks {
            compress(block);
        }
        for (slot, byte) in self.block.iter_mut().zip(tail) {
            *slot = *byte;
        }
        self.filled = tail.len();
    }

    /// Pads the held input and passes the final block, or two, to `compress`.
    ///
    /// The padding is a single one bit, zero bits up to the last `L` bytes of
    /// a block, and then the message's length in bits, big-endian, in those
    /// `L` bytes: 8 for SHA-1 and SHA2-256, and 16 for SHA2-512 (FIPS 180-4
    /// §5.1).
    fn finish<const L: usize>(mut self, mut compress: impl FnMut(&[u8; N])) {
        let bits = u128::from(self.length).wrapping_mul(8).to_be_bytes();
        let length = bits.get(bits.len().saturating_sub(L)..).unwrap_or(&bits);
        let mut tail = self.block.iter_mut().skip(self.filled);
        if let Some(first) = tail.next() {
            *first = 0x80;
        }
        tail.for_each(|byte| *byte = 0);
        // The one bit took a byte, so the length fits after it only when
        // fewer than `N - length.len()` bytes were held.
        if self.filled >= N.saturating_sub(length.len()) {
            compress(&self.block);
            self.block = [0; N];
        }
        for (slot, byte) in self.block.iter_mut().rev().zip(length.iter().rev()) {
            *slot = *byte;
        }
        compress(&self.block);
    }

    /// Pads the held input as SHA-3 pads it, and passes the final block to
    /// `absorb`: the bits `01` that mark a SHA-3 digest, then the padding
    /// pad10*1, a one bit, zero bits, and a one bit that ends the block
    /// (FIPS 202 §6.1 and §5.1).
    ///
    /// Bits fill each byte from its lowest (FIPS 202 Appendix B.1), so the
    /// marking and the padding's first bit are the byte `0x06`, and its last
    /// bit is the top bit of the block's last byte, which may be the same
    /// byte.
    fn finish_sha3(mut self, absorb: impl FnOnce(&[u8; N])) {
        let mut tail = self.block.iter_mut().skip(self.filled);
        if let Some(first) = tail.next() {
            *first = 0x06;
        }
        tail.for_each(|byte| *byte = 0);
        if let Some(last) = self.block.last_mut() {
            *last |= 0x80;
        }
        absorb(&self.block);
    }
}

/// The big-endian bytes of `words`, as many as `output` holds.
///
/// A truncated function, such as SHA2-224, outputs a prefix of its final
/// state, which is an output shorter than the state.
fn write_words<const N: usize>(words: &[u32], output: &mut [u8; N]) {
    for (bytes, word) in output.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *bytes = word.to_be_bytes();
    }
}

/// [`write_words`], for 64-bit words.
fn write_wide_words<const N: usize>(words: &[u64], output: &mut [u8; N]) {
    for (bytes, word) in output.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        *bytes = word.to_be_bytes();
    }
}

/// The SHA-1 and SHA-2 choice function: each bit of `x` selects the bit of
/// `y` or of `z`.
fn ch<T>(x: T, y: T, z: T) -> T
where
    T: Copy
        + core::ops::BitAnd<Output = T>
        + core::ops::BitXor<Output = T>
        + core::ops::Not<Output = T>,
{
    (x & y) ^ (!x & z)
}

/// The SHA-1 and SHA-2 majority function: each bit is the majority of the
/// three inputs' bits.
fn maj<T>(x: T, y: T, z: T) -> T
where
    T: Copy + core::ops::BitAnd<Output = T> + core::ops::BitXor<Output = T>,
{
    (x & y) ^ (x & z) ^ (y & z)
}
