//! Keys and signatures rPGP does not make, for the divergences that only
//! such input shows: an RSA key narrower than 2048 bits, an Ed25519 key of
//! small order, and an Ed25519 signature whose R is of small order.
//!
//! rPGP builds and hashes each signature; a [`Forger`] stands in for the
//! secret key, and computes the signature's material from the digest rPGP
//! hands it.

use std::fmt;

use num_bigint::BigUint;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::types::{
    Fingerprint, KeyDetails, KeyId, KeyVersion, Mpi, Password, PublicParams, SignatureBytes,
    SigningKey, Timestamp,
};
use sha2::{Digest as _, Sha512};

/// A packet with a new-format header.
pub(crate) fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    // A one-octet length below 192, a two-octet one up to 8383 (RFC 9580
    // §4.2.1.2).
    let length = match u16::try_from(body.len()) {
        Ok(length @ 0..192) => vec![length as u8],
        Ok(length @ 192..8384) => {
            let length = length - 192;
            vec![(length >> 8) as u8 + 192, length as u8]
        }
        _ => panic!("a body of {} octets", body.len()),
    };
    [&[0xC0 | tag][..], &length, body].concat()
}

/// An integer as an MPI (RFC 9580 §3.2): its bit count, then its octets.
fn mpi(value: &[u8]) -> Vec<u8> {
    let bits = value.len() * 8 - value[0].leading_zeros() as usize;
    [&u16::try_from(bits).unwrap().to_be_bytes()[..], value].concat()
}

/// A version 4 RSA key of `bits` bits from `seed`, as a Public Key packet,
/// and a function making PKCS #1 v1.5 signatures over SHA2-256 digests with
/// it.
pub(crate) fn rsa(
    bits: usize,
    seed: u64,
    created: u32,
) -> (Vec<u8>, impl Fn(&[u8]) -> SignatureBytes) {
    use rsa::traits::PublicKeyParts as _;
    let secret = rsa::RsaPrivateKey::new(&mut crate::make::rng(seed), bits).unwrap();
    let body = [
        &[4][..],
        &created.to_be_bytes(),
        &[1],
        &mpi(&secret.n().to_bytes_be()),
        &mpi(&secret.e().to_bytes_be()),
    ]
    .concat();
    // The DER prefix of a SHA2-256 DigestInfo (RFC 9580 §5.2.2, Table 24).
    let prefix = [
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let sign = move |digest: &[u8]| {
        let signature = secret
            .sign(
                rsa::Pkcs1v15Sign::new_unprefixed(),
                &[&prefix[..], digest].concat(),
            )
            .unwrap();
        SignatureBytes::Mpis(vec![Mpi::from_slice(&signature)])
    };
    (packet(6, &body), sign)
}

/// The packet of an Ed25519 public key with the point encoded as `point`: an
/// EdDSALegacy key over Ed25519Legacy in version 4, an Ed25519 key in
/// version 6.
pub(crate) fn ed25519_key(version: KeyVersion, point: &[u8; 32], created: u32) -> Vec<u8> {
    let created = created.to_be_bytes();
    let body = match version {
        KeyVersion::V4 => {
            let oid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
            // A 263-bit MPI: the prefix 0x40, then the native point.
            [
                &[4][..],
                &created,
                &[22, 9],
                &oid,
                &[0x01, 0x07, 0x40],
                point,
            ]
            .concat()
        }
        KeyVersion::V6 => [&[6][..], &created, &[27, 0, 0, 0, 32], point].concat(),
        other => panic!("{other:?}"),
    };
    packet(6, &body)
}

/// The encoding of the identity point, of order 1.
pub(crate) const IDENTITY: [u8; 32] = {
    let mut identity = [0; 32];
    identity[0] = 1;
    identity
};

/// The encoding of the base point B.
const BASE: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// An Ed25519 signature's material: R and S as integers in version 4
/// (EdDSALegacy), natively in version 6.
pub(crate) fn ed25519_signature(version: KeyVersion, signature: [u8; 64]) -> SignatureBytes {
    match version {
        KeyVersion::V4 => SignatureBytes::Mpis(vec![
            Mpi::from_slice(&signature[..32]),
            Mpi::from_slice(&signature[32..]),
        ]),
        _ => SignatureBytes::Native(signature.to_vec().into()),
    }
}

/// R = B and S = 1, which satisfies the verification equation for every
/// digest under the identity key: [1]B = B + [k]O.
pub(crate) fn universal(_digest: &[u8]) -> [u8; 64] {
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&BASE);
    signature[32] = 1;
    signature
}

/// The order of the base point, L = 2^252 + 27742317777372353535851937790883648493.
fn order() -> BigUint {
    (BigUint::from(1u8) << 252u32)
        + "27742317777372353535851937790883648493"
            .parse::<BigUint>()
            .unwrap()
}

/// A little-endian integer.
fn little_endian(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

/// The 32-octet little-endian encoding of a scalar below L.
fn scalar_bytes(scalar: &BigUint) -> [u8; 32] {
    let mut bytes = scalar.to_bytes_le();
    bytes.resize(32, 0);
    bytes.try_into().unwrap()
}

/// The key of the secret `seed`, and a function making signatures under it
/// whose R is the identity, of order 1: S = k·a mod L, so that
/// [S]B = O + [k]A holds for the digest it is given.
pub(crate) fn small_order_r(seed: [u8; 32]) -> ([u8; 32], impl Fn(&[u8]) -> [u8; 64]) {
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let point = signing.verifying_key().to_bytes();
    // The secret scalar, clamped as RFC 8032 §5.1.5 says: A = [a]B.
    let mut clamped: [u8; 32] = Sha512::digest(seed)[..32].try_into().unwrap();
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let secret = little_endian(&clamped);
    let sign = move |digest: &[u8]| {
        let k = little_endian(&Sha512::digest([&IDENTITY[..], &point, digest].concat())) % order();
        let s = (k * &secret) % order();
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&IDENTITY);
        signature[32..].copy_from_slice(&scalar_bytes(&s));
        signature
    };
    (point, sign)
}

/// A signer under `key` whose signature over a digest is whatever `sign`
/// computes from it.
pub(crate) struct Forger<F> {
    pub(crate) key: pgp::packet::PublicKey,
    pub(crate) sign: F,
}

impl<F> fmt::Debug for Forger<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Forger").field("key", &self.key).finish()
    }
}

impl<F> KeyDetails for Forger<F> {
    fn version(&self) -> KeyVersion {
        self.key.version()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.key.legacy_key_id()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.key.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.key.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.key.public_params()
    }
}

impl<F: Fn(&[u8]) -> SignatureBytes> SigningKey for Forger<F> {
    fn sign(
        &self,
        _: &Password,
        _: HashAlgorithm,
        digest: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        Ok((self.sign)(digest))
    }

    fn hash_alg(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }
}
