//! Certificates and signatures made with rPGP, from seeded randomness, so
//! that every run makes the same keys.

use pgp::composed::{
    CleartextSignedMessage, DetachedSignature, EncryptionCaps, KeyType, SecretKeyParamsBuilder,
    SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::ser::Serialize as _;
use pgp::types::{KeyVersion, Password, SigningKey, Timestamp};
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng as _;

/// A random number generator seeded with `seed`.
pub(crate) fn rng(seed: u64) -> ChaCha8Rng {
    ChaCha8Rng::seed_from_u64(seed)
}

/// When every key is made: 2026-01-01 00:00:00 UTC.
///
/// The self-signatures are made at the time of the run, as rPGP stamps them
/// with its clock; the keys are older, as a key always is.
pub(crate) const CREATED: u32 = 1_767_225_600;

/// A shape of certificate: a primary key, a signing subkey, and an
/// encryption subkey.
#[derive(Debug, Clone)]
pub(crate) struct Shape {
    pub(crate) name: &'static str,
    pub(crate) version: KeyVersion,
    pub(crate) primary: KeyType,
    pub(crate) signing: KeyType,
    pub(crate) encryption: KeyType,
}

/// Makes a certificate of `shape` from `seed`, with two user IDs.
///
/// The primary key certifies and signs; the signing subkey signs, with a
/// back-signature; the encryption subkey only encrypts.
pub(crate) fn certificate(shape: &Shape, seed: u64) -> SignedSecretKey {
    let signing = SubkeyParamsBuilder::default()
        .version(shape.version)
        .key_type(shape.signing.clone())
        .created_at(Timestamp::from_secs(CREATED))
        .can_sign(true)
        .build()
        .expect("signing subkey parameters");
    let encryption = SubkeyParamsBuilder::default()
        .version(shape.version)
        .key_type(shape.encryption.clone())
        .created_at(Timestamp::from_secs(CREATED))
        .can_encrypt(EncryptionCaps::All)
        .build()
        .expect("encryption subkey parameters");
    SecretKeyParamsBuilder::default()
        .version(shape.version)
        .key_type(shape.primary.clone())
        .created_at(Timestamp::from_secs(CREATED))
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(format!("{} <primary@example.org>", shape.name))
        .user_ids(vec![format!("{} <second@example.org>", shape.name)])
        .subkey(signing)
        .subkey(encryption)
        .build()
        .expect("key parameters")
        .generate(rng(seed))
        .expect("key generation")
}

/// The transferable public key of `secret`, as binary packets.
pub(crate) fn public(secret: &SignedSecretKey) -> Vec<u8> {
    secret
        .to_public_key()
        .to_bytes()
        .expect("serializing a certificate")
}

/// A binary (`text` false) or text detached signature over `document` by
/// `signer`, as a Signature packet; `None` where rPGP refuses to make it.
pub(crate) fn detached(
    signer: &dyn SigningKey,
    hash: HashAlgorithm,
    text: bool,
    document: &[u8],
    seed: u64,
) -> Option<Vec<u8>> {
    // rPGP signs through a sized signer; it offers one over a trait object.
    let signer = Box::new(signer);
    let password = Password::empty();
    let signature = if text {
        DetachedSignature::sign_text_data(rng(seed), &signer, &password, hash, document)
    } else {
        DetachedSignature::sign_binary_data(rng(seed), &signer, &password, hash, document)
    };
    Some(signature.ok()?.to_bytes().expect("serializing a signature"))
}

/// A cleartext signed message over `text` by `signer`, armored.
pub(crate) fn cleartext(signer: &dyn SigningKey, text: &str, seed: u64) -> Vec<u8> {
    CleartextSignedMessage::sign(rng(seed), text, &Box::new(signer), &Password::empty())
        .expect("signing a cleartext message")
        .to_armored_bytes(Default::default())
        .expect("armoring a cleartext message")
}
