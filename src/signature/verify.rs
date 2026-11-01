//! Verifying a signature with a key: the data the signature's hash covers, for
//! each type of signature (RFC 9580 §5.2.4), and the check of that hash
//! against the signature's material.

use core::fmt;

use super::{Signature, SignatureMaterial, SignatureType};
use crate::ed25519::{self, Ed25519Error};
use crate::hash::{Context, Digest};
use crate::key::{self, KeyMaterial, PublicKey, PublicKeyAlgorithm};
use crate::packet::Version;
use crate::rsa::{self, RsaError};

#[cfg(test)]
mod tests;

/// What a signature is a statement about: the data its hash covers, besides
/// the signature's own fields.
///
/// A signature's [type](SignatureType) decides which kind of subject it is
/// made over, and [`Signature::verify`] refuses a subject of another kind.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Subject<'a> {
    /// A document: for a binary signature (0x00), hashed as it is, and for a
    /// text signature (0x01), hashed with its line endings made CR LF.
    ///
    /// A line ends at an LF, with or without a CR before it, and any other
    /// CR is part of the text. A text signature also verifies over the
    /// document as GnuPG reads it, without the CRs that come before a line's
    /// CR LF or end the document.
    Document(&'a [u8]),
    /// A key alone: for a direct-key signature (0x1F), a key revocation
    /// (0x20), and a certification revocation (0x30) that revokes a
    /// direct-key signature.
    Key(&'a PublicKey),
    /// A key and one of its user IDs: for a certification (0x10 to 0x13),
    /// and a certification revocation (0x30) that revokes one.
    UserId {
        /// The key the user ID belongs to.
        key: &'a PublicKey,
        /// The user ID: the body of its User ID packet.
        user_id: &'a [u8],
    },
    /// A primary key and one of its subkeys: for a subkey binding (0x18), a
    /// primary key binding (0x19), and a subkey revocation (0x28).
    Subkey {
        /// The primary key.
        primary: &'a PublicKey,
        /// The subkey.
        subkey: &'a PublicKey,
    },
}

/// The kind of a [`Subject`], which a signature's type decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Document,
    Key,
    UserId,
    Subkey,
}

impl Subject<'_> {
    fn kind(&self) -> Kind {
        match self {
            Subject::Document(_) => Kind::Document,
            Subject::Key(_) => Kind::Key,
            Subject::UserId { .. } => Kind::UserId,
            Subject::Subkey { .. } => Kind::Subkey,
        }
    }
}

/// The kinds of subject a signature of `signature_type` is made over, or
/// `None` for a type irongall verifies over none.
///
/// A certification revocation is made over the same data as the signature it
/// revokes (RFC 9580 §5.2.1.13): a certification, or a direct-key signature.
fn kinds(signature_type: SignatureType) -> Option<&'static [Kind]> {
    Some(match signature_type {
        SignatureType::BINARY | SignatureType::TEXT => &[Kind::Document],
        SignatureType::GENERIC_CERTIFICATION
        | SignatureType::PERSONA_CERTIFICATION
        | SignatureType::CASUAL_CERTIFICATION
        | SignatureType::POSITIVE_CERTIFICATION => &[Kind::UserId],
        SignatureType::SUBKEY_BINDING
        | SignatureType::PRIMARY_KEY_BINDING
        | SignatureType::SUBKEY_REVOCATION => &[Kind::Subkey],
        SignatureType::DIRECT_KEY | SignatureType::KEY_REVOCATION => &[Kind::Key],
        SignatureType::CERTIFICATION_REVOCATION => &[Kind::UserId, Kind::Key],
        _ => return None,
    })
}

/// Why a signature does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VerifyError {
    /// The signature is of a type irongall verifies over no subject: a
    /// standalone, timestamp, or third-party confirmation signature, or a type
    /// RFC 9580 does not assign.
    UnsupportedType,
    /// The signature is of a type made over another kind of subject, such as
    /// a certification checked against a subkey.
    WrongSubject,
    /// The signature's version is not the key's: a version 4 key makes
    /// version 4 signatures, and a version 6 key version 6 ones (RFC 9580
    /// §5.2.3, Table 27).
    VersionMismatch,
    /// The signature names a public-key algorithm other than the key's.
    AlgorithmMismatch,
    /// The key is of an algorithm irongall does not verify with, of a curve it
    /// does not know, or of one that cannot sign: RSA's encrypt-only variant.
    UnsupportedAlgorithm,
    /// The signature's hash algorithm is one irongall does not implement.
    UnsupportedHash,
    /// The signature's hash is shorter than its algorithm allows: an Ed25519
    /// signature needs at least 256 bits (RFC 9580 §5.2.3.3 and §5.2.3.4).
    HashTooShort,
    /// The key's RSA modulus is narrower than 2048 bits, which RFC 9580 §12.4
    /// forbids verifying with.
    ModulusTooShort,
    /// The key's RSA modulus is wider than 8192 bits, the widest irongall
    /// verifies with.
    ModulusTooLong,
    /// The key's RSA public exponent is larger than 2^33 - 1, the largest
    /// irongall verifies with.
    ExponentTooLarge,
    /// The key's material is not a valid key: an even RSA modulus, an RSA
    /// exponent that is even or below 3, or an Ed25519 point that is encoded
    /// non-canonically or of small order.
    InvalidKey,
    /// The first two octets of the hash are not the ones the signature
    /// carries: the signature was made over other data.
    HashPrefixMismatch,
    /// The signature is not one the key made over the subject.
    BadSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VerifyError::UnsupportedType => "a type of signature irongall does not verify",
            VerifyError::WrongSubject => "a type of signature not made over a subject of this kind",
            VerifyError::VersionMismatch => "a signature of a version other than its key's",
            VerifyError::AlgorithmMismatch => {
                "a signature naming a public-key algorithm other than its key's"
            }
            VerifyError::UnsupportedAlgorithm => "a key irongall does not verify with",
            VerifyError::UnsupportedHash => "a hash algorithm irongall does not implement",
            VerifyError::HashTooShort => "a hash shorter than the signature's algorithm allows",
            VerifyError::ModulusTooShort => "an RSA modulus narrower than 2048 bits",
            VerifyError::ModulusTooLong => "an RSA modulus wider than 8192 bits",
            VerifyError::ExponentTooLarge => "an RSA public exponent larger than 2^33 - 1",
            VerifyError::InvalidKey => "key material that is not a valid key",
            VerifyError::HashPrefixMismatch => "a signature made over other data",
            VerifyError::BadSignature => "a signature the key did not make over the subject",
        })
    }
}

impl core::error::Error for VerifyError {}

impl VerifyError {
    /// Whether the error is the key's alone: irongall verifies no signature
    /// with the key, whatever its material.
    pub(crate) fn is_key_error(self) -> bool {
        match self {
            VerifyError::UnsupportedAlgorithm
            | VerifyError::ModulusTooShort
            | VerifyError::ModulusTooLong
            | VerifyError::ExponentTooLarge
            | VerifyError::InvalidKey => true,
            VerifyError::UnsupportedType
            | VerifyError::WrongSubject
            | VerifyError::VersionMismatch
            | VerifyError::AlgorithmMismatch
            | VerifyError::UnsupportedHash
            | VerifyError::HashTooShort
            | VerifyError::HashPrefixMismatch
            | VerifyError::BadSignature => false,
        }
    }
}

/// The [`VerifyError`] an RSA key's refusal, or its signature's, is reported
/// as. A function rather than a `From` implementation, which would put the
/// conversion in the public API beside the public [`RsaError`].
fn rsa_failure(error: RsaError) -> VerifyError {
    match error {
        RsaError::ModulusTooShort => VerifyError::ModulusTooShort,
        RsaError::ModulusTooLong => VerifyError::ModulusTooLong,
        RsaError::ExponentTooLarge => VerifyError::ExponentTooLarge,
        RsaError::InvalidKey => VerifyError::InvalidKey,
        RsaError::BadSignature => VerifyError::BadSignature,
    }
}

impl From<Ed25519Error> for VerifyError {
    fn from(error: Ed25519Error) -> VerifyError {
        match error {
            Ed25519Error::InvalidKey => VerifyError::InvalidKey,
            Ed25519Error::BadSignature => VerifyError::BadSignature,
        }
    }
}

/// The shortest hash an Ed25519 signature may be made over, in octets: 256
/// bits for Ed25519 (RFC 9580 §5.2.3.4), and the curve's field size, 32
/// octets, for EdDSALegacy over Ed25519Legacy (§5.2.3.3, Table 19).
const ED25519_MINIMUM_HASH_LENGTH: usize = 32;

impl Signature {
    /// Verifies that the signature is `key`'s over `subject`.
    ///
    /// This checks that the signature's type is made over a subject of this
    /// kind, that its version and public-key algorithm are the key's, that
    /// its hash is one its public-key algorithm may rest on, and that the key
    /// made it over the subject. It judges nothing else: not the signature's
    /// times or the key's, not whether the key was entitled to make it, and
    /// not whether its hash algorithm is still trustworthy. A valid RSA
    /// signature over SHA-1 verifies; an Ed25519 signature over a hash
    /// shorter than 256 bits does not, as RFC 9580 §5.2.3.3 and §5.2.3.4
    /// require.
    ///
    /// # Errors
    ///
    /// When the signature does not verify; the error says why.
    pub fn verify(&self, key: &PublicKey, subject: Subject<'_>) -> Result<(), VerifyError> {
        self.check_subject(subject.kind())?;
        let check = self.check_key(key)?;
        let digests = self.digests(subject)?;
        self.check_hash_length()?;
        self.check_digests(check, &digests)
    }

    /// Checks that `key` made the signature over `subject`, as
    /// [`verify`](Self::verify) does, but without the floor RFC 9580 sets on
    /// the length of an Ed25519 signature's hash.
    ///
    /// The equation still establishes which key made the signature, and the
    /// policy attributes a certificate's statements by it: one made over a
    /// hash too short for its algorithm still restricts what the certificate
    /// grants, and grants nothing, which the policy decides apart through
    /// [`hash_too_short`](Self::hash_too_short).
    pub(crate) fn made_by(&self, key: &PublicKey, subject: Subject<'_>) -> Result<(), VerifyError> {
        self.check_subject(subject.kind())?;
        let check = self.check_key(key)?;
        self.check_digests(check, &self.digests(subject)?)
    }

    /// Whether the signature's hash is shorter than its public-key algorithm
    /// allows: an Ed25519 signature must rest on a hash of 256 bits or more
    /// (RFC 9580 §5.2.3.3 and §5.2.3.4), so one over SHA-1 or SHA2-224 never
    /// verifies, whichever key made it.
    pub(crate) fn hash_too_short(&self) -> bool {
        matches!(
            self.public_key_algorithm,
            PublicKeyAlgorithm::ED25519 | PublicKeyAlgorithm::EDDSA_LEGACY
        ) && self
            .hash_algorithm
            .digest_length()
            .is_some_and(|length| length < ED25519_MINIMUM_HASH_LENGTH)
    }

    /// Checks that the signature's hash is one its public-key algorithm may
    /// rest on: see [`hash_too_short`](Self::hash_too_short).
    fn check_hash_length(&self) -> Result<(), VerifyError> {
        if self.hash_too_short() {
            Err(VerifyError::HashTooShort)
        } else {
            Ok(())
        }
    }

    /// Begins hashing a document for the signature, in pieces, so that a
    /// signature over a document too large to hold whole can be verified:
    /// [`DocumentHash::verify`] then does what [`verify`](Self::verify) does
    /// over [`Subject::Document`].
    ///
    /// # Errors
    ///
    /// When the signature is not over a document: [`VerifyError::WrongSubject`]
    /// or [`VerifyError::UnsupportedType`]. When its hash algorithm is one
    /// irongall does not implement: [`VerifyError::UnsupportedHash`].
    pub fn document_hash(&self) -> Result<DocumentHash<'_>, VerifyError> {
        self.check_subject(Kind::Document)?;
        Ok(DocumentHash {
            signature: self,
            context: self.context()?,
            line_endings: self.line_endings(),
        })
    }

    /// Checks that the signature's type is made over a subject of `kind`.
    fn check_subject(&self, kind: Kind) -> Result<(), VerifyError> {
        if kinds(self.signature_type)
            .ok_or(VerifyError::UnsupportedType)?
            .contains(&kind)
        {
            Ok(())
        } else {
            Err(VerifyError::WrongSubject)
        }
    }

    /// Checks that `key` can have made the signature: of the signature's
    /// version and public-key algorithm, and of an algorithm irongall
    /// verifies with.
    fn check_key<'k>(&'k self, key: &'k PublicKey) -> Result<Check<'k>, VerifyError> {
        if self.version != key.version() {
            return Err(VerifyError::VersionMismatch);
        }
        if self.public_key_algorithm != key.algorithm() {
            return Err(VerifyError::AlgorithmMismatch);
        }
        Check::of(key, &self.material)
    }

    /// Checks each hash the signature may be made over, as
    /// [`check_digest`](Self::check_digest) does: the signature verifies if
    /// it verifies over any of them.
    ///
    /// When none verifies, the error is the last a hash whose prefix matches
    /// met, or, if no prefix matches, [`VerifyError::HashPrefixMismatch`].
    fn check_digests(&self, check: Check<'_>, digests: &Digests) -> Result<(), VerifyError> {
        let mut error = VerifyError::HashPrefixMismatch;
        for digest in digests.iter() {
            match self.check_digest(check, digest) {
                Ok(()) => return Ok(()),
                Err(VerifyError::HashPrefixMismatch) => {}
                Err(other) => error = other,
            }
        }
        Err(error)
    }

    /// Checks the hash the signature is made over against the two octets of
    /// it the signature carries, and then against the signature itself.
    fn check_digest(&self, check: Check<'_>, digest: &Digest) -> Result<(), VerifyError> {
        if digest.as_bytes().get(..2) != Some(&self.hash_prefix[..]) {
            return Err(VerifyError::HashPrefixMismatch);
        }
        match check {
            Check::Rsa {
                modulus,
                exponent,
                value,
            } => rsa::PublicKey::new(modulus, exponent)
                .and_then(|key| key.verify(digest, value))
                .map_err(rsa_failure)?,
            Check::Ed25519 { key, value } => ed25519::verify(key, digest, value)?,
        }
        Ok(())
    }

    /// The hashes the signature may be made over, if it is over `subject`
    /// (RFC 9580 §5.2.4): a version 6 signature's salt, the subject's data,
    /// and the trailer, under the signature's hash algorithm. There are two
    /// only for a text document that GnuPG reads otherwise.
    ///
    /// The caller has checked that the signature's type is made over a
    /// subject of this kind.
    fn digests(&self, subject: Subject<'_>) -> Result<Digests, VerifyError> {
        let mut context = self.context()?;
        let mut line_endings = None;
        match subject {
            Subject::Document(document) => {
                line_endings = self.line_endings();
                hash_document(&mut context, line_endings.as_mut(), document);
            }
            Subject::Key(key) => self.hash_key(&mut context, key)?,
            Subject::UserId { key, user_id } => {
                self.hash_key(&mut context, key)?;
                // Packet lengths are four octets, so a user ID read from one
                // always fits.
                let length = u32::try_from(user_id.len()).map_err(|_| VerifyError::BadSignature)?;
                context.update(&[0xB4]);
                context.update(&length.to_be_bytes());
                context.update(user_id);
            }
            Subject::Subkey { primary, subkey } => {
                self.hash_key(&mut context, primary)?;
                self.hash_key(&mut context, subkey)?;
            }
        }
        Ok(self.finish(&context, line_endings.as_ref()))
    }

    /// A hash context under the signature's hash algorithm, holding what
    /// comes before the subject's data: a version 6 signature's salt.
    fn context(&self) -> Result<Context, VerifyError> {
        let mut context = Context::new(self.hash_algorithm).ok_or(VerifyError::UnsupportedHash)?;
        context.update(&self.salt);
        Ok(context)
    }

    /// The hashes of `context`, which holds the subject's data, once the
    /// trailer follows it: for a text document, `line_endings` holds what
    /// the document's end decides, and whether GnuPG's reading differs.
    fn finish(&self, context: &Context, line_endings: Option<&LineEndings>) -> Digests {
        let (context, gnupg) = match line_endings {
            Some(line_endings) => line_endings.finish(context),
            None => (context.clone(), None),
        };
        Digests {
            digest: self.trailed(context),
            gnupg: gnupg.map(|context| self.trailed(context)),
        }
    }

    /// The hash of `context` once the trailer follows it.
    fn trailed(&self, mut context: Context) -> Digest {
        self.hash_trailer(&mut context);
        context.finalize()
    }

    /// The line-ending conversion a document passes through on its way to
    /// the hash: for a text signature, the conversion to CR LF, and for any
    /// other, none.
    fn line_endings(&self) -> Option<LineEndings> {
        (self.signature_type == SignatureType::TEXT).then(LineEndings::default)
    }

    /// Hashes a key framed as the signature's version frames it (RFC 9580
    /// §5.2.4).
    ///
    /// The framing follows the signature's version rather than the key's, as
    /// the RFC states it and as Sequoia implements it; rPGP follows the
    /// key's. The two agree whenever the versions do, which they must for
    /// every self-signature, and differ only for a signature by a key of one
    /// version over a key of the other.
    ///
    /// A version 4 signature states a key's length in two octets, so it
    /// covers no key whose body is longer, and the signature cannot verify.
    fn hash_key(&self, context: &mut Context, key: &PublicKey) -> Result<(), VerifyError> {
        key::frame_for_hashing(self.version, key.body(), |data| context.update(data))
            .ok_or(VerifyError::BadSignature)
    }

    /// Hashes the trailer (RFC 9580 §5.2.4): the signature's fields from its
    /// version through its hashed subpackets, then the version again, `0xFF`,
    /// and the length of those fields in four octets, modulo 2^32.
    fn hash_trailer(&self, context: &mut Context) {
        let version = match self.version {
            Version::V4 => 4,
            Version::V6 => 6,
        };
        // A packet's body is at most 2^32 - 1 octets, so this never wraps.
        let hashed_fields = self.hashed_fields();
        let length = u32::try_from(hashed_fields.len()).unwrap_or(u32::MAX);
        context.update(hashed_fields);
        context.update(&[version, 0xFF]);
        context.update(&length.to_be_bytes());
    }
}

/// The hashes a signature over a subject may be made over.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Digests {
    /// The subject's hash. For a text document, a line ends at an LF, with
    /// or without a CR before it, and any other CR is part of the text.
    digest: Digest,
    /// For a text document GnuPG may read otherwise, the hash as GnuPG reads
    /// it: without the CRs that come before a line's CR LF or end the
    /// document. It is there for a document with two CRs in a row or a CR at
    /// its end, and may equal the first.
    gnupg: Option<Digest>,
}

impl Digests {
    /// Each hash, the subject's first.
    fn iter(&self) -> impl Iterator<Item = &Digest> {
        core::iter::once(&self.digest).chain(&self.gnupg)
    }
}

/// The cryptographic check a key and a signature's material call for.
#[derive(Clone, Copy)]
enum Check<'a> {
    Rsa {
        modulus: &'a [u8],
        exponent: &'a [u8],
        value: &'a [u8],
    },
    Ed25519 {
        key: &'a [u8; 32],
        value: &'a [u8; 64],
    },
}

impl<'a> Check<'a> {
    /// The check for `key` and a signature of the key's algorithm whose
    /// material is `material`.
    ///
    /// # Errors
    ///
    /// [`VerifyError::UnsupportedAlgorithm`] if irongall does not verify with
    /// the key, and [`VerifyError::BadSignature`] if it does but cannot read
    /// the material, which the key then did not make: an EdDSALegacy
    /// signature whose integers are wider than Ed25519's.
    fn of(key: &'a PublicKey, material: &'a SignatureMaterial) -> Result<Check<'a>, VerifyError> {
        match (VerifyingKey::of(key)?, material) {
            (VerifyingKey::Rsa { modulus, exponent }, SignatureMaterial::Rsa(value)) => {
                Ok(Check::Rsa {
                    modulus,
                    exponent,
                    value,
                })
            }
            (VerifyingKey::Ed25519(key), SignatureMaterial::Ed25519(value)) => {
                Ok(Check::Ed25519 { key, value })
            }
            _ => Err(VerifyError::BadSignature),
        }
    }
}

/// A key's material, as the algorithm irongall verifies the key's
/// signatures with reads it.
#[derive(Clone, Copy)]
enum VerifyingKey<'a> {
    Rsa {
        modulus: &'a [u8],
        exponent: &'a [u8],
    },
    Ed25519(&'a [u8; 32]),
}

impl<'a> VerifyingKey<'a> {
    /// `key`'s material, if irongall verifies with the key's algorithm.
    ///
    /// RSA's encrypt-only variant (2) has material like any RSA key, but its
    /// algorithm says it does not sign.
    ///
    /// # Errors
    ///
    /// [`VerifyError::UnsupportedAlgorithm`] if irongall does not verify with
    /// the key's algorithm, or the key carries material of another.
    fn of(key: &'a PublicKey) -> Result<VerifyingKey<'a>, VerifyError> {
        match (key.algorithm(), key.material()) {
            (
                PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSA_SIGN_ONLY,
                KeyMaterial::Rsa { modulus, exponent },
            ) => Ok(VerifyingKey::Rsa { modulus, exponent }),
            (
                PublicKeyAlgorithm::ED25519 | PublicKeyAlgorithm::EDDSA_LEGACY,
                KeyMaterial::Ed25519(key),
            ) => Ok(VerifyingKey::Ed25519(key)),
            _ => Err(VerifyError::UnsupportedAlgorithm),
        }
    }
}

/// Checks that irongall verifies signatures with `key`: that the key is of
/// an algorithm irongall verifies with, and its material a key that
/// algorithm's verification accepts.
///
/// A key that fails verifies no signature, whatever its material, and the
/// error is one of those [`VerifyError::is_key_error`] names. Verifying a
/// signature checks the same, through the same checks, once it has hashed
/// the signature's subject.
pub(crate) fn check_verifying_key(key: &PublicKey) -> Result<(), VerifyError> {
    match VerifyingKey::of(key)? {
        VerifyingKey::Rsa { modulus, exponent } => {
            rsa::check_key(modulus, exponent).map_err(rsa_failure)?;
        }
        VerifyingKey::Ed25519(key) => ed25519::check_key(key)?,
    }
    Ok(())
}

/// A document being hashed for a signature, in pieces: what
/// [`Signature::document_hash`] begins.
///
/// Each piece passes to the hash as it arrives, so the document need not be
/// held whole:
///
/// ```
/// use irongall::signature::{Signature, Subject};
/// use irongall::{armor, cert, packet};
///
/// # let certificate = "\
/// # -----BEGIN PGP PUBLIC KEY BLOCK-----
/// #
/// # xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
/// # GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
/// # KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
/// # gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
/// # QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
/// # +eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
/// # BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
/// # j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
/// # I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
/// # -----END PGP PUBLIC KEY BLOCK-----
/// # ";
/// # let data = armor::decode(certificate.as_bytes())?.into_data();
/// # let certificate = cert::certificates(&data).next().unwrap()?;
/// // The version 6 text signature of RFC 9580 Appendix A.6, by the primary
/// // key of the certificate of Appendix A.3.
/// let armored = "\
/// -----BEGIN PGP SIGNATURE-----
///
/// wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
/// 2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
/// /FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
/// NK2ay45cX1IVAQ==
/// -----END PGP SIGNATURE-----
/// ";
/// let data = armor::decode(armored.as_bytes())?.into_data();
/// let signature = Signature::from_packet(&packet::packets(&data).next().unwrap()?)?;
///
/// let mut hash = signature.document_hash()?;
/// for line in ["What we need from the grocery store:\n", "\n"] {
///     hash.update(line.as_bytes());
/// }
/// hash.update(b"- tofu\n- vegetables\n- noodles\n");
/// hash.verify(certificate.primary())?;
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct DocumentHash<'a> {
    signature: &'a Signature,
    context: Context,
    /// For a text signature, the conversion of the document's line endings,
    /// which carries its state from one piece to the next.
    line_endings: Option<LineEndings>,
}

impl<'a> DocumentHash<'a> {
    /// The signature the document is being hashed for.
    pub fn signature(&self) -> &'a Signature {
        self.signature
    }

    /// Passes the next piece of the document to the hash.
    pub fn update(&mut self, piece: &[u8]) {
        hash_document(&mut self.context, self.line_endings.as_mut(), piece);
    }

    /// Verifies that the signature is `key`'s over the document passed so
    /// far, as [`Signature::verify`] does over [`Subject::Document`].
    ///
    /// The hashing is not consumed, so one document can be checked against
    /// several keys, or hashed further.
    ///
    /// # Errors
    ///
    /// When the signature does not verify; the error says why.
    pub fn verify(&self, key: &PublicKey) -> Result<(), VerifyError> {
        let check = self.signature.check_key(key)?;
        self.signature.check_hash_length()?;
        self.check_digests(check)
    }

    /// Checks that `key` made the signature over the document passed so
    /// far, as [`Signature::made_by`] does over [`Subject::Document`]:
    /// without the floor on the length of an Ed25519 signature's hash.
    pub(crate) fn made_by(&self, key: &PublicKey) -> Result<(), VerifyError> {
        let check = self.signature.check_key(key)?;
        self.check_digests(check)
    }

    /// Checks the hashes of the document passed so far against `check`.
    fn check_digests(&self, check: Check<'_>) -> Result<(), VerifyError> {
        let digests = self
            .signature
            .finish(&self.context, self.line_endings.as_ref());
        self.signature.check_digests(check, &digests)
    }
}

/// Passes a piece of a document to a hash context: through `line_endings`
/// for a text signature, and as it is for any other.
fn hash_document(context: &mut Context, line_endings: Option<&mut LineEndings>, piece: &[u8]) {
    match line_endings {
        Some(line_endings) => line_endings.update(context, piece),
        None => context.update(piece),
    }
}

/// Passes a text document to a hash context with its line endings made CR LF
/// (RFC 9580 §5.2.4), in pieces of any size, as two readings of where a line
/// ends.
///
/// RFC 9580 §5.2.1.2 does not say what a line ending is, and implementations
/// read it three ways. They agree on LF and CR LF, and differ over a CR that
/// no LF directly follows:
///
/// - A line ends at an LF, with or without a CR before it, and any other CR
///   is part of the text. OpenPGP.js hashes a text so, and so does rPGP,
///   apart from its signer making a CR that ends the text a line ending.
/// - As above, but the CRs before a line's CR LF, and those that end the
///   text, are dropped. GnuPG and RNP hash a text so.
/// - A line also ends at a lone CR. Sequoia and Bouncy Castle hash a text
///   so.
///
/// A text signature verifies under either of the first two readings, which
/// differ only in CRs at the end of a line or of the text. The third is not
/// followed: under it, an LF could be replaced by a CR without breaking the
/// signature, and a program that splits lines at LFs would then read two
/// lines as one.
///
/// One hash context serves both readings until a second CR in a row, after
/// which they may part: a CR that ends the text passed so far is held back
/// from it, since what follows decides how each reading hashes it. From the
/// second CR on, GnuPG's reading continues in a context of its own, which
/// holds back the CRs it may drop, while the first reading's hashes every
/// CR as it arrives. So finishing a hash, which [`DocumentHash::verify`]
/// does for each key it is checked against, never hashes more than one CR.
#[derive(Debug, Clone, Default)]
struct LineEndings {
    /// The CRs that end the text passed so far. Until the readings part,
    /// at most one, which no context holds yet; after, any number, which
    /// the first reading's context holds and GnuPG's does not.
    crs: u64,
    /// The hash as GnuPG reads the line endings, once the readings part.
    gnupg: Option<Context>,
}

impl LineEndings {
    /// Passes the next piece of the document.
    fn update(&mut self, context: &mut Context, piece: &[u8]) {
        let mut rest = piece;
        while let Some((line, from_lf)) = rest
            .iter()
            .position(|&octet| octet == b'\n')
            .and_then(|at| rest.split_at_checked(at))
        {
            self.text(context, line);
            self.line_ending(context);
            rest = from_lf.get(1..).unwrap_or_default();
        }
        self.text(context, rest);
    }

    /// Passes text that holds no LF.
    fn text(&mut self, context: &mut Context, text: &[u8]) {
        let mut body = text;
        while let [rest @ .., b'\r'] = body {
            body = rest;
        }
        if !body.is_empty() {
            // Text follows the CRs that ended the text before, so both
            // readings keep them.
            match &mut self.gnupg {
                None => hash_crs(context, self.crs),
                Some(gnupg) => {
                    hash_crs(gnupg, self.crs);
                    gnupg.update(body);
                }
            }
            context.update(body);
            self.crs = 0;
        }
        let ending = u64::try_from(text.len().saturating_sub(body.len())).unwrap_or(u64::MAX);
        self.crs = self.crs.saturating_add(ending);
        match self.gnupg {
            Some(_) => hash_crs(context, ending),
            None if self.crs > 1 => {
                self.gnupg = Some(context.clone());
                hash_crs(context, self.crs);
            }
            None => {}
        }
    }

    /// Passes an LF, which ends a line: the CR before it, if there is one,
    /// is the line ending's own, and any before that are text, or, as GnuPG
    /// reads them, dropped.
    fn line_ending(&mut self, context: &mut Context) {
        match &mut self.gnupg {
            // At most one CR is held back, and the line ending is its own.
            None => context.update(b"\r\n"),
            Some(gnupg) => {
                context.update(if self.crs > 0 { b"\n" } else { b"\r\n" });
                gnupg.update(b"\r\n");
            }
        }
        self.crs = 0;
    }

    /// The hash contexts once the document has ended: the first reading's,
    /// which keeps the CRs that end the text, and GnuPG's, which drops them,
    /// if the readings may differ.
    fn finish(&self, context: &Context) -> (Context, Option<Context>) {
        match &self.gnupg {
            Some(gnupg) => (context.clone(), Some(gnupg.clone())),
            None => {
                let mut ended = context.clone();
                hash_crs(&mut ended, self.crs);
                (ended, (self.crs > 0).then(|| context.clone()))
            }
        }
    }
}

/// Passes `count` CRs to a hash context.
fn hash_crs(context: &mut Context, count: u64) {
    const CRS: [u8; 64] = [b'\r'; 64];
    let mut left = count;
    while let Some(after) = left.checked_sub(64) {
        context.update(&CRS);
        left = after;
    }
    // Fewer than 64 are left, so the conversion never fails.
    context.update(
        CRS.get(..usize::try_from(left).unwrap_or_default())
            .unwrap_or_default(),
    );
}
