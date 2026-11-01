//! Verifying a document's signatures against a keyring, under a policy.
//!
//! A [`Keyring`] holds the certificates a caller trusts. [`Keyring::verify`]
//! answers whether a document is signed by one of them: whether any of its
//! signatures verifies with a key in the keyring, and is accepted under a
//! [`Policy`] as of a given time. The rules are the [`policy`] module's.
//!
//! ```
//! use irongall::keyring::Keyring;
//! use irongall::policy::Policy;
//! use irongall::{armor, cert, document};
//!
//! // The version 6 certificate of RFC 9580 Appendix A.3, and the cleartext
//! // signed message of Appendix A.6 its primary key signed.
//! # let certificate = "\
//! # -----BEGIN PGP PUBLIC KEY BLOCK-----
//! #
//! # xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
//! # GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
//! # KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
//! # gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
//! # QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
//! # +eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
//! # BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
//! # j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
//! # I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
//! # -----END PGP PUBLIC KEY BLOCK-----
//! # ";
//! # let message = "\
//! # -----BEGIN PGP SIGNED MESSAGE-----
//! #
//! # What we need from the grocery store:
//! #
//! # - - tofu
//! # - - vegetables
//! # - - noodles
//! #
//! # -----BEGIN PGP SIGNATURE-----
//! #
//! # wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
//! # 2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
//! # /FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
//! # NK2ay45cX1IVAQ==
//! # -----END PGP SIGNATURE-----
//! # ";
//! let data = armor::decode(certificate.as_bytes())?.into_data();
//! let keyring: Keyring = cert::certificates(&data).collect::<Result<_, _>>()?;
//! let message = document::cleartext(message.as_bytes())?;
//!
//! // 2022-12-14 00:00:00 UTC, the day after the message was signed.
//! let now = 1_670_976_000;
//! let verified = keyring.verify(&Policy::new(), now, message.signatures(), message.text())?;
//! assert_eq!(
//!     verified.key().fingerprint().to_string(),
//!     "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"
//! );
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # How a document is judged
//!
//! Every signature on the document is tried with every key in the keyring it
//! may have been made by: those its issuers name, or every key if it names
//! none. A signature that verifies with a key is then judged under the
//! policy, and the first accepted is the answer. A signature a key made but
//! the policy refuses does not end the search, since the document may carry
//! another, from the same key or another, that the policy accepts. When none
//! is accepted, the refusal reported is the first refusal of a signature a
//! key in the keyring made. If no key made one, it is the first signature
//! that names as its issuer a key in the keyring irongall does not verify
//! with, such as a DSA key, and otherwise that nothing verified.
//!
//! Each signature is hashed over the document once, however many keys it is
//! tried with, and a certificate's own signatures are verified only once one
//! of its keys has made a signature on the document.

#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use core::fmt;

use crate::cert::{self, Certificate};
use crate::key::{Fingerprint, PublicKey};
use crate::policy::{self, Authority, Policy, Reason};
use crate::signature::{DocumentHash, Signature};

/// The certificates a caller trusts to sign documents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keyring {
    certificates: Vec<Certificate>,
}

impl Keyring {
    /// A keyring of `certificates`.
    ///
    /// Certificates of the same primary key, such as two copies of one
    /// certificate obtained at different times, are combined into one, as
    /// though their packets had been read together: every signature either
    /// holds is weighed, so a revocation that one holds is not lifted by
    /// another that lacks it. The parts that were passed over are those of
    /// both, each with its offset in the input it was read from.
    ///
    /// Nothing is judged here: a revoked or expired certificate is kept, and
    /// refused, with its reason, when it signs.
    pub fn new(certificates: impl IntoIterator<Item = Certificate>) -> Keyring {
        Keyring {
            certificates: cert::combine(certificates),
        }
    }

    /// The certificates, in the order they were given, those of the same
    /// primary key combined into one at the place of the first.
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    /// Verifies that a key in the keyring signed `document`: that one of
    /// `signatures` verifies with it over the document, and is accepted
    /// under `policy` as of `now`, in seconds since the Unix epoch.
    ///
    /// The signatures are those a [`Cleartext`](crate::document::Cleartext)
    /// or a [`Detached`](crate::document::Detached) carries. Those that are
    /// not over a document, and those of a hash irongall does not implement,
    /// are passed over.
    ///
    /// A text signature verifies over the document with its line endings
    /// made CR LF, not over its exact octets; a policy that refuses text
    /// signatures, [`Policy::with_text_signatures`], holds a binary file to
    /// every octet.
    ///
    /// # Errors
    ///
    /// When no signature is accepted, the reason: see the
    /// [module documentation](self).
    pub fn verify<'a>(
        &'a self,
        policy: &Policy,
        now: u64,
        signatures: &'a [Signature],
        document: &[u8],
    ) -> Result<Verified<'a>, Refusal> {
        if signatures.len() > policy.max_signatures() {
            return Err(Refusal::of(Reason::TooManySignatures));
        }
        let hashes: Vec<DocumentHash<'a>> = signatures
            .iter()
            .filter_map(|signature| signature.document_hash().ok())
            .map(|mut hash| {
                hash.update(document);
                hash
            })
            .collect();
        self.verify_hashed(policy, now, &hashes)
    }

    /// [`verify`](Self::verify), for a document hashed in pieces for each of
    /// its signatures: see [`Signature::document_hash`].
    ///
    /// # Errors
    ///
    /// When no signature is accepted, the reason: see the
    /// [module documentation](self).
    pub fn verify_hashed<'a>(
        &'a self,
        policy: &Policy,
        now: u64,
        hashes: &[DocumentHash<'a>],
    ) -> Result<Verified<'a>, Refusal> {
        if hashes.len() > policy.max_signatures() {
            return Err(Refusal::of(Reason::TooManySignatures));
        }
        let mut authorities: Vec<Option<Authority<'a>>> =
            self.certificates.iter().map(|_| None).collect();
        let mut refusal = None;
        let mut unsupported = None;
        for hash in hashes {
            let signature = hash.signature();
            for (certificate, authority) in self.certificates.iter().zip(&mut authorities) {
                for (index, key) in policy::keys(certificate).enumerate() {
                    if !may_be_by(signature, key) {
                        continue;
                    }
                    // Which key made the signature is the equation's to say,
                    // so one over a hash too short for its key's algorithm
                    // is refused by the policy for its hash, not passed over
                    // as unverified.
                    if let Err(error) = hash.made_by(key) {
                        if error.is_key_error() && names(signature, key) {
                            unsupported.get_or_insert(Refusal::by(
                                Reason::UnsupportedKey,
                                certificate,
                                key,
                            ));
                        }
                        continue;
                    }
                    let authority =
                        authority.get_or_insert_with(|| Authority::new(certificate, policy, now));
                    // An authority holds a standing for each of its
                    // certificate's keys, in this order, so one is there.
                    let standing = authority.standing(index).ok_or(Reason::Unverified);
                    match standing
                        .and_then(|standing| policy::accept(standing, signature, policy, now))
                    {
                        Ok(()) => {
                            return Ok(Verified {
                                certificate,
                                key,
                                signature,
                            });
                        }
                        Err(reason) => {
                            refusal.get_or_insert(Refusal::by(reason, certificate, key));
                        }
                    }
                }
            }
        }
        Err(refusal
            .or(unsupported)
            .unwrap_or(Refusal::of(Reason::Unverified)))
    }
}

impl FromIterator<Certificate> for Keyring {
    fn from_iter<I: IntoIterator<Item = Certificate>>(certificates: I) -> Keyring {
        Keyring::new(certificates)
    }
}

/// Whether `signature` may have been made by `key`, as the issuers it names
/// say: those naming `key`, and those naming no issuer at all.
///
/// An issuer is a hint, and an unhashed one can be changed by anyone, so this
/// only decides which keys a signature over a document is tried with. Trying
/// one that is named wrongly costs a failed verification, and passing over
/// one that is named wrongly loses nothing that removing the signature would
/// not, since a document's signature can only be accepted. A certificate's
/// own signatures, which can restrict what it grants, are each verified with
/// the key that would have made them whatever issuer they name (see the
/// [`policy`] module).
fn may_be_by(signature: &Signature, key: &PublicKey) -> bool {
    issued_by(signature, key).is_none_or(|named| named)
}

/// Whether one of the issuers `signature` names is `key`.
fn names(signature: &Signature, key: &PublicKey) -> bool {
    issued_by(signature, key) == Some(true)
}

/// Whether the issuers `signature` names include `key`, or `None` if it
/// names none.
fn issued_by(signature: &Signature, key: &PublicKey) -> Option<bool> {
    let fingerprint = key.fingerprint();
    let key_id = key.key_id();
    let mut named = None;
    for issuer in signature.issuer_fingerprints() {
        if issuer == fingerprint {
            return Some(true);
        }
        named = Some(false);
    }
    for issuer in signature.issuer_key_ids() {
        if issuer == key_id {
            return Some(true);
        }
        named = Some(false);
    }
    named
}

/// A signature a key in the keyring made over a document, and the policy
/// accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified<'a> {
    certificate: &'a Certificate,
    key: &'a PublicKey,
    signature: &'a Signature,
}

impl<'a> Verified<'a> {
    /// The certificate whose key made the signature: the identity that
    /// stands behind the document, and the one to pin, since it does not
    /// change when the certificate rotates its signing subkeys.
    pub fn certificate(&self) -> &'a Certificate {
        self.certificate
    }

    /// The key that made the signature: the certificate's primary key, or
    /// one of its subkeys.
    pub fn key(&self) -> &'a PublicKey {
        self.key
    }

    /// The signature.
    pub fn signature(&self) -> &'a Signature {
        self.signature
    }
}

/// Why no signature on a document was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    reason: Reason,
    /// The fingerprints of the certificate and the key that made the
    /// signature refused, when a key in the keyring made one, or that the
    /// signature names, when the reason is [`Reason::UnsupportedKey`].
    signer: Option<(Fingerprint, Fingerprint)>,
}

impl Refusal {
    fn of(reason: Reason) -> Refusal {
        Refusal {
            reason,
            signer: None,
        }
    }

    /// A refusal of a signature by `key`, of `certificate`.
    fn by(reason: Reason, certificate: &Certificate, key: &PublicKey) -> Refusal {
        Refusal {
            reason,
            signer: Some((certificate.primary().fingerprint(), key.fingerprint())),
        }
    }

    /// Why.
    pub fn reason(&self) -> Reason {
        self.reason
    }

    /// The fingerprint of the certificate whose key made the signature
    /// refused, if a key in the keyring made it, or whose key the signature
    /// names, if the reason is [`Reason::UnsupportedKey`].
    pub fn certificate(&self) -> Option<Fingerprint> {
        self.signer.map(|(certificate, _)| certificate)
    }

    /// The fingerprint of the key that made the signature refused, if a key
    /// in the keyring made it, or that the signature names, if the reason is
    /// [`Reason::UnsupportedKey`].
    pub fn key(&self) -> Option<Fingerprint> {
        self.signer.map(|(_, key)| key)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.signer {
            Some((certificate, key)) if certificate == key => {
                write!(f, "{} (key {key})", self.reason)
            }
            Some((certificate, key)) => {
                write!(f, "{} (key {key}, certificate {certificate})", self.reason)
            }
            None => self.reason.fmt(f),
        }
    }
}

impl core::error::Error for Refusal {}
