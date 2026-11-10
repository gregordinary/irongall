//! What a signature that verifies is worth: the rules that decide whether it
//! is accepted, and the authority a certificate grants its keys.
//!
//! A [`Policy`] holds the rules a caller chooses: which hash algorithms a
//! signature may rest on, the narrowest RSA key accepted, how many signatures
//! a document may carry, whether a signature must not have expired, how far
//! ahead of the caller's clock a signer's clock may run, and whether a text
//! signature is accepted as well as a binary one. An
//! [`Authority`] is a certificate judged under a policy at a given time:
//! when the certificate itself lapses, and which of its keys may sign, from
//! when until when, or the reason one may not.
//! [`Keyring::verify`](crate::keyring::Keyring::verify) applies both to
//! a document's signatures.
//!
//! The time is always the caller's. irongall never reads a clock, so a
//! document pinned in the past can be judged as of the time it was
//! published.
//!
//! # A certificate's authority
//!
//! Only the certificate's own statements count: signatures its primary key
//! made, each verified before it counts. A signature by any other key,
//! including a revoker the certificate designates, is not weighed. Which
//! key made a signature is established by verifying it with the key that
//! would have, never by the issuer it names: an issuer in the unhashed area
//! can be changed by anyone who handles the certificate, and one naming
//! another key would hide a revocation the primary key made.
//!
//! What a statement is over, the primary key alone, a user ID, or a subkey,
//! is established the same way, by verifying it over that part, never by
//! where it is placed, since the order of a certificate's packets is
//! covered by no signature either. A statement that does not verify over
//! the part it is placed with is tried over the other parts it may be over,
//! by its equation wherever its hash prefix matches, and counts over the one
//! it verifies over. The prefix, the first two octets of the signature's
//! hash, is not covered by the signature, so over the part a statement is
//! placed with, its equation is checked whatever its prefix.
//!
//! That search is bounded by the certificate's size. A certificate as its
//! maker wrote it places each of its own statements where it verifies, so
//! what is searched are the certifications other keys made over its user
//! IDs, each tried over every user ID, and whatever has been inserted or
//! moved. Judging a certificate hashes at most 128 octets in the search for
//! each octet of the certificate's signatures, and checks by its equation
//! no more signatures there than the certificate holds. A certificate that
//! needs more grants nothing ([`Reason::UnattributedSignatures`]), since a
//! statement the search did not reach might restrict it. Certifications by
//! other keys stay within the bound unless the certificate has scores of
//! user IDs and almost nothing but such certifications. A user ID needs no
//! signature, though, so anyone who handles a certificate can add user IDs
//! until it needs more, and it then grants nothing, alone or combined with
//! another copy of itself. GnuPG drops a user ID that carries no
//! self-signature when it imports a certificate, so a certificate exported
//! from a GnuPG keyring holds none.
//!
//! - A certificate grants nothing if its primary key has revoked itself, for
//!   whatever reason and from whatever time, or if the policy does not accept
//!   its primary key.
//! - Over each object the primary key signs, the primary key alone and each
//!   user ID, the newest self-signature governs (RFC 9580 §5.2.3.10). A
//!   self-signature counts only if it is dated no earlier than the primary
//!   key, since one claiming to predate the key cannot have been made when
//!   it says, and no later than the given time, since one dated later
//!   describes a state not yet in effect. Several made in the same second
//!   all govern: packet order is covered by no signature, so it decides
//!   nothing, and what they state is combined as below.
//! - A governing self-signature is in force until it expires (§5.2.3.18), or
//!   until the primary key withdraws it with a certification revocation over
//!   the same object, made no earlier (§5.2.1.13). One that is not in force
//!   neither grants nor restricts: a user ID whose self-signature has expired
//!   or been withdrawn is no longer bound to the key, and says nothing about
//!   it.
//! - A certificate grants nothing unless a self-signature in force binds its
//!   primary key: a direct-key signature, or, in a version 4 certificate, a
//!   certification of a user ID. A version 6 certificate needs a direct-key
//!   signature (§5.2.3.10). Without such a binding, removing the
//!   self-signatures that state the key's expiration would lift it.
//! - The primary key may sign if at least one self-signature in force states
//!   key flags, and every one that does grants signing (§5.2.3.29). A
//!   self-signature that states none grants nothing. Its signatures are
//!   accepted from its creation until the earliest of the key expirations
//!   (§5.2.3.13) and the expirations that the self-signatures in force
//!   state. Every user ID in force restricts the key, not the primary one
//!   alone: GnuPG and Sequoia re-sign every user ID in force when they change
//!   a key's expiration, so the user IDs agree, and where they do not, the
//!   narrowest holds.
//! - A subkey may sign if the policy accepts it, its primary key has not
//!   revoked it, and the newest subkey bindings over it, made no earlier
//!   than either key and no later than the given time, each rest on a hash
//!   the policy accepts, grant signing, and embed the subkey's own
//!   back-signature (RFC 9580 §5.2.1.8). The back-signature must verify,
//!   rest on a hash the policy accepts, and be dated as the bindings are: no
//!   earlier than either key and no later than the given time. Its
//!   signatures are accepted from the creation of the later of the two keys
//!   until the earliest of the primary key's lapse, the bindings' key
//!   expirations, and the bindings' and the back-signatures' own
//!   expirations. A back-signature that states an expiration must be in the
//!   binding's hashed area, which the binding covers; see [the
//!   back-signature's expiration](#a-back-signatures-expiration).
//!
//! A signature counts as made by the given time if it is dated no later
//! than the policy's [clock skew](Policy::clock_skew) after it.
//!
//! Every rule above fails closed: a statement found as above that restricts
//! what a certificate grants is never passed over for a reason of irongall's
//! own where passing over it would lift the restriction. The statements
//! irongall cannot attribute to any key are set out below. So the policy's
//! hash algorithms apply to the bindings and back-signatures that grant a
//! subkey its authority, where refusing one refuses the subkey, and to the
//! self-signatures over the primary key and the certification revocations
//! that withdraw them, where refusing one that governs or withdraws refuses
//! the certificate rather than let an older self-signature, perhaps with a
//! longer life, govern in its place. They do not apply to key and subkey
//! revocations, where refusing one would leave a revoked key in force. For
//! the same reason, a signature irongall does not honor still revokes if it
//! is a revocation, and refuses the certificate or the subkey if it is a
//! self-signature or binding that governs, or withdraws one. irongall does
//! not honor a signature that carries a critical subpacket it does not
//! implement, or that is malformed only where verifying it does not look: a
//! subpacket of the wrong form, an embedded signature or an unhashed area
//! that does not read, octets after its material, or an integer of its
//! material whose length is not written as RFC 9580 requires (§3.2). Nor does
//! it honor a certificate's statement whose hash prefix is not its hash's
//! (§5.2.3.6). None of these is covered by the signature, so passing over
//! such a signature would let anyone who handles the certificate lift a
//! restriction by changing them.
//!
//! An Ed25519 signature over a hash shorter than 256 bits never verifies
//! (RFC 9580 §5.2.3.3 and §5.2.3.4), but its equation still establishes the
//! key that made it. So a certificate's statement made so is weighed as one
//! over a hash the policy refuses: a revocation revokes, and a
//! self-signature, binding, or withdrawal that governs refuses its
//! certificate or subkey.
//!
//! A statement over a hash irongall does not implement, MD5 or RIPEMD-160,
//! or of a version irongall does not read, version 3, cannot be attributed
//! to any key, so it is passed over whatever it states: a revocation
//! revokes nothing, a certification revocation withdraws nothing, and a
//! newer self-signature or binding does not keep an older one from
//! governing. RFC 9580 forbids making a signature over either hash (§9.5),
//! and making a version 3 signature (§5.2).
//!
//! A self-signature over the primary key made before 1 February 2023, and a
//! certification revocation made before then, are the exception: each
//! grants, or withdraws, over any hash on which its key's signatures
//! verify, SHA-1 among them for an RSA key, as in GnuPG, since many keys in
//! use, archive signing keys among them, were self-signed over SHA-1 alone
//! before then. RFC 9580 §9.5 forbids validating a recent signature that
//! depends on SHA-1, and discourages validating an old one. The date is the
//! one from which Sequoia's standard policy refuses SHA-1 in a
//! self-signature.
//!
//! The risk the exception leaves is a chosen-prefix collision, by which a
//! key holder who certified another party's key over SHA-1 also certified,
//! with the same signature, a user ID of that party's choosing on its own
//! key. The forged self-signature is that certification, its creation time
//! included, so only a certification made before the date can serve as one.
//! Such a signature states no key flags and no expiration, and loses the
//! primary user ID to any user ID marked primary or certified over a hash
//! the policy accepts. A certificate stripped of its other user IDs is,
//! however, bound by it alone, with no expiration.
//!
//! # A back-signature's expiration
//!
//! A binding covers the back-signature it embeds only if the back-signature
//! is in its hashed area, as Sequoia and OpenPGP.js place it. GnuPG and RNP
//! place it in the unhashed area, which no signature covers. A
//! back-signature's expiration therefore holds only in the hashed area: one
//! in the unhashed area that states an expiration refuses the subkey
//! ([`Reason::UnhonoredBinding`]) rather than bound it. GnuPG and RNP give a
//! back-signature no expiration of its own, and one in the unhashed area
//! that states none gives its consent as one the binding covers does. Every
//! bound on a subkey irongall accepts rests on a signature that covers it.
//!
//! # A document's signature
//!
//! A signature over a document is accepted when it verifies with a key that
//! may sign, rests on a hash the policy accepts, is of a type the policy
//! accepts, is dated no later than the given time and the clock skew allow,
//! was made within the key's window, and, if the policy requires fresh
//! signatures, had not expired by the given time. The key's window must
//! still be open at the given time, too: a signature's date is its signer's
//! claim, so once a key has expired, whoever holds it could otherwise date a
//! new signature within its life. A document pinned in the past is judged
//! as of the time it was published.

mod statements;
#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::ops::RangeInclusive;

use crate::bignum;
use crate::cert::{Certificate, Subkey, UserId};
use crate::hash::HashAlgorithm;
use crate::key::{KeyMaterial, PublicKey};
use crate::packet::Version;
use crate::signature::{self, Signature, SignatureType, Subject};
use statements::{Statement, Statements};

/// The rules a signature is judged by.
///
/// The defaults, [`Policy::new`]:
///
/// - The hash algorithms SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA3-256,
///   and SHA3-512. SHA-1, MD5, and RIPEMD-160 are refused: collisions
///   against all three are within reach, and a signature binds its signer
///   only to its digest. A self-signature over a primary key made before
///   1 February 2023 may rest on any hash on which its key's signatures
///   verify (see the [module documentation](self)).
/// - Every key irongall verifies with ([`Policy::accepts_key`]): RSA keys of
///   2048 bits or more, the narrowest RFC 9580 §12.4 permits verifying with,
///   and Ed25519 keys.
/// - At most 16 signatures on a document.
/// - Signatures that have not expired.
/// - A clock skew of 30 minutes: a signature dated up to that long after the
///   time it is judged at counts as made, since the signer's clock and the
///   caller's may disagree.
/// - Text signatures as well as binary ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    hashes: Vec<HashAlgorithm>,
    rsa_minimum_bits: usize,
    max_signatures: usize,
    fresh: bool,
    clock_skew: u64,
    text_signatures: bool,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy::new()
    }
}

impl Policy {
    /// The default rules.
    pub fn new() -> Policy {
        Policy {
            hashes: [
                HashAlgorithm::SHA224,
                HashAlgorithm::SHA256,
                HashAlgorithm::SHA384,
                HashAlgorithm::SHA512,
                HashAlgorithm::SHA3_256,
                HashAlgorithm::SHA3_512,
            ]
            .to_vec(),
            rsa_minimum_bits: 2048,
            max_signatures: 16,
            fresh: true,
            clock_skew: 30 * 60,
            text_signatures: true,
        }
    }

    /// Whether a signature may rest on `algorithm`.
    ///
    /// An Ed25519 signature also needs a hash of 256 bits or more, whatever
    /// the policy accepts (RFC 9580 §5.2.3.3 and §5.2.3.4).
    pub fn accepts_hash(&self, algorithm: HashAlgorithm) -> bool {
        self.hashes.contains(&algorithm)
    }

    /// The policy with `algorithm` accepted, or not.
    ///
    /// Accepting an algorithm irongall does not implement changes nothing: a
    /// signature over it never verifies. Nor does accepting SHA-1 or SHA2-224
    /// for an Ed25519 signature, which needs a longer hash.
    #[must_use]
    pub fn with_hash(mut self, algorithm: HashAlgorithm, accepted: bool) -> Policy {
        self.hashes.retain(|&held| held != algorithm);
        if accepted {
            self.hashes.push(algorithm);
        }
        self
    }

    /// The narrowest RSA modulus accepted, in bits.
    pub fn rsa_minimum_bits(&self) -> usize {
        self.rsa_minimum_bits
    }

    /// The policy with the narrowest RSA modulus accepted made `bits`.
    ///
    /// A value below 2048 changes nothing: RFC 9580 §12.4 forbids verifying
    /// with a narrower key, and irongall never does.
    #[must_use]
    pub fn with_rsa_minimum_bits(mut self, bits: usize) -> Policy {
        self.rsa_minimum_bits = bits;
        self
    }

    /// The most signatures a document may carry.
    ///
    /// Each signature is hashed over the whole document and checked against
    /// every key that may have made it, so the bound is what keeps the
    /// document's maker from choosing how much work verifying it takes.
    pub fn max_signatures(&self) -> usize {
        self.max_signatures
    }

    /// The policy with the most signatures a document may carry made
    /// `count`.
    #[must_use]
    pub fn with_max_signatures(mut self, count: usize) -> Policy {
        self.max_signatures = count;
        self
    }

    /// Whether a signature must not have expired by the time it is judged
    /// at.
    pub fn requires_fresh_signatures(&self) -> bool {
        self.fresh
    }

    /// The policy with fresh signatures required, or not.
    ///
    /// A document pinned in the past, whose signature has since expired, is
    /// judged without the requirement, or at the time it was published. One
    /// whose signing key has since expired is judged at the time it was
    /// published: no policy accepts a signature by a key whose authority has
    /// lapsed.
    #[must_use]
    pub fn with_fresh_signatures(mut self, required: bool) -> Policy {
        self.fresh = required;
        self
    }

    /// How far after the time it is judged at a signature may be dated and
    /// still count as made, in seconds: the tolerance for a caller's clock
    /// that runs behind the signer's.
    ///
    /// It applies wherever a signature's date is held to the time judged at:
    /// a document's signature dated later is refused, a self-signature or
    /// binding dated later does not govern, and a back-signature dated later
    /// gives no consent.
    pub fn clock_skew(&self) -> u64 {
        self.clock_skew
    }

    /// The policy with the clock skew tolerated made `seconds`.
    ///
    /// A caller judging at an exact time rather than at a clock's reading,
    /// such as the time a pinned document was published, may make it zero.
    #[must_use]
    pub fn with_clock_skew(mut self, seconds: u64) -> Policy {
        self.clock_skew = seconds;
        self
    }

    /// Whether a text signature (0x01) is accepted over a document, as well
    /// as a binary one (0x00).
    ///
    /// A text signature is made over a document with its line endings made
    /// CR LF, so it verifies over every form of the document that differs
    /// only in the CRs before its LFs and at its end: it does not fix the
    /// document's exact octets. The signer chooses the type, and the
    /// signature's hash covers it, so no one else can change it.
    pub fn accepts_text_signatures(&self) -> bool {
        self.text_signatures
    }

    /// The policy with text signatures accepted, or not.
    ///
    /// A caller verifying a file whose every octet counts, such as an
    /// archive or a binary package, refuses them. A cleartext signed message
    /// carries text signatures only, so a policy that refuses them accepts
    /// no such message.
    #[must_use]
    pub fn with_text_signatures(mut self, accepted: bool) -> Policy {
        self.text_signatures = accepted;
        self
    }

    /// Whether a signature may rest on `key`: a key irongall verifies with,
    /// and if it is an RSA key, one at least
    /// [`rsa_minimum_bits`](Self::rsa_minimum_bits) wide.
    ///
    /// irongall verifies with an RSA key of 2048 to 8192 bits whose public
    /// exponent is odd and from 3 to 2^33 - 1, and with an Ed25519 key whose
    /// point is encoded canonically and is not of small order (see the
    /// [crate's conformance notes](crate#conformance)). The set accepted is
    /// named rather than the set refused, so a key of an algorithm irongall
    /// does not verify with, or one whose material it refuses to verify
    /// with, is never accepted.
    pub fn accepts_key(&self, key: &PublicKey) -> bool {
        signature::check_verifying_key(key).is_ok()
            && match key.material() {
                KeyMaterial::Rsa { modulus, .. } => {
                    bignum::bit_length(modulus) >= self.rsa_minimum_bits
                }
                KeyMaterial::Ed25519(_) | KeyMaterial::Opaque => true,
            }
    }

    /// The latest a signature judged at `now` may be dated and count as
    /// made: `now`, and the clock skew tolerated.
    fn horizon(&self, now: u64) -> u64 {
        now.saturating_add(self.clock_skew)
    }

    /// Whether a signature may rest on the hash it names: one the policy
    /// accepts, and no shorter than the signature's public-key algorithm
    /// allows (see [`Reason::WeakHash`]).
    fn accepts_hash_of(&self, signature: &Signature) -> bool {
        self.accepts_hash(signature.hash_algorithm()) && !signature.hash_too_short()
    }

    /// Whether a self-signature over the primary key may grant what it
    /// states, or a certification revocation withdraw one, as far as its
    /// hash goes: one made before [`SELF_SIGNATURE_HASHES_FROM`] whatever
    /// hash it rests on, if no shorter than its public-key algorithm allows,
    /// and one made since only if the policy accepts its hash too.
    fn accepts_self_signature_hash(&self, signature: &Signature) -> bool {
        if signature.creation_time() < SELF_SIGNATURE_HASHES_FROM {
            !signature.hash_too_short()
        } else {
            self.accepts_hash_of(signature)
        }
    }
}

/// 1 February 2023, in seconds since the Unix epoch: a self-signature over
/// the primary key made from then on must rest on a hash the policy accepts,
/// and one made earlier may rest on any (see the [module
/// documentation](self)).
const SELF_SIGNATURE_HASHES_FROM: u32 = 1_675_209_600;

/// When a key's signatures are accepted: those made from when its authority
/// begins until it lapses, and judged before it lapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    created: u32,
    expires: Option<u64>,
}

impl Window {
    /// When the key's authority begins, in seconds since the Unix epoch: the
    /// key's creation, or for a subkey made before its primary key, the
    /// primary key's. The earliest a signature by the key is accepted.
    pub fn created(&self) -> u32 {
        self.created
    }

    /// When the key's authority lapses, in seconds since the Unix epoch, or
    /// `None` if nothing bounds it. A signature made then or later is not
    /// accepted, and from then on, no signature is.
    pub fn expires(&self) -> Option<u64> {
        self.expires
    }

    /// Whether a signature made at `time` falls in the window.
    pub fn contains(&self, time: u64) -> bool {
        u64::from(self.created) <= time && self.expires.is_none_or(|expires| time < expires)
    }
}

/// Why a signature is not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reason {
    /// The document carries more signatures than the policy verifies.
    TooManySignatures,
    /// No signature on the document verifies with a key in the keyring.
    Unverified,
    /// No signature on the document verifies with a key in the keyring, and
    /// one names as its issuer a key in the keyring that irongall does not
    /// verify with: one of an algorithm it does not implement, such as DSA or
    /// ECDSA, or an RSA key outside the bounds it verifies with.
    ///
    /// An issuer is the signature's own claim, so this says which key the
    /// signature names, not which key made it.
    UnsupportedKey,
    /// The signature rests on a hash the policy does not accept, or on one
    /// shorter than its public-key algorithm allows: an Ed25519 signature
    /// needs a hash of 256 bits or more (RFC 9580 §5.2.3.3 and §5.2.3.4).
    WeakHash,
    /// The signature is a text signature, which the policy does not accept:
    /// it is made over the document with its line endings made CR LF, not
    /// over its exact octets.
    TextSignature,
    /// The signature is dated after the time it is judged at, by more than
    /// the policy's clock skew: it claims a time not yet reached.
    Postdated,
    /// The signature is dated before the key that made it had authority:
    /// before the key was created, or, for a subkey, before its primary key
    /// was.
    BeforeKeyCreation,
    /// The signature was made after the authority of the key that made it
    /// had lapsed.
    AfterKeyExpiration,
    /// The authority of the key that made the signature had lapsed by the
    /// time the signature was judged at, though the signature is dated
    /// within it. A signature's date is its signer's claim, so an expired
    /// key's holder could date a new one within the key's life.
    KeyExpired,
    /// The signature had expired by the time it was judged at, and the
    /// policy requires fresh signatures.
    SignatureExpired,
    /// The certificate's primary key has revoked itself.
    CertificateRevoked,
    /// The policy does not accept the certificate's primary key, on which the
    /// authority of every key in it rests.
    WeakPrimaryKey,
    /// A self-signature that governs the certificate's primary key is one
    /// irongall does not honor, or a certification revocation that withdraws
    /// one is: it carries a critical subpacket whose meaning irongall does not
    /// implement, is malformed where verifying it does not look, or carries
    /// a hash prefix that is not its hash's (see the [module
    /// documentation](self)).
    UnhonoredSelfSignature,
    /// A self-signature that governs the certificate's primary key, or a
    /// certification revocation that withdraws one, rests on a hash on which
    /// a self-signature may not grant: one shorter than its public-key
    /// algorithm allows, or, if it was made on or after 1 February 2023, one
    /// the policy does not accept (see the [module documentation](self)).
    WeakSelfSignature,
    /// The certificate is of version 6 and has no direct-key signature in
    /// force (RFC 9580 §5.2.3.10).
    MissingDirectKeySignature,
    /// No self-signature in force binds the certificate's primary key: no
    /// direct-key signature, and no certification of a user ID, that the
    /// primary key made, dated from the key's creation to the time judged
    /// at, that has neither expired nor been withdrawn.
    MissingSelfSignature,
    /// The certificate's self-signatures do not grant its primary key the
    /// right to sign.
    PrimaryMayNotSign,
    /// The certificate's primary key has revoked the subkey.
    SubkeyRevoked,
    /// No binding by the certificate's primary key over the subkey verifies,
    /// dated from the creation of the later of the two keys to the time
    /// judged at.
    UnboundSubkey,
    /// The subkey's governing binding is one irongall does not honor: it
    /// carries a critical subpacket whose meaning irongall does not
    /// implement, is malformed where verifying it does not look, carries a
    /// hash prefix that is not its hash's, or embeds in its unhashed area a
    /// back-signature that states an expiration, which the binding does not
    /// cover (see the [module documentation](self)).
    UnhonoredBinding,
    /// The subkey's governing binding rests on a hash the policy does not
    /// accept, or on one shorter than its public-key algorithm allows.
    WeakBinding,
    /// The subkey's governing binding does not grant it the right to sign.
    SubkeyMayNotSign,
    /// The subkey's governing binding carries no back-signature by the
    /// subkey that the policy accepts, so the binding is the primary key's
    /// claim alone.
    MissingBackSignature,
    /// The policy does not accept the subkey.
    WeakSubkey,
    /// The certificate holds more signatures that are not over the part they
    /// are placed with than judging it tries over its other parts: finding
    /// what each is over would take more work than the size of the
    /// certificate's signatures allows, so a restriction its primary key
    /// made might be missed (see the [module documentation](self)).
    UnattributedSignatures,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Reason::TooManySignatures => {
                "the document carries more signatures than the policy verifies"
            }
            Reason::Unverified => "no signature verifies with a key in the keyring",
            Reason::UnsupportedKey => {
                "the signature names as its issuer a key irongall does not verify with"
            }
            Reason::WeakHash => "the signature rests on a hash the policy does not accept",
            Reason::TextSignature => {
                "the signature is a text signature, and the policy accepts only binary ones"
            }
            Reason::Postdated => "the signature is dated after the time it is judged at",
            Reason::BeforeKeyCreation => {
                "the signature is dated before its signing key or its certificate existed"
            }
            Reason::AfterKeyExpiration => {
                "the signature was made after its signing key's authority lapsed"
            }
            Reason::KeyExpired => "the signing key's authority has lapsed",
            Reason::SignatureExpired => "the signature has expired",
            Reason::CertificateRevoked => "the signing key's certificate has been revoked",
            Reason::WeakPrimaryKey => {
                "the signing key's certificate rests on a primary key the policy does not accept"
            }
            Reason::UnhonoredSelfSignature => {
                "the signing key's certificate is governed by a self-signature irongall does not \
                 honor"
            }
            Reason::WeakSelfSignature => {
                "the signing key's certificate is governed by a self-signature, or one is \
                 withdrawn by a revocation, that rests on a hash the policy does not accept"
            }
            Reason::MissingDirectKeySignature => {
                "the signing key's version 6 certificate has no direct-key signature"
            }
            Reason::MissingSelfSignature => {
                "the signing key's certificate has no self-signature in force over its primary key"
            }
            Reason::PrimaryMayNotSign => {
                "the primary key that made the signature is not certified for signing"
            }
            Reason::SubkeyRevoked => {
                "the subkey that made the signature has been revoked by its certificate"
            }
            Reason::UnboundSubkey => {
                "the subkey that made the signature carries no valid binding from its certificate"
            }
            Reason::UnhonoredBinding => {
                "the binding of the subkey that made the signature is one irongall does not honor"
            }
            Reason::WeakBinding => {
                "the binding of the subkey that made the signature rests on a hash the policy \
                 does not accept"
            }
            Reason::SubkeyMayNotSign => {
                "the subkey that made the signature is not certified for signing"
            }
            Reason::MissingBackSignature => {
                "the subkey that made the signature has not counter-signed its binding"
            }
            Reason::WeakSubkey => "the policy does not accept the subkey that made the signature",
            Reason::UnattributedSignatures => {
                "the signing key's certificate holds more signatures out of place than irongall \
                 tries to place"
            }
        })
    }
}

/// What a certificate grants its keys, judged under a policy at a given
/// time: for each key, the [`Window`] in which its signatures are accepted,
/// or the reason none are.
///
/// See the [module documentation](self) for the rules.
#[derive(Debug, Clone)]
pub struct Authority<'a> {
    certificate: &'a Certificate,
    /// When the certificate lapses, or why it grants nothing.
    lapse: Result<Option<u64>, Reason>,
    /// The primary key's standing, then each subkey's, in order.
    standings: Vec<Result<Window, Reason>>,
    primary_user_id: Option<&'a UserId>,
}

impl<'a> Authority<'a> {
    /// Judges `certificate` under `policy` as of `now`, in seconds since the
    /// Unix epoch.
    ///
    /// This verifies the certificate's signatures, each with the key that
    /// would have made it whatever issuer it names: at most one public-key
    /// operation for each signature the certificate holds, over the part it
    /// is placed with, two for a certification revocation that follows a
    /// user ID, which may be over the user ID or over the primary key alone,
    /// and one for each back-signature in a governing subkey binding. The
    /// search for what the signatures that are not over the part they are
    /// placed with are over adds at most one more for each signature, and
    /// hashes at most 128 octets for each octet of them (see the [module
    /// documentation](self)).
    ///
    /// A signature of the primary key's version and algorithm reaches its
    /// public-key operation over the part it is placed with, whatever its
    /// two-octet hash prefix, and everything a signature is hashed over is
    /// public, so anyone can give a signature the prefix that lets it reach
    /// one in the search too. A certificate of uncertain origin, such as a
    /// copy from a keyserver, can therefore make judging it cost time in
    /// proportion to its size. For each megabyte of such signatures, that is
    /// on the order of a second or two under an RSA-2048 or Ed25519 primary
    /// key, and it grows with an RSA key's width and exponent: about 5
    /// seconds under a 4096-bit key and 20 under an 8192-bit key, with the
    /// exponent 65537, and about a minute under an 8192-bit key with the
    /// largest exponent irongall accepts, 2^33 - 1. It can also hold user IDs
    /// added without a signature until the search exceeds its bound, and
    /// grant nothing. [`Keyring::verify`](crate::keyring::Keyring::verify)
    /// judges a certificate only once one of its keys has made a signature
    /// on the document.
    pub fn new(certificate: &'a Certificate, policy: &Policy, now: u64) -> Authority<'a> {
        let statements = Statements::of(certificate, policy);
        let governing = Governing::of(certificate, &statements, policy, now);
        let anchor = anchor(certificate, &governing, policy);
        let primary = anchor.and_then(|lapse| {
            primary_may_sign(&governing)?;
            Ok(Window {
                created: certificate.primary().creation_time(),
                expires: lapse,
            })
        });
        let mut standings = Vec::with_capacity(certificate.subkeys().len().saturating_add(1));
        standings.push(primary);
        standings.extend(certificate.subkeys().iter().zip(&statements.subkeys).map(
            |(subkey, statements)| {
                anchor.and_then(|lapse| {
                    subkey_standing(
                        certificate,
                        subkey,
                        statements.as_deref(),
                        policy,
                        now,
                        lapse,
                    )
                })
            },
        ));
        Authority {
            certificate,
            lapse: anchor,
            standings,
            primary_user_id: governing.primary_user_id(policy),
        }
    }

    /// The certificate judged.
    pub fn certificate(&self) -> &'a Certificate {
        self.certificate
    }

    /// When the certificate itself lapses, in seconds since the Unix epoch:
    /// the earliest of its primary key's expirations and those of the
    /// self-signatures in force over it, or `None` if nothing bounds it.
    /// Every key's window closes by then, whether or not the primary key may
    /// sign.
    ///
    /// # Errors
    ///
    /// The reason the certificate grants nothing, when it does not.
    pub fn lapse(&self) -> Result<Option<u64>, Reason> {
        self.lapse
    }

    /// Each key of the certificate with when its signatures are accepted, or
    /// why none are: the primary key first, then each subkey in the order the
    /// certificate holds them.
    pub fn signers(&self) -> impl Iterator<Item = (&'a PublicKey, Result<Window, Reason>)> + '_ {
        keys(self.certificate).zip(self.standings.iter().copied())
    }

    /// The certificate's primary user ID: of the user IDs whose
    /// certifications are in force, one marked primary; among several, or
    /// where none is marked, one certified over a hash the policy accepts;
    /// among several still, the one certified most recently, or else the
    /// first. `None` if no user ID's certification is in force.
    ///
    /// RFC 9580 §5.2.3.27 leaves the choice to the implementation when no
    /// user ID is marked; this one is stable, so one certificate always
    /// names the same user ID.
    pub fn primary_user_id(&self) -> Option<&'a UserId> {
        self.primary_user_id
    }

    /// The standing of the certificate's key at `index`, in the order of
    /// [`keys`].
    pub(crate) fn standing(&self, index: usize) -> Option<Result<Window, Reason>> {
        self.standings.get(index).copied()
    }
}

/// The keys of a certificate: the primary key, then each subkey in order.
pub(crate) fn keys(certificate: &Certificate) -> impl Iterator<Item = &PublicKey> {
    core::iter::once(certificate.primary()).chain(certificate.subkeys().iter().map(Subkey::key))
}

/// Judges a signature over a document, made by a key whose standing is
/// `standing`: whether it is accepted (see the
/// [module documentation](self)).
pub(crate) fn accept(
    standing: Result<Window, Reason>,
    signature: &Signature,
    policy: &Policy,
    now: u64,
) -> Result<(), Reason> {
    let window = standing?;
    if !policy.accepts_hash_of(signature) {
        return Err(Reason::WeakHash);
    }
    if signature.signature_type() == SignatureType::TEXT && !policy.text_signatures {
        return Err(Reason::TextSignature);
    }
    let made = u64::from(signature.creation_time());
    if made > policy.horizon(now) {
        return Err(Reason::Postdated);
    }
    if made < u64::from(window.created) {
        return Err(Reason::BeforeKeyCreation);
    }
    if !window.contains(made) {
        return Err(Reason::AfterKeyExpiration);
    }
    if window.expires.is_some_and(|expires| now >= expires) {
        return Err(Reason::KeyExpired);
    }
    if policy.fresh && signature_expires(signature).is_some_and(|expires| now >= expires) {
        return Err(Reason::SignatureExpired);
    }
    Ok(())
}

/// When a signature expires, in seconds since the Unix epoch, or `None` if
/// it does not.
fn signature_expires(signature: &Signature) -> Option<u64> {
    signature
        .expiration_time()
        .map(|seconds| u64::from(signature.creation_time()).saturating_add(u64::from(seconds)))
}

/// When a self-signature says the key it is over, created at `created`,
/// expires, or `None` if it does not say.
fn key_expires(created: u32, signature: &Signature) -> Option<u64> {
    signature
        .key_expiration_time()
        .map(|seconds| u64::from(created).saturating_add(u64::from(seconds)))
}

/// The earliest of `times`, or `None` if none is bounded.
fn earliest(times: impl IntoIterator<Item = Option<u64>>) -> Option<u64> {
    times.into_iter().flatten().min()
}

/// The signatures that govern among `candidates`, statements the primary
/// key made over one part of its certificate: of those dated within `made`,
/// the newest, with every other made in the same second. Empty if none
/// qualifies.
///
/// Packet order is covered by no signature, so it decides nothing: every
/// signature tied as the newest governs, and the caller combines what they
/// state restrictively.
fn govern<'s>(
    candidates: impl Iterator<Item = Statement<'s>>,
    made: &RangeInclusive<u64>,
) -> Vec<Statement<'s>> {
    let mut newest: Vec<Statement<'s>> = Vec::new();
    for (signature, honored) in candidates {
        let created = signature.creation_time();
        if !made.contains(&u64::from(created)) {
            continue;
        }
        let held = newest.first().map(|(held, _)| held.creation_time());
        match held.map(|held| held.cmp(&created)) {
            Some(Ordering::Greater) => continue,
            Some(Ordering::Less) => newest.clear(),
            Some(Ordering::Equal) | None => {}
        }
        newest.push((signature, honored));
    }
    newest
}

/// The statements among `statements` whose type `signature_type` accepts.
fn of_type<'s>(
    statements: &[Statement<'s>],
    signature_type: impl Fn(SignatureType) -> bool,
) -> impl Iterator<Item = Statement<'s>> {
    statements
        .iter()
        .copied()
        .filter(move |(signature, _)| signature_type(signature.signature_type()))
}

/// Whether `signature_type` is a certification of a user ID (0x10 to 0x13),
/// as opposed to a revocation of one.
fn is_certification(signature_type: SignatureType) -> bool {
    matches!(
        signature_type,
        SignatureType::GENERIC_CERTIFICATION
            | SignatureType::PERSONA_CERTIFICATION
            | SignatureType::CASUAL_CERTIFICATION
            | SignatureType::POSITIVE_CERTIFICATION
    )
}

/// The certification revocations among `statements`.
fn certification_revocations<'s>(
    statements: &[Statement<'s>],
) -> impl Iterator<Item = Statement<'s>> {
    of_type(statements, |signature_type| {
        signature_type == SignatureType::CERTIFICATION_REVOCATION
    })
}

/// How a certification revocation withdraws the self-signatures over its
/// object, ordered from the least sound to the most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Withdrawal {
    /// It is one irongall does not honor, so what it withdraws, irongall
    /// cannot tell.
    Unhonored,
    /// It rests on a hash on which a self-signature made when it was may not
    /// grant ([`Policy::accepts_self_signature_hash`]), so it may not
    /// withdraw one either: a withdrawal can lift a restriction.
    Weak,
    /// It withdraws them.
    Sound,
}

/// How the primary key has withdrawn what it stated over an object at
/// `created`, with one of `revocations`, its certification revocations over
/// the object, no older: the soundest such withdrawal, or `None` if none
/// withdraws it.
///
/// Any certification revocation counts, whenever it was made, provided it
/// is no older than what it revokes: one made earlier cannot withdraw it,
/// since the self-signature re-certifies what it revoked.
fn withdrawal<'s>(
    created: u32,
    revocations: impl Iterator<Item = Statement<'s>>,
    policy: &Policy,
) -> Option<Withdrawal> {
    revocations
        .filter(|(revocation, _)| revocation.creation_time() >= created)
        .map(|(revocation, honored)| {
            if !honored {
                Withdrawal::Unhonored
            } else if !policy.accepts_self_signature_hash(revocation) {
                Withdrawal::Weak
            } else {
                Withdrawal::Sound
            }
        })
        .max()
}

/// A governing self-signature over the primary key that is in force.
#[derive(Debug, Clone, Copy)]
struct SelfSignature<'a> {
    signature: &'a Signature,
    /// Whether irongall honors it, and the soundest certification revocation
    /// that withdraws it, if one does, is one irongall honors.
    honored: bool,
    /// Whether it rests on a hash on which a self-signature made when it was
    /// may not grant ([`Policy::accepts_self_signature_hash`]), or the
    /// soundest certification revocation that withdraws it rests on such a
    /// hash. It grants nothing, and refuses the certificate.
    weak: bool,
    /// The user ID it certifies, or `None` for a direct-key signature.
    user_id: Option<&'a UserId>,
}

impl<'a> SelfSignature<'a> {
    /// Of `governing`, the self-signatures that govern one object, `user_id`
    /// or the primary key alone, those in force as of `now`: none if the
    /// primary key has withdrawn them, with one of its certification
    /// `revocations` over the object, and otherwise those that have not
    /// expired.
    ///
    /// Withdrawn by a revocation irongall does not honor, they stay in force
    /// unhonored, which refuses the certificate: what such a revocation
    /// withdraws, irongall cannot tell. Withdrawn only by one over a hash on
    /// which they could not grant, they stay in force as weak, which refuses
    /// the certificate too. One that `policy` does not accept the hash of
    /// stays in force as weak as well.
    fn in_force(
        governing: Vec<Statement<'a>>,
        user_id: Option<&'a UserId>,
        revocations: impl Iterator<Item = Statement<'a>>,
        policy: &Policy,
        now: u64,
    ) -> impl Iterator<Item = SelfSignature<'a>> {
        let withdrawn = governing
            .first()
            .and_then(|(signature, _)| withdrawal(signature.creation_time(), revocations, policy));
        governing
            .into_iter()
            .filter(move |_| withdrawn != Some(Withdrawal::Sound))
            .filter(move |(signature, _)| {
                signature_expires(signature).is_none_or(|expires| now < expires)
            })
            .map(move |(signature, honored)| SelfSignature {
                signature,
                honored: honored && withdrawn != Some(Withdrawal::Unhonored),
                weak: !policy.accepts_self_signature_hash(signature)
                    || withdrawn == Some(Withdrawal::Weak),
                user_id,
            })
    }
}

/// What a certificate's primary key has said about itself, as of a time:
/// the self-signatures in force over it, and whether it has revoked itself.
struct Governing<'a> {
    /// The governing self-signatures in force, over the primary key alone
    /// and over each user ID.
    in_force: Vec<SelfSignature<'a>>,
    /// Whether the primary key has made a key revocation.
    revoked: bool,
    /// Whether finding what the primary key's statements are over took more
    /// than judging a certificate may spend, so that some may be missing:
    /// see [`Statements::of`].
    unbounded: bool,
}

impl<'a> Governing<'a> {
    fn of(
        certificate: &'a Certificate,
        statements: &Statements<'a>,
        policy: &Policy,
        now: u64,
    ) -> Governing<'a> {
        let primary = certificate.primary();
        let made = u64::from(primary.creation_time())..=policy.horizon(now);
        let over_key = &statements.key;
        let revoked = of_type(over_key, |signature_type| {
            signature_type == SignatureType::KEY_REVOCATION
        })
        .next()
        .is_some();
        let direct = govern(
            of_type(over_key, |signature_type| {
                signature_type == SignatureType::DIRECT_KEY
            }),
            &made,
        );
        let mut in_force: Vec<_> = SelfSignature::in_force(
            direct,
            None,
            certification_revocations(over_key),
            policy,
            now,
        )
        .collect();
        for (user_id, over_user_id) in certificate.user_ids().iter().zip(&statements.user_ids) {
            let governing = govern(of_type(over_user_id, is_certification), &made);
            in_force.extend(SelfSignature::in_force(
                governing,
                Some(user_id),
                certification_revocations(over_user_id),
                policy,
                now,
            ));
        }
        Governing {
            in_force,
            revoked,
            unbounded: statements.unbounded,
        }
    }

    /// See [`Authority::primary_user_id`]. `None` if the primary key's
    /// statements may not all have been found.
    fn primary_user_id(&self, policy: &Policy) -> Option<&'a UserId> {
        if self.unbounded {
            return None;
        }
        let mut best: Option<(&UserId, (bool, bool, u32))> = None;
        for governing in &self.in_force {
            let Some(user_id) = governing.user_id else {
                continue;
            };
            if !governing.honored || governing.weak {
                continue;
            }
            let certification = governing.signature;
            let rank = (
                certification.is_primary_user_id(),
                policy.accepts_hash_of(certification),
                certification.creation_time(),
            );
            if best.is_none_or(|(_, held)| rank > held) {
                best = Some((user_id, rank));
            }
        }
        best.map(|(user_id, _)| user_id)
    }
}

/// What every key of a certificate rests on: the certificate's own standing,
/// and when its primary key's authority lapses, or the reason the
/// certificate grants nothing.
fn anchor(
    certificate: &Certificate,
    governing: &Governing<'_>,
    policy: &Policy,
) -> Result<Option<u64>, Reason> {
    let primary = certificate.primary();
    if governing.revoked {
        return Err(Reason::CertificateRevoked);
    }
    if !policy.accepts_key(primary) {
        return Err(Reason::WeakPrimaryKey);
    }
    if governing.unbounded {
        return Err(Reason::UnattributedSignatures);
    }
    let in_force = &governing.in_force;
    if in_force.iter().any(|governing| !governing.honored) {
        return Err(Reason::UnhonoredSelfSignature);
    }
    if in_force.iter().any(|governing| governing.weak) {
        return Err(Reason::WeakSelfSignature);
    }
    if primary.version() == Version::V6
        && in_force.iter().all(|governing| governing.user_id.is_some())
    {
        return Err(Reason::MissingDirectKeySignature);
    }
    if in_force.is_empty() {
        return Err(Reason::MissingSelfSignature);
    }
    let created = primary.creation_time();
    Ok(earliest(in_force.iter().flat_map(|governing| {
        [
            key_expires(created, governing.signature),
            signature_expires(governing.signature),
        ]
    })))
}

/// Whether the self-signatures in force grant the primary key the right to
/// sign: one states key flags, and every one that states key flags grants
/// signing.
fn primary_may_sign(governing: &Governing<'_>) -> Result<(), Reason> {
    let mut stated = governing
        .in_force
        .iter()
        .filter_map(|governing| governing.signature.key_flags())
        .peekable();
    if stated.peek().is_some() && stated.all(|flags| flags.may_sign()) {
        Ok(())
    } else {
        Err(Reason::PrimaryMayNotSign)
    }
}

/// The window in which `subkey`'s signatures are accepted, given that its
/// primary key's authority lapses at `lapse`, or the reason none are.
/// `statements` are the primary key's statements over the subkey, or `None`
/// if the policy refuses the subkey, over which none is verified (see
/// [`Statements::of`]).
fn subkey_standing(
    certificate: &Certificate,
    subkey: &Subkey,
    statements: Option<&[Statement<'_>]>,
    policy: &Policy,
    now: u64,
    lapse: Option<u64>,
) -> Result<Window, Reason> {
    let primary = certificate.primary();
    let key = subkey.key();
    let Some(statements) = statements else {
        return Err(Reason::WeakSubkey);
    };
    if of_type(statements, |signature_type| {
        signature_type == SignatureType::SUBKEY_REVOCATION
    })
    .next()
    .is_some()
    {
        return Err(Reason::SubkeyRevoked);
    }
    // A signature claiming to predate either key it speaks about cannot have
    // been made when it says.
    let created = primary.creation_time().max(key.creation_time());
    let made = u64::from(created)..=policy.horizon(now);
    let bindings = govern(
        of_type(statements, |signature_type| {
            signature_type == SignatureType::SUBKEY_BINDING
        }),
        &made,
    );
    if bindings.is_empty() {
        return Err(Reason::UnboundSubkey);
    }
    if bindings.iter().any(|&(_, honored)| !honored) {
        return Err(Reason::UnhonoredBinding);
    }
    // The flags first: a binding that does not grant signing refuses the
    // subkey whatever its hash, and saying so names the reason that would
    // stand were the hash accepted.
    if !bindings
        .iter()
        .all(|(binding, _)| binding.key_flags().is_some_and(|flags| flags.may_sign()))
    {
        return Err(Reason::SubkeyMayNotSign);
    }
    if !bindings
        .iter()
        .all(|(binding, _)| policy.accepts_hash_of(binding))
    {
        return Err(Reason::WeakBinding);
    }
    let mut expires = lapse;
    for (binding, _) in bindings {
        let consent = back_signature_lapse(binding, primary, key, &made, policy)?;
        expires = earliest([
            expires,
            key_expires(key.creation_time(), binding),
            signature_expires(binding),
            consent,
        ]);
    }
    Ok(Window { created, expires })
}

/// When the consent a binding's back-signatures give lapses, or `None` if it
/// does not; [`Reason::UnhonoredBinding`] if one that counts states an
/// expiration the binding does not cover; or
/// [`Reason::MissingBackSignature`] if the binding embeds none that counts.
///
/// A back-signature counts if it is a primary key binding (0x19) that
/// verifies as `subkey`'s over the two keys, rests on a hash the policy
/// accepts, and is dated within `made`: no earlier than the creation of the
/// later of the two keys, since a signature claiming to predate the keys it
/// speaks about cannot have been made when it says, and no later than the
/// time judged at and the clock skew, since consent dated later is not yet
/// given. The back-signature is the subkey holder's consent to the binding,
/// without which any certificate could adopt a signing key it does not hold
/// and present that key's signatures as its own (RFC 9580 §5.2.1.8). Its
/// expiration bounds the consent, and where several count, the earliest
/// expiration governs, so one added beside another extends nothing. An
/// expiration holds only where the binding covers the back-signature, in
/// its hashed area, so a binding whose back-signature in the unhashed area
/// states one is refused rather than bounded by it (see [the
/// back-signature's expiration](self#a-back-signatures-expiration)).
fn back_signature_lapse(
    binding: &Signature,
    primary: &PublicKey,
    subkey: &PublicKey,
    made: &RangeInclusive<u64>,
    policy: &Policy,
) -> Result<Option<u64>, Reason> {
    let subject = Subject::Subkey { primary, subkey };
    // A back-signature only grants, so unlike a certificate's other
    // statements, it counts only if it verifies outright.
    let counts = |back: &&Signature| {
        back.signature_type() == SignatureType::PRIMARY_KEY_BINDING
            && made.contains(&u64::from(back.creation_time()))
            && policy.accepts_hash_of(back)
            && back.verify(subkey, subject).is_ok()
    };
    let (covered, uncovered) = binding.embedded_by_area();
    let mut counted = false;
    for back in uncovered.iter().filter(counts) {
        if signature_expires(back).is_some() {
            return Err(Reason::UnhonoredBinding);
        }
        counted = true;
    }
    let mut lapses = covered
        .iter()
        .filter(counts)
        .map(signature_expires)
        .peekable();
    if !counted && lapses.peek().is_none() {
        return Err(Reason::MissingBackSignature);
    }
    Ok(earliest(lapses))
}
