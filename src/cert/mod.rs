//! Certificates (RFC 9580 §10.1): a primary key with the user IDs, subkeys,
//! and signatures that travel with it.
//!
//! [`certificates`] reads a keyring: one or more certificates, one after
//! another, each beginning at a Public Key packet. Assembly places every
//! signature with what it is over, and verifies nothing; checking a signature
//! is [`Signature::verify`], with the [`Subject`] its place in the certificate
//! gives it:
//!
//! ```
//! use irongall::signature::Subject;
//! use irongall::{armor, cert};
//!
//! // The version 6 certificate of RFC 9580 Appendix A.3.
//! let armored = "\
//! -----BEGIN PGP PUBLIC KEY BLOCK-----
//!
//! xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
//! GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
//! KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
//! gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
//! QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
//! +eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
//! BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
//! j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
//! I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
//! -----END PGP PUBLIC KEY BLOCK-----
//! ";
//! let data = armor::decode(armored.as_bytes())?.into_data();
//! for certificate in cert::certificates(&data) {
//!     let certificate = certificate?;
//!     let primary = certificate.primary();
//!     // Its direct-key signature, over the primary key.
//!     for signature in certificate.primary_signatures() {
//!         signature.verify(primary, Subject::Key(primary))?;
//!     }
//!     // Its subkey's binding, over the primary key and the subkey.
//!     for subkey in certificate.subkeys() {
//!         let subject = Subject::Subkey { primary, subkey: subkey.key() };
//!         for signature in subkey.signatures() {
//!             signature.verify(primary, subject)?;
//!         }
//!     }
//! }
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Assembly
//!
//! Every packet after the primary key is placed by where it is:
//!
//! - The signatures after the primary key, before any user ID or subkey, are
//!   over the primary key: [`Certificate::primary_signatures`].
//! - A User ID packet begins a [`UserId`], and the signatures after it are
//!   over it and the primary key. One that repeats a user ID the certificate
//!   already holds continues that one instead.
//! - A Public Subkey packet begins a [`Subkey`], and the signatures after it
//!   are over it and the primary key. One that repeats a subkey the
//!   certificate already holds, with the same packet body, continues that
//!   one instead.
//! - A User Attribute packet begins something irongall does not read, and
//!   the signatures after it are passed over with it.
//! - Trust, Marker, and Padding packets, and packets of a type that is unknown
//!   and not critical (RFC 9580 §4.3), are passed over wherever they are.
//!
//! A direct-key signature and a key revocation are over the primary key alone,
//! and are placed with the primary key wherever they appear, even after
//! something passed over: passed over, a revocation would leave a revoked key
//! in force. So is a certification revocation, which revokes a certification
//! of a user ID or a direct-key signature (RFC 9580 §5.2.1.13), except after
//! a user ID. There it is placed with the user ID, since it may be over
//! either, and the [`policy`](crate::policy) weighs it as both.
//!
//! Each user ID and each subkey is held once, with every signature over it,
//! because what a certificate grants is judged from all its maker has said
//! about each: held twice, a repetition with only an older signature over it
//! would be judged apart from the revocation or the newer signature that
//! supersedes it, and would grant what they withdrew. Two subkeys whose
//! packets differ are different keys, even if they share a fingerprint,
//! since every signature over a subkey is made over its packet.
//!
//! A keyring may hold one certificate more than once, such as copies
//! obtained at different times: [`certificates`] reads each as it is, and
//! [`Keyring::new`](crate::keyring::Keyring::new) combines them.
//!
//! Where a signature is placed is a guess at what it is over, since no
//! signature covers the order of a certificate's packets, and judging a
//! certificate does not rely on it: the [`policy`](crate::policy) counts
//! each of the primary key's statements over the part it verifies over,
//! wherever it is placed. So a certification, subkey binding, or subkey
//! revocation that cannot be placed with a part of its kind, because it
//! follows something passed over or its type does not belong where it is,
//! is kept with the certificate, though no part lists it, and is weighed
//! there.
//!
//! # What is passed over, and what is refused
//!
//! A part of a certificate irongall cannot use is passed over, and the
//! certificate read without it; [`Certificate::skipped`] keeps the reasons.
//! RFC 9580 §5.2.5 requires this of a signature that cannot be read. The parts
//! passed over are:
//!
//! - a signature that does not read;
//! - a signature of a type that does not belong where it is, such as a subkey
//!   binding after a user ID;
//! - a subkey that does not read, or whose version is not the primary key's
//!   (RFC 9580 §10.1.1 and §10.1.3), together with its signatures;
//! - a user ID longer than 2048 octets, together with its signatures. Each
//!   certification of a user ID is verified over the whole of it, so without
//!   a bound, judging a certificate would cost the length of a user ID times
//!   the number of signatures over it. GnuPG reads no longer user ID either.
//!
//! A certificate is refused whole, and the keyring read on from the next
//! certificate, when it does not begin with a Public Key packet, when its
//! primary key does not read, or when it holds a packet no certificate holds:
//! secret key material, a message, or a packet of an unknown critical type
//! (RFC 9580 §4.3). A Secret Key packet begins a certificate of its own, so a
//! secret key exported beside public ones refuses only itself.
//!
//! A failure in the packet framing ends the keyring, since nothing after it can
//! be located, and refuses the certificate it was found in: a certificate cut
//! short might be missing its revocations.
//!
//! [`Signature::verify`]: crate::signature::Signature::verify
//! [`Subject`]: crate::signature::Subject

#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::iter::FusedIterator;

use crate::key::{Fingerprint, PublicKey};
use crate::packet::{self, Packet, PacketError, PacketErrorKind, Packets, Tag};
use crate::signature::{Signature, SignatureType};

/// A certificate, also called a transferable public key: a primary key, the
/// signatures over it, and its user IDs and subkeys with theirs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    primary: PublicKey,
    primary_signatures: Signatures,
    user_ids: Vec<UserId>,
    subkeys: Vec<Subkey>,
    /// The certifications, subkey bindings, and subkey revocations that are
    /// not placed with a part of their kind: those after something passed
    /// over, and those where their type does not belong. Judging the
    /// certificate tries each over every part it may be over (see the
    /// [module documentation](self)).
    unplaced: Signatures,
    skipped: Vec<PacketError>,
}

impl Certificate {
    /// The primary key.
    pub fn primary(&self) -> &PublicKey {
        &self.primary
    }

    /// The signatures over the primary key alone, in the order they appear:
    /// direct-key signatures (0x1F), key revocations (0x20), and
    /// certification revocations (0x30), which revoke a direct-key signature,
    /// wherever they appear but after a user ID (see the
    /// [module documentation](self)).
    pub fn primary_signatures(&self) -> &[Signature] {
        &self.primary_signatures.honored
    }

    /// The signatures over the primary key alone that irongall does not
    /// honor; see [`Signatures::unhonored`].
    pub(crate) fn unhonored_primary_signatures(&self) -> &[Signature] {
        &self.primary_signatures.unhonored
    }

    /// The user IDs, each once, in the order they first appear.
    pub fn user_ids(&self) -> &[UserId] {
        &self.user_ids
    }

    /// The subkeys, each once, in the order they first appear.
    pub fn subkeys(&self) -> &[Subkey] {
        &self.subkeys
    }

    /// The parts of the certificate that were passed over, each with the
    /// reason: signatures and subkeys that do not read, signatures that do
    /// not belong where they are, and subkeys of the wrong version.
    pub fn skipped(&self) -> &[PacketError] {
        &self.skipped
    }

    /// The certifications, subkey bindings, and subkey revocations placed
    /// with no part, those irongall honors first: see
    /// [`Certificate::unplaced`].
    pub(crate) fn unplaced_signatures(&self) -> (&[Signature], &[Signature]) {
        (&self.unplaced.honored, &self.unplaced.unhonored)
    }
}

/// A user ID and the signatures over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserId {
    value: Vec<u8>,
    signatures: Signatures,
}

impl UserId {
    /// The user ID: the body of its User ID packet, at most 2048 octets. RFC
    /// 9580 §5.11 says it is UTF-8; it is not checked.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// The signatures over the user ID and the primary key, in the order they
    /// appear: certifications (0x10 to 0x13), and certification revocations
    /// (0x30), each of which revokes a certification of the user ID or a
    /// direct-key signature over the primary key alone.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures.honored
    }

    /// The signatures over the user ID that irongall does not honor; see
    /// [`Signatures::unhonored`].
    pub(crate) fn unhonored_signatures(&self) -> &[Signature] {
        &self.signatures.unhonored
    }
}

/// A subkey and the signatures over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subkey {
    key: PublicKey,
    signatures: Signatures,
}

impl Subkey {
    /// The subkey.
    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The signatures over the subkey and the primary key, in the order they
    /// appear: subkey bindings (0x18), and subkey revocations (0x28).
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures.honored
    }

    /// The signatures over the subkey that irongall does not honor; see
    /// [`Signatures::unhonored`].
    pub(crate) fn unhonored_signatures(&self) -> &[Signature] {
        &self.signatures.unhonored
    }
}

/// The signatures placed over one part of a certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Signatures {
    /// Those that read.
    honored: Vec<Signature>,
    /// Those that read only when what irongall cannot honor is overlooked
    /// ([`Signature::from_packet_unhonored`]): a hashed subpacket marked
    /// critical whose meaning irongall does not implement, a malformed
    /// subpacket, or an unhashed area or embedded signature that does not
    /// read. The certificate's [`skipped`](Certificate::skipped) records
    /// each as passed over, and nothing may act on what one grants. Judging
    /// the certificate weighs them in one direction only: a revocation among
    /// them that verifies still revokes, and a self-signature among them
    /// that verifies and would govern keeps an older one from governing in
    /// its place, since passing over either would leave in force what its
    /// maker withdrew.
    unhonored: Vec<Signature>,
}

/// Reads `input` as a keyring: a sequence of certificates.
///
/// The iterator yields each certificate in turn, or the reason it was
/// refused, and ends at the end of the input or after a failure in the packet
/// framing, which it yields.
pub fn certificates(input: &[u8]) -> Certificates<'_> {
    Certificates {
        packets: packet::packets(input),
        next: None,
    }
}

/// The certificates of a keyring; see [`certificates`].
#[derive(Debug, Clone)]
pub struct Certificates<'a> {
    packets: Packets<'a>,
    /// What ended the last certificate, and begins the next one: a Public Key
    /// or Secret Key packet, or a framing failure.
    next: Option<Result<Packet<'a>, PacketError>>,
}

impl<'a> Certificates<'a> {
    /// Passes over packets up to the next one that begins a certificate,
    /// which is kept, as is a framing failure.
    fn skip_to_next(&mut self) {
        for packet in self.packets.by_ref() {
            if !matches!(&packet, Ok(packet) if !begins_certificate(packet.tag())) {
                self.next = Some(packet);
                return;
            }
        }
    }
}

impl Iterator for Certificates<'_> {
    type Item = Result<Certificate, PacketError>;

    fn next(&mut self) -> Option<Self::Item> {
        let first = loop {
            match self.next.take().or_else(|| self.packets.next())? {
                Ok(packet) if passed_over(packet.tag()) => continue,
                Ok(packet) => break packet,
                Err(error) => return Some(Err(error)),
            }
        };
        if first.tag() != Tag::PUBLIC_KEY {
            self.skip_to_next();
            return Some(Err(first.error(PacketErrorKind::UnexpectedType)));
        }
        let mut assembly = match PublicKey::from_packet(&first) {
            Ok(primary) => Assembly::new(primary),
            Err(error) => {
                self.skip_to_next();
                return Some(Err(error));
            }
        };
        for packet in self.packets.by_ref() {
            match packet {
                Ok(packet) if begins_certificate(packet.tag()) => {
                    self.next = Some(Ok(packet));
                    break;
                }
                Ok(packet) => {
                    if let Err(error) = assembly.add(&packet) {
                        self.skip_to_next();
                        return Some(Err(error));
                    }
                }
                // A certificate cut short might lack its revocations.
                Err(error) => return Some(Err(error)),
            }
        }
        Some(Ok(assembly.certificate))
    }
}

impl FusedIterator for Certificates<'_> {}

/// `certificates`, with those of the same primary key combined into one, at
/// the place of the first: see [`Keyring::new`](crate::keyring::Keyring::new).
///
/// Two primary keys are the same if their packets' bodies are, as two
/// subkeys are within a certificate.
pub(crate) fn combine(certificates: impl IntoIterator<Item = Certificate>) -> Vec<Certificate> {
    let mut combined: Vec<Assembly> = Vec::new();
    let mut primaries: BTreeMap<Fingerprint, Vec<usize>> = BTreeMap::new();
    for certificate in certificates {
        let indexes = primaries
            .entry(certificate.primary.fingerprint())
            .or_default();
        let held = indexes.iter().copied().find(|&index| {
            combined
                .get(index)
                .is_some_and(|held| held.certificate.primary == certificate.primary)
        });
        match held.and_then(|index| combined.get_mut(index)) {
            Some(held) => held.combine(certificate),
            None => {
                indexes.push(combined.len());
                combined.push(Assembly::resume(certificate));
            }
        }
    }
    combined
        .into_iter()
        .map(|assembly| assembly.certificate)
        .collect()
}

/// The longest user ID a certificate is read with, in octets; a longer one is
/// passed over (see the [module documentation](self)).
const MAXIMUM_USER_ID_LENGTH: usize = 2048;

/// Whether a packet of type `tag` begins a certificate: a Public Key packet,
/// or a Secret Key packet, which begins a transferable secret key (RFC 9580
/// §10.2).
fn begins_certificate(tag: Tag) -> bool {
    tag == Tag::PUBLIC_KEY || tag == Tag::SECRET_KEY
}

/// Whether a packet of type `tag` is passed over wherever it is in a
/// keyring: a Trust packet, in which a keyring records its owner's trust in
/// a key (RFC 9580 §5.10), or one passed over in any sequence.
fn passed_over(tag: Tag) -> bool {
    tag == Tag::TRUST || tag.is_passed_over()
}

/// What the signatures read next are placed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// The primary key, before any user ID or subkey.
    Primary,
    /// The user ID at this index: the last one read, or the one it repeats.
    UserId(usize),
    /// The subkey at this index: the last one read, or the one it repeats.
    Subkey(usize),
    /// Something passed over: a user attribute, a user ID that is too long,
    /// or a subkey that does not read or is of the wrong version.
    PassedOver,
}

/// A certificate being assembled, packet by packet, or combined with another
/// of the same primary key.
struct Assembly {
    certificate: Certificate,
    place: Place,
    /// Where each user ID is in the certificate, by its value.
    user_ids: BTreeMap<Vec<u8>, usize>,
    /// Where the subkeys of each fingerprint are in the certificate: one,
    /// unless keys whose packets differ share a fingerprint.
    subkeys: BTreeMap<Fingerprint, Vec<usize>>,
}

impl Assembly {
    fn new(primary: PublicKey) -> Assembly {
        Assembly::resume(Certificate {
            primary,
            primary_signatures: Signatures::default(),
            user_ids: Vec::new(),
            subkeys: Vec::new(),
            unplaced: Signatures::default(),
            skipped: Vec::new(),
        })
    }

    /// Resumes assembling `certificate`, whose user IDs and subkeys are each
    /// held once.
    fn resume(certificate: Certificate) -> Assembly {
        let Certificate {
            primary,
            primary_signatures,
            user_ids,
            subkeys,
            unplaced,
            skipped,
        } = certificate;
        let mut assembly = Assembly {
            certificate: Certificate {
                primary,
                primary_signatures,
                user_ids: Vec::with_capacity(user_ids.len()),
                subkeys: Vec::with_capacity(subkeys.len()),
                unplaced,
                skipped,
            },
            place: Place::Primary,
            user_ids: BTreeMap::new(),
            subkeys: BTreeMap::new(),
        };
        assembly.take(user_ids, subkeys);
        assembly.place = Place::Primary;
        assembly
    }

    /// Combines `other`, a certificate of the same primary key, into the
    /// certificate, as though their packets had been read one after the
    /// other: its signatures over the primary key with the certificate's,
    /// and those over each of its user IDs and subkeys with those over the
    /// same user ID or subkey, which is added if the certificate lacks it.
    fn combine(&mut self, other: Certificate) {
        self.place = Place::Primary;
        self.extend(other.primary_signatures);
        self.take(other.user_ids, other.subkeys);
        let unplaced = &mut self.certificate.unplaced;
        unplaced.honored.extend(other.unplaced.honored);
        unplaced.unhonored.extend(other.unplaced.unhonored);
        self.certificate.skipped.extend(other.skipped);
        self.place = Place::PassedOver;
    }

    /// Places `user_ids` and `subkeys`, with their signatures, as though
    /// their packets had been read.
    fn take(&mut self, user_ids: Vec<UserId>, subkeys: Vec<Subkey>) {
        for user_id in user_ids {
            self.user_id(user_id.value);
            self.extend(user_id.signatures);
        }
        for subkey in subkeys {
            self.subkey(subkey.key);
            self.extend(subkey.signatures);
        }
    }

    /// Places the next packet, or refuses the certificate for it.
    fn add(&mut self, packet: &Packet<'_>) -> Result<(), PacketError> {
        let certificate = &mut self.certificate;
        match packet.tag() {
            Tag::SIGNATURE => self.add_signature(packet),
            Tag::USER_ID if packet.body().len() > MAXIMUM_USER_ID_LENGTH => {
                certificate
                    .skipped
                    .push(packet.error(PacketErrorKind::UserIdTooLong));
                self.place = Place::PassedOver;
            }
            Tag::USER_ID => self.user_id(packet.body().to_vec()),
            Tag::PUBLIC_SUBKEY => {
                let key = PublicKey::from_packet(packet).and_then(|key| {
                    if key.version() == certificate.primary.version() {
                        Ok(key)
                    } else {
                        Err(packet.error(PacketErrorKind::SubkeyVersion))
                    }
                });
                match key {
                    Ok(key) => self.subkey(key),
                    Err(error) => {
                        certificate.skipped.push(error);
                        self.place = Place::PassedOver;
                    }
                }
            }
            Tag::USER_ATTRIBUTE => self.place = Place::PassedOver,
            tag if passed_over(tag) => {}
            _ => return Err(packet.error(PacketErrorKind::UnexpectedType)),
        }
        Ok(())
    }

    /// Places what follows with the user ID `value`: the one the certificate
    /// holds already, or else a new one.
    fn user_id(&mut self, value: Vec<u8>) {
        let user_ids = &mut self.certificate.user_ids;
        let index = *self.user_ids.entry(value).or_insert_with_key(|value| {
            let index = user_ids.len();
            user_ids.push(UserId {
                value: value.clone(),
                signatures: Signatures::default(),
            });
            index
        });
        self.place = Place::UserId(index);
    }

    /// Places what follows with the subkey `key`: the one the certificate
    /// holds already, read from the same packet body, or else a new one.
    fn subkey(&mut self, key: PublicKey) {
        let subkeys = &mut self.certificate.subkeys;
        let indexes = self.subkeys.entry(key.fingerprint()).or_default();
        let held = indexes
            .iter()
            .copied()
            .find(|&index| subkeys.get(index).is_some_and(|held| held.key == key));
        let index = held.unwrap_or_else(|| {
            let index = subkeys.len();
            indexes.push(index);
            subkeys.push(Subkey {
                key,
                signatures: Signatures::default(),
            });
            index
        });
        self.place = Place::Subkey(index);
    }

    /// The signatures placed with `place`, or `None` for something passed
    /// over, whose signatures go with it.
    fn signatures(&mut self, place: Place) -> Option<&mut Signatures> {
        let certificate = &mut self.certificate;
        match place {
            Place::Primary => Some(&mut certificate.primary_signatures),
            Place::UserId(index) => certificate
                .user_ids
                .get_mut(index)
                .map(|user_id| &mut user_id.signatures),
            Place::Subkey(index) => certificate
                .subkeys
                .get_mut(index)
                .map(|subkey| &mut subkey.signatures),
            Place::PassedOver => None,
        }
    }

    /// Adds `signatures` to those placed where the last packet put them.
    fn extend(&mut self, signatures: Signatures) {
        if let Some(placed) = self.signatures(self.place) {
            placed.honored.extend(signatures.honored);
            placed.unhonored.extend(signatures.unhonored);
        }
    }

    /// Places a signature with what it is over, or passes over it.
    ///
    /// A signature refused only for what irongall cannot honor is still
    /// placed, apart from the others: see [`Signatures::unhonored`]. A
    /// certification, subkey binding, or subkey revocation that cannot be
    /// placed with a part of its kind is kept unplaced (see
    /// [`Certificate::unplaced`]).
    fn add_signature(&mut self, packet: &Packet<'_>) {
        let certificate = &mut self.certificate;
        let (signature, refusal) = match Signature::from_packet(packet) {
            Ok(signature) => (signature, None),
            Err(error) => match Signature::from_packet_unhonored(packet) {
                Ok(signature) => (signature, Some(error)),
                Err(_) => {
                    // The signatures of something passed over go with it.
                    if self.place != Place::PassedOver {
                        certificate.skipped.push(error);
                    }
                    return;
                }
            },
        };
        let honored = refusal.is_none();
        // Matched first, so that one placed with the primary key wherever it
        // is escapes something passed over whether it is honored or not.
        let place = match (signature.signature_type(), self.place) {
            (SignatureType::DIRECT_KEY | SignatureType::KEY_REVOCATION, _)
            | (
                SignatureType::CERTIFICATION_REVOCATION,
                Place::Primary | Place::Subkey(_) | Place::PassedOver,
            ) => Some(Place::Primary),
            (
                SignatureType::GENERIC_CERTIFICATION
                | SignatureType::PERSONA_CERTIFICATION
                | SignatureType::CASUAL_CERTIFICATION
                | SignatureType::POSITIVE_CERTIFICATION
                | SignatureType::CERTIFICATION_REVOCATION,
                place @ Place::UserId(_),
            )
            | (
                SignatureType::SUBKEY_BINDING | SignatureType::SUBKEY_REVOCATION,
                place @ Place::Subkey(_),
            ) => Some(place),
            // The signatures of something passed over go with it, and are
            // not recorded as passed over themselves, but a statement among
            // them is kept, since the policy places it by what it is over.
            (_, Place::PassedOver) => {
                self.unplace(signature, honored);
                return;
            }
            _ => None,
        };
        if let Some(error) = refusal {
            self.certificate.skipped.push(error);
        }
        match place.and_then(|place| self.signatures(place)) {
            Some(signatures) if honored => signatures.honored.push(signature),
            Some(signatures) => signatures.unhonored.push(signature),
            None => {
                // An unhonored signature's refusal is already recorded.
                if honored {
                    self.certificate
                        .skipped
                        .push(packet.error(PacketErrorKind::MisplacedSignature));
                }
                self.unplace(signature, honored);
            }
        }
    }

    /// Keeps `signature`, placed with no part, if it is a statement over a
    /// user ID or a subkey: a certification, a subkey binding, or a subkey
    /// revocation. A certification revocation is never unplaced, since one
    /// that follows no user ID is placed with the primary key.
    fn unplace(&mut self, signature: Signature, honored: bool) {
        if !matches!(
            signature.signature_type(),
            SignatureType::GENERIC_CERTIFICATION
                | SignatureType::PERSONA_CERTIFICATION
                | SignatureType::CASUAL_CERTIFICATION
                | SignatureType::POSITIVE_CERTIFICATION
                | SignatureType::SUBKEY_BINDING
                | SignatureType::SUBKEY_REVOCATION
        ) {
            return;
        }
        let unplaced = &mut self.certificate.unplaced;
        if honored {
            unplaced.honored.push(signature);
        } else {
            unplaced.unhonored.push(signature);
        }
    }
}
