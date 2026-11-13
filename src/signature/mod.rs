//! Signature packets (RFC 9580 §5.2): versions 4 and 6, with their
//! subpackets.
//!
//! [`Signature::from_packet`] reads a Signature packet:
//!
//! ```
//! use irongall::signature::{Signature, SignatureType};
//! use irongall::{armor, packet};
//!
//! // The version 4 signature of RFC 9580 Appendix A.2.
//! let armored = "\
//! -----BEGIN PGP SIGNATURE-----
//!
//! iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/VvkMypjiECY3vZg/2xbBMd/S
//! ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE
//! -----END PGP SIGNATURE-----
//! ";
//! let data = armor::decode(armored.as_bytes())?.into_data();
//! let packet = packet::packets(&data).next().unwrap()?;
//! let signature = Signature::from_packet(&packet)?;
//! assert_eq!(signature.signature_type(), SignatureType::BINARY);
//! // 2015-09-16 12:24:53 UTC.
//! assert_eq!(signature.creation_time(), 1_442_406_293);
//! let issuers: Vec<_> = signature.issuer_key_ids().map(|id| id.to_string()).collect();
//! assert_eq!(issuers, ["8CFDE12197965A9A"]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # What is read
//!
//! - Versions 4 and 6. A signature of another version, version 3 included, is
//!   refused as [`UnsupportedVersion`](PacketErrorKind::UnsupportedVersion).
//! - A signature of any algorithm parses. Only the material of the algorithms
//!   irongall verifies with is read: RSA, Ed25519, and EdDSALegacy over
//!   Ed25519Legacy. Any other material is [`SignatureMaterial::Opaque`].
//! - Every subpacket, kept as it appears in its area. The typed accessors read
//!   the hashed area only, which the signature covers, and where it holds a
//!   type more than once they take the last (RFC 9580 §5.2.3.9). Issuers and
//!   embedded signatures are the exception, read from both areas: an issuer
//!   only says which key to try, and an embedded signature is verified on its
//!   own.
//!
//! # What is refused
//!
//! A signature that is malformed, or that asks for something irongall does not
//! implement, is refused, and RFC 9580 §5.2.5 requires that the packets around
//! it be read regardless. Beyond the structure and lengths of the packet:
//!
//! - A subpacket of a type irongall decodes that is not of the type's form,
//!   and one of a type it keeps without decoding whose length is not the
//!   one RFC 9580 gives the type (§5.2.5): Exportable Certification,
//!   Revocable, Trust Signature, Revocation Key, Notation Data whose lengths
//!   do not add up, Signature Target, Intended Recipient Fingerprint, and
//!   Preferred AEAD Ciphersuites. The form of such a type is not otherwise
//!   checked.
//! - A signature without a creation time in its hashed area (RFC 9580
//!   §5.2.3.11).
//! - A version 6 salt of a size other than its hash algorithm's (RFC 9580
//!   §5.2.3).
//! - A hashed subpacket marked critical that irongall does not honor (RFC 9580
//!   §5.2.3.7). It honors the types it decodes, and those whose meaning cannot
//!   change whether a signature verifies: algorithm preferences, features, key
//!   server preferences, the preferred key server, the policy URI, and the
//!   signer's user ID. Any other type marked critical refuses the signature,
//!   among them exportability, trust signatures and their regular
//!   expressions, revocability, revocation keys, notations, signature targets,
//!   and intended recipients.
//!
//! Reading a signature judges nothing else about it. Its type, algorithms,
//! times, and flags are for whatever verifies it to weigh.
//!
//! # Verifying
//!
//! [`Signature::verify`] checks a signature with a key, over the [`Subject`]
//! it is a statement about: a document, a key, a key and one of its user IDs,
//! or a primary key and one of its subkeys. It checks the cryptography and
//! nothing else. [`cert`](crate::cert) assembles the certificates whose keys,
//! user IDs, and subkeys are those subjects.

mod subpacket;
mod verify;

#[cfg(test)]
mod tests;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

pub use subpacket::{
    KeyFlags, RevocationCode, RevocationReason, Subpacket, SubpacketType, Subpackets,
};
pub use verify::{DocumentHash, Subject, VerifyError};
pub(crate) use verify::{
    Over, Prefix, PrimaryChecks, SubjectKind, check_verifying_key, statement_kinds,
};

use crate::hash::HashAlgorithm;
use crate::key::{Fingerprint, KeyId, PublicKeyAlgorithm};
use crate::packet::{Fields, Packet, PacketError, PacketErrorKind, Tag, Version};
use crate::wire::wire_number;
use subpacket::Area;

wire_number! {
    /// A signature's type (RFC 9580 §5.2.1): what the signature is a statement
    /// about.
    ///
    /// Every octet is a type a signature can carry; the constants name the
    /// ones RFC 9580 assigns.
    pub struct SignatureType;
    unnamed = "signature type";
    /// A signature of a binary document (0x00).
    const BINARY = 0x00, "Binary Signature";
    /// A signature of a text document, its line endings made CR LF (0x01).
    const TEXT = 0x01, "Text Signature";
    /// A signature of its own subpackets only (0x02).
    const STANDALONE = 0x02, "Standalone Signature";
    /// A certification of a user ID that says nothing of how well the
    /// certifier checked it (0x10).
    const GENERIC_CERTIFICATION = 0x10, "Generic Certification Signature";
    /// A certification of a user ID without checking it (0x11).
    const PERSONA_CERTIFICATION = 0x11, "Persona Certification Signature";
    /// A certification of a user ID after some checking (0x12).
    const CASUAL_CERTIFICATION = 0x12, "Casual Certification Signature";
    /// A certification of a user ID after substantial checking (0x13).
    const POSITIVE_CERTIFICATION = 0x13, "Positive Certification Signature";
    /// A primary key's binding of a subkey (0x18).
    const SUBKEY_BINDING = 0x18, "Subkey Binding Signature";
    /// A signing subkey's binding to its primary key: the back-signature
    /// (0x19).
    const PRIMARY_KEY_BINDING = 0x19, "Primary Key Binding Signature";
    /// A signature over a key alone (0x1F).
    const DIRECT_KEY = 0x1F, "Direct Key Signature";
    /// A revocation of a primary key (0x20).
    const KEY_REVOCATION = 0x20, "Key Revocation Signature";
    /// A revocation of a subkey's binding (0x28).
    const SUBKEY_REVOCATION = 0x28, "Subkey Revocation Signature";
    /// A revocation of a certification or direct-key signature (0x30).
    const CERTIFICATION_REVOCATION = 0x30, "Certification Revocation Signature";
    /// A timestamp signature (0x40).
    const TIMESTAMP = 0x40, "Timestamp Signature";
    /// A signature over another signature (0x50).
    const THIRD_PARTY_CONFIRMATION = 0x50, "Third-Party Confirmation Signature";
}

impl SignatureType {
    /// Whether the type is a certification of a user ID (0x10 to 0x13), as
    /// opposed to a revocation of one.
    pub(crate) const fn is_certification(self) -> bool {
        matches!(
            self,
            SignatureType::GENERIC_CERTIFICATION
                | SignatureType::PERSONA_CERTIFICATION
                | SignatureType::CASUAL_CERTIFICATION
                | SignatureType::POSITIVE_CERTIFICATION
        )
    }
}

/// A signature's material, for the algorithms irongall verifies with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureMaterial<'a> {
    /// An RSA signature, of any of the three RSA algorithms: the value
    /// m^d mod n, big-endian, without leading zeros (RFC 9580 §5.2.3.1).
    Rsa(&'a [u8]),
    /// An Ed25519 signature in its native 64-octet encoding, R then S
    /// (RFC 8032 §5.1.6).
    ///
    /// An Ed25519 signature carries the encoding as it is; an EdDSALegacy one
    /// over Ed25519Legacy carries R and S as two integers (RFC 9580
    /// §5.2.3.3.1).
    Ed25519([u8; 64]),
    /// Material irongall does not read: an algorithm it does not verify with,
    /// or EdDSALegacy over a curve other than Ed25519Legacy. The signature
    /// verifies nothing.
    Opaque,
}

/// A signature: the content of a Signature packet, or of an Embedded
/// Signature subpacket.
///
/// A signature holds its body as it was read, and what is read from the body
/// on demand, such as its subpackets and material, is read from that: so the
/// memory a signature holds is its body and a few words, whatever the body
/// holds. Two signatures are equal when their bodies are, octet for octet.
///
/// Its [`Debug`](fmt::Debug) form shows what the accessors read from the
/// body, not the body's octets.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    /// The body: from the version through the material, and, for a
    /// signature read with what irongall cannot honor overlooked, any octets
    /// after the material.
    body: Box<[u8]>,
    /// The signatures embedded in either area, hashed area first.
    embedded: Box<[Signature]>,
    /// Where the hashed area ends in the body: the end of the part the
    /// signature's own hash covers (RFC 9580 §5.2.4).
    hashed_end: usize,
    /// Where the unhashed area ends in the body.
    unhashed_end: usize,
    /// Where the material begins in the body.
    material_start: usize,
    creation_time: u32,
    /// How many of `embedded`, from the first, are in the hashed area.
    embedded_hashed: u32,
    version: Version,
    signature_type: SignatureType,
    public_key_algorithm: PublicKeyAlgorithm,
    hash_algorithm: HashAlgorithm,
    hash_prefix: [u8; 2],
    /// What reading the signature did with what irongall cannot honor,
    /// which decides how its material's integers are read.
    unhonored: Unhonored,
    /// Whether the unhashed area read: one that did not, overlooked, is
    /// taken for an empty one.
    unhashed_read: bool,
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("version", &self.version)
            .field("signature_type", &self.signature_type)
            .field("public_key_algorithm", &self.public_key_algorithm)
            .field("hash_algorithm", &self.hash_algorithm)
            .field("creation_time", &self.creation_time)
            .field("hashed_subpackets", &self.hashed_subpackets())
            .field("unhashed_subpackets", &self.unhashed_subpackets())
            .field("hash_prefix", &self.hash_prefix)
            .field("salt", &self.salt())
            .field("material", &self.material())
            .field("embedded_signatures", &self.embedded)
            .field("honored", &self.is_honored())
            .finish()
    }
}

impl Signature {
    /// The fewest octets a signature's body can hold and read: version 4,
    /// with a creation time alone in its hashed area, an empty unhashed
    /// area, and material of no length, which an algorithm irongall does not
    /// read may have. Version, type, algorithms, and the hashed area's
    /// length take six octets, the creation time six, the unhashed area's
    /// length two, and the hash prefix two.
    ///
    /// Reading allocates for a signature only where this many octets could
    /// hold one, so what it allocates for signatures that turn out not to
    /// read is bounded by the input's length.
    pub(crate) const SHORTEST: usize = 16;

    /// Reads a Signature packet.
    ///
    /// # Errors
    ///
    /// When the packet is of another type, or the signature is of a version
    /// other than 4 or 6, malformed, or refused for one of the reasons in the
    /// [module documentation](self). A signature of an algorithm irongall
    /// does not read is not an error; its material is
    /// [`SignatureMaterial::Opaque`].
    pub fn from_packet(packet: &Packet<'_>) -> Result<Signature, PacketError> {
        Signature::read_packet(packet, Unhonored::Refuse)
    }

    /// Reads a Signature packet as [`from_packet`](Self::from_packet) does,
    /// except that neither what irongall reads a signature only to act on
    /// what it grants, nor how a part no signature covers is written, refuses
    /// it: a hashed subpacket marked critical whose meaning irongall does not
    /// implement, a subpacket of a type irongall decodes that is malformed,
    /// and an embedded signature that does not read, each of which is
    /// overlooked; an unhashed area whose subpackets do not read, which is
    /// taken for an empty one; octets after the material, which are passed
    /// over; and an integer of the material whose length is not written as
    /// RFC 9580 §3.2 requires, whose value is read regardless. What verifying
    /// the signature needs must read: its structure, its hashed area's
    /// subpackets, its creation time, and the values of its material.
    ///
    /// Such a signature is one irongall cannot honor, and nothing may act on
    /// what it grants. It exists so that judging a certificate can weigh it
    /// as a statement its maker still made: a revocation that revokes, or a
    /// newer self-signature that keeps an older one from governing. The
    /// unhashed area, the packet's length, and the lengths of the material's
    /// integers are covered by no signature, so without this, anyone who
    /// handles a certificate could make a revocation in it go unread by
    /// altering them.
    pub(crate) fn from_packet_unhonored(packet: &Packet<'_>) -> Result<Signature, PacketError> {
        Signature::read_packet(packet, Unhonored::Overlook)
    }

    fn read_packet(packet: &Packet<'_>, unhonored: Unhonored) -> Result<Signature, PacketError> {
        if packet.tag() != Tag::SIGNATURE {
            return Err(packet.error(PacketErrorKind::UnexpectedType));
        }
        Signature::read(packet.fields(), false, unhonored)
    }

    /// Reads a signature's body, to the end of `fields`. `embedded` is whether
    /// the body is an Embedded Signature subpacket's.
    fn read(
        mut fields: Fields<'_>,
        embedded: bool,
        unhonored: Unhonored,
    ) -> Result<Signature, PacketError> {
        let mut body = fields.clone();
        let at = fields.offset();
        let within = |fields: &Fields<'_>| fields.offset().saturating_sub(at);
        let version = Version::from_number(fields.u8()?)
            .ok_or_else(|| fields.error_at(PacketErrorKind::UnsupportedVersion, at))?;
        let signature_type = SignatureType(fields.u8()?);
        let public_key_algorithm = PublicKeyAlgorithm(fields.u8()?);
        let hash_algorithm = HashAlgorithm(fields.u8()?);

        let mut embedded_signatures = Vec::new();
        let hashed_at = fields.offset();
        let hashed = area(&mut fields, version)?;
        subpacket::read_area(
            hashed.clone(),
            Area::Hashed,
            version,
            embedded,
            unhonored,
            &mut embedded_signatures,
        )?;
        let creation_time = last(
            Subpackets::of(hashed.clone().rest()),
            SubpacketType::SIGNATURE_CREATION_TIME,
        )
        .and_then(subpacket::time)
        .ok_or_else(|| fields.error_at(PacketErrorKind::MissingCreationTime, hashed_at))?;
        let hashed_end = within(&fields);
        let embedded_hashed = embedded_signatures.len();
        let unhashed_read = match subpacket::read_area(
            area(&mut fields, version)?,
            Area::Unhashed,
            version,
            embedded,
            unhonored,
            &mut embedded_signatures,
        ) {
            Ok(()) => true,
            Err(_) if unhonored == Unhonored::Overlook => {
                embedded_signatures.truncate(embedded_hashed);
                false
            }
            Err(error) => return Err(error),
        };
        let unhashed_end = within(&fields);

        let hash_prefix = fields.array()?;
        if version == Version::V6 {
            let size_at = fields.offset();
            let size = fields.u8()?;
            if hash_algorithm.v6_salt_size() != Some(size) {
                return Err(fields.error_at(PacketErrorKind::SaltSize, size_at));
            }
            fields.take(usize::from(size))?;
        }
        let material_start = within(&fields);
        read_material(&mut fields, public_key_algorithm, version, unhonored)?;
        match unhonored {
            Unhonored::Refuse => fields.finish()?,
            Unhonored::Overlook => {
                fields.rest();
            }
        }

        Ok(Signature {
            body: body.rest().into(),
            embedded: embedded_signatures.into_boxed_slice(),
            hashed_end,
            unhashed_end,
            material_start,
            creation_time,
            embedded_hashed: u32::try_from(embedded_hashed).unwrap_or(u32::MAX),
            version,
            signature_type,
            public_key_algorithm,
            hash_algorithm,
            hash_prefix,
            unhonored,
            unhashed_read,
        })
    }

    /// The hashed area's subpackets, as octets: after the four octets of
    /// version and algorithms, and the area's length.
    fn hashed_area(&self) -> &[u8] {
        let start = 4_usize.saturating_add(area_length_width(self.version));
        self.body.get(start..self.hashed_end).unwrap_or_default()
    }

    /// The unhashed area's subpackets, as octets: none if they did not read.
    fn unhashed_area(&self) -> &[u8] {
        if !self.unhashed_read {
            return &[];
        }
        let start = self
            .hashed_end
            .saturating_add(area_length_width(self.version));
        self.body.get(start..self.unhashed_end).unwrap_or_default()
    }

    /// The signature's version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The signature's type.
    pub fn signature_type(&self) -> SignatureType {
        self.signature_type
    }

    /// The algorithm of the key that made the signature.
    pub fn public_key_algorithm(&self) -> PublicKeyAlgorithm {
        self.public_key_algorithm
    }

    /// The algorithm of the hash the signature is made over.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    /// The first two octets of the hash the signature is made over, which a
    /// verifier can compare before checking the signature itself. A match is
    /// never evidence that the signature is valid.
    pub fn hash_prefix(&self) -> [u8; 2] {
        self.hash_prefix
    }

    /// A version 6 signature's salt, hashed before anything else (RFC 9580
    /// §5.2.4). Empty for version 4.
    pub fn salt(&self) -> &[u8] {
        match self.version {
            Version::V4 => &[],
            // After the hash prefix and the salt's size.
            Version::V6 => self
                .body
                .get(self.unhashed_end.saturating_add(3)..self.material_start)
                .unwrap_or_default(),
        }
    }

    /// The signature's material.
    pub fn material(&self) -> SignatureMaterial<'_> {
        let mut fields = Fields::of(self.body.get(self.material_start..).unwrap_or_default());
        // Read when the signature was, so this does not fail.
        read_material(
            &mut fields,
            self.public_key_algorithm,
            self.version,
            self.unhonored,
        )
        .unwrap_or(SignatureMaterial::Opaque)
    }

    /// The hashed subpackets, in order: those the signature covers.
    pub fn hashed_subpackets(&self) -> Subpackets<'_> {
        Subpackets::of(self.hashed_area())
    }

    /// The unhashed subpackets, in order. The signature does not cover them,
    /// so anyone who handles it can change them, and they are advisory only
    /// (RFC 9580 §13.13).
    pub fn unhashed_subpackets(&self) -> Subpackets<'_> {
        Subpackets::of(self.unhashed_area())
    }

    /// When the signature was made, in seconds since the Unix epoch.
    pub fn creation_time(&self) -> u32 {
        self.creation_time
    }

    /// How long after its creation the signature expires, in seconds, or
    /// `None` if it does not (RFC 9580 §5.2.3.18). A stated zero means it
    /// does not.
    pub fn expiration_time(&self) -> Option<u32> {
        self.last_hashed(SubpacketType::SIGNATURE_EXPIRATION_TIME)
            .and_then(subpacket::time)
            .filter(|&seconds| seconds != 0)
    }

    /// How long after the key's creation the key expires, in seconds, or
    /// `None` if it does not (RFC 9580 §5.2.3.13). A stated zero means it
    /// does not. Found on self-signatures, where the key is the one they bind:
    /// the primary key, or a subkey for a subkey binding.
    pub fn key_expiration_time(&self) -> Option<u32> {
        self.last_hashed(SubpacketType::KEY_EXPIRATION_TIME)
            .and_then(subpacket::time)
            .filter(|&seconds| seconds != 0)
    }

    /// The flags the signature grants the key it binds, if it states any
    /// (RFC 9580 §5.2.3.29).
    pub fn key_flags(&self) -> Option<KeyFlags<'_>> {
        self.last_hashed(SubpacketType::KEY_FLAGS)
            .map(subpacket::key_flags)
    }

    /// Whether a user ID's self-signature marks the user ID as the key's
    /// primary one (RFC 9580 §5.2.3.27).
    pub fn is_primary_user_id(&self) -> bool {
        self.last_hashed(SubpacketType::PRIMARY_USER_ID)
            .and_then(subpacket::primary_user_id)
            .unwrap_or(false)
    }

    /// Why a revocation revokes, if it says (RFC 9580 §5.2.3.31).
    pub fn revocation_reason(&self) -> Option<RevocationReason<'_>> {
        self.last_hashed(SubpacketType::REASON_FOR_REVOCATION)
            .and_then(subpacket::revocation_reason)
    }

    /// The key IDs the signature names its issuer by, from the hashed area and
    /// then the unhashed one.
    ///
    /// These say which key to try, not which key signed: a key ID is not
    /// unique, and an unhashed one is not covered by the signature. Only a
    /// verification establishes the issuer.
    pub fn issuer_key_ids(&self) -> impl Iterator<Item = KeyId> + '_ {
        self.both_areas(SubpacketType::ISSUER_KEY_ID)
            .filter_map(subpacket::key_id)
    }

    /// The fingerprints the signature names its issuer by, from the hashed
    /// area and then the unhashed one. As with
    /// [`issuer_key_ids`](Self::issuer_key_ids), these say which key to try.
    pub fn issuer_fingerprints(&self) -> impl Iterator<Item = Fingerprint> + '_ {
        self.both_areas(SubpacketType::ISSUER_FINGERPRINT)
            .filter_map(|body| subpacket::fingerprint(body, self.version))
    }

    /// The signatures embedded in the signature, from the hashed area and then
    /// the unhashed one: in practice, a signing subkey's back-signature in its
    /// binding (RFC 9580 §5.2.3.34).
    ///
    /// An embedded signature is verified on its own. The area it was found in
    /// says only whether this signature covers it, which decides whether a
    /// back-signature's expiration can hold (see the [`policy`](crate::policy)
    /// module). Its own embedded signatures are not read.
    pub fn embedded_signatures(&self) -> &[Signature] {
        &self.embedded
    }

    /// The [embedded signatures](Self::embedded_signatures) in the hashed
    /// area, which this signature covers, and those in the unhashed area,
    /// which nothing covers.
    pub(crate) fn embedded_by_area(&self) -> (&[Signature], &[Signature]) {
        usize::try_from(self.embedded_hashed)
            .ok()
            .and_then(|hashed| self.embedded.split_at_checked(hashed))
            .unwrap_or((&self.embedded, &[]))
    }

    /// The part of the body the signature's own hash covers: from the version
    /// through the hashed subpackets (RFC 9580 §5.2.4).
    pub(crate) fn hashed_fields(&self) -> &[u8] {
        self.body.get(..self.hashed_end).unwrap_or_default()
    }

    /// Whether the signature read as [`from_packet`](Self::from_packet)
    /// reads it, rather than only with what irongall cannot honor overlooked
    /// ([`from_packet_unhonored`](Self::from_packet_unhonored)).
    pub(crate) fn is_honored(&self) -> bool {
        self.unhonored == Unhonored::Refuse
    }

    /// The length of the signature's body, in octets: of its packet's body,
    /// or of the subpacket it is embedded in.
    pub(crate) fn length(&self) -> usize {
        self.body.len()
    }

    /// The body of the last hashed subpacket of `subpacket_type`.
    fn last_hashed(&self, subpacket_type: SubpacketType) -> Option<&[u8]> {
        last(self.hashed_subpackets(), subpacket_type)
    }

    /// The bodies of the subpackets of `subpacket_type` in either area, hashed
    /// first.
    fn both_areas(&self, subpacket_type: SubpacketType) -> impl Iterator<Item = &[u8]> {
        self.hashed_subpackets()
            .chain(self.unhashed_subpackets())
            .filter(move |subpacket| subpacket.subpacket_type() == subpacket_type)
            .map(|subpacket| subpacket.body())
    }
}

/// What reading a signature does with what irongall reads only to act on
/// what the signature grants, where irongall cannot honor it: a hashed
/// subpacket marked critical whose meaning irongall does not implement (RFC
/// 9580 §5.2.3.7), a malformed subpacket of a type it decodes, an embedded
/// signature that does not read, or an unhashed area that does not; and with
/// a part no signature covers that is not written as RFC 9580 requires:
/// octets after the material, or an integer of the material whose length is
/// not (§3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unhonored {
    /// Refuses the signature.
    Refuse,
    /// Reads the signature regardless: see
    /// [`Signature::from_packet_unhonored`].
    Overlook,
}

/// The body of the last subpacket of `subpacket_type` in `subpackets`.
fn last(subpackets: Subpackets<'_>, subpacket_type: SubpacketType) -> Option<&[u8]> {
    subpackets
        .filter(|subpacket| subpacket.subpacket_type() == subpacket_type)
        .last()
        .map(|subpacket| subpacket.body())
}

/// How many octets a subpacket area's length takes in a signature of
/// `version`: two in version 4, and four in version 6 (RFC 9580 §5.2.3).
const fn area_length_width(version: Version) -> usize {
    match version {
        Version::V4 => 2,
        Version::V6 => 4,
    }
}

/// The next subpacket area: its length, big-endian in
/// [`area_length_width`] octets, then that many octets.
fn area<'a>(fields: &mut Fields<'a>, version: Version) -> Result<Fields<'a>, PacketError> {
    // At most four octets, so the value fits in 32 bits.
    let length = fields
        .take(area_length_width(version))?
        .iter()
        .fold(0_u32, |length, &octet| {
            length.wrapping_shl(8) | u32::from(octet)
        });
    fields.split(usize::try_from(length).unwrap_or(usize::MAX))
}

/// Reads the algorithm-specific material of a signature (RFC 9580 §5.2.3.1 to
/// §5.2.3.5), up to the end of `fields`.
///
/// Where `unhonored` says to overlook what irongall cannot honor, an integer
/// is read for its value alone, however its length is written: see
/// [`Fields::mpi_value`].
fn read_material<'a>(
    fields: &mut Fields<'a>,
    algorithm: PublicKeyAlgorithm,
    version: Version,
    unhonored: Unhonored,
) -> Result<SignatureMaterial<'a>, PacketError> {
    let mpi = |fields: &mut Fields<'a>| match unhonored {
        Unhonored::Refuse => fields.mpi(version),
        Unhonored::Overlook => fields.mpi_value(),
    };
    match algorithm {
        PublicKeyAlgorithm::RSA
        | PublicKeyAlgorithm::RSA_ENCRYPT_ONLY
        | PublicKeyAlgorithm::RSA_SIGN_ONLY => Ok(SignatureMaterial::Rsa(mpi(fields)?)),
        PublicKeyAlgorithm::ED25519 => Ok(SignatureMaterial::Ed25519(fields.array()?)),
        // RFC 9580 §5.2.3.3.1 forbids EdDSALegacy in version 6.
        PublicKeyAlgorithm::EDDSA_LEGACY if version == Version::V4 => {
            let r = mpi(fields)?;
            let s = mpi(fields)?;
            Ok(ed25519_legacy(r, s).map_or(SignatureMaterial::Opaque, SignatureMaterial::Ed25519))
        }
        _ => {
            fields.rest();
            Ok(SignatureMaterial::Opaque)
        }
    }
}

/// The native Ed25519 signature that an EdDSALegacy signature's R and S carry,
/// or `None` if either is longer than 32 octets, as on another curve.
///
/// Each is a native, little-endian octet string of 32 octets read as an
/// integer, so the integer's encoding dropped the string's leading zero
/// octets, and they are restored here (RFC 9580 §5.2.3.3.1).
fn ed25519_legacy(r: &[u8], s: &[u8]) -> Option<[u8; 64]> {
    if r.len() > 32 || s.len() > 32 {
        return None;
    }
    let mut native = [0; 64];
    let (native_r, native_s) = native.split_at_mut(32);
    for (target, source) in [(native_r, r), (native_s, s)] {
        for (slot, byte) in target.iter_mut().rev().zip(source.iter().rev()) {
            *slot = *byte;
        }
    }
    Some(native)
}
