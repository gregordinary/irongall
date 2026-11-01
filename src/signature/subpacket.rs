//! Signature subpackets (RFC 9580 §5.2.3.7): the typed fields of a version 4
//! or version 6 signature.

use alloc::vec::Vec;

use super::{Signature, Unhonored};
use crate::key::{Fingerprint, KeyId};
use crate::packet::{Fields, PacketError, PacketErrorKind, Version};
use crate::wire::wire_number;

wire_number! {
    /// A signature subpacket's type (RFC 9580 §5.2.3.7): the low seven bits of
    /// the octet that carries it, whose high bit marks the subpacket critical.
    ///
    /// The constants name the types RFC 9580 assigns.
    pub struct SubpacketType;
    unnamed = "subpacket type";
    /// Signature Creation Time (2).
    const SIGNATURE_CREATION_TIME = 2, "Signature Creation Time";
    /// Signature Expiration Time (3).
    const SIGNATURE_EXPIRATION_TIME = 3, "Signature Expiration Time";
    /// Exportable Certification (4).
    const EXPORTABLE_CERTIFICATION = 4, "Exportable Certification";
    /// Trust Signature (5).
    const TRUST_SIGNATURE = 5, "Trust Signature";
    /// Regular Expression (6).
    const REGULAR_EXPRESSION = 6, "Regular Expression";
    /// Revocable (7).
    const REVOCABLE = 7, "Revocable";
    /// Key Expiration Time (9).
    const KEY_EXPIRATION_TIME = 9, "Key Expiration Time";
    /// Preferred Symmetric Ciphers for v1 SEIPD (11).
    const PREFERRED_SYMMETRIC_CIPHERS = 11, "Preferred Symmetric Ciphers for v1 SEIPD";
    /// Revocation Key (12), deprecated.
    const REVOCATION_KEY = 12, "Revocation Key";
    /// Issuer Key ID (16).
    const ISSUER_KEY_ID = 16, "Issuer Key ID";
    /// Notation Data (20).
    const NOTATION_DATA = 20, "Notation Data";
    /// Preferred Hash Algorithms (21).
    const PREFERRED_HASH_ALGORITHMS = 21, "Preferred Hash Algorithms";
    /// Preferred Compression Algorithms (22).
    const PREFERRED_COMPRESSION_ALGORITHMS = 22, "Preferred Compression Algorithms";
    /// Key Server Preferences (23).
    const KEY_SERVER_PREFERENCES = 23, "Key Server Preferences";
    /// Preferred Key Server (24).
    const PREFERRED_KEY_SERVER = 24, "Preferred Key Server";
    /// Primary User ID (25).
    const PRIMARY_USER_ID = 25, "Primary User ID";
    /// Policy URI (26).
    const POLICY_URI = 26, "Policy URI";
    /// Key Flags (27).
    const KEY_FLAGS = 27, "Key Flags";
    /// Signer's User ID (28).
    const SIGNERS_USER_ID = 28, "Signer's User ID";
    /// Reason for Revocation (29).
    const REASON_FOR_REVOCATION = 29, "Reason for Revocation";
    /// Features (30).
    const FEATURES = 30, "Features";
    /// Signature Target (31).
    const SIGNATURE_TARGET = 31, "Signature Target";
    /// Embedded Signature (32).
    const EMBEDDED_SIGNATURE = 32, "Embedded Signature";
    /// Issuer Fingerprint (33).
    const ISSUER_FINGERPRINT = 33, "Issuer Fingerprint";
    /// Intended Recipient Fingerprint (35).
    const INTENDED_RECIPIENT_FINGERPRINT = 35, "Intended Recipient Fingerprint";
    /// Preferred AEAD Ciphersuites (39).
    const PREFERRED_AEAD_CIPHERSUITES = 39, "Preferred AEAD Ciphersuites";
}

/// One signature subpacket, as it appears in its area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subpacket {
    subpacket_type: SubpacketType,
    critical: bool,
    body: Vec<u8>,
}

impl Subpacket {
    /// The subpacket's type.
    pub fn subpacket_type(&self) -> SubpacketType {
        self.subpacket_type
    }

    /// Whether the subpacket is marked critical: its signer asks that an
    /// evaluator that does not recognize it treat the signature as in error.
    pub fn is_critical(&self) -> bool {
        self.critical
    }

    /// The subpacket's data, after its type.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// The flags of a Key Flags subpacket (RFC 9580 §5.2.3.29).
///
/// The flags are a string of octets of any length, and a flag past its end is
/// zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyFlags<'a>(&'a [u8]);

impl<'a> KeyFlags<'a> {
    /// Whether the key may certify user IDs, and make direct-key signatures
    /// over other keys (0x01).
    pub fn may_certify(&self) -> bool {
        self.first() & 0x01 != 0
    }

    /// Whether the key may sign data (0x02).
    pub fn may_sign(&self) -> bool {
        self.first() & 0x02 != 0
    }

    /// The flags' octets, as the subpacket carries them.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    fn first(&self) -> u8 {
        self.0.first().copied().unwrap_or(0)
    }
}

wire_number! {
    /// A revocation's machine-readable reason (RFC 9580 §5.2.3.31).
    ///
    /// The constants name the codes RFC 9580 assigns.
    pub struct RevocationCode;
    unnamed = "revocation code";
    /// No reason specified (0).
    const NO_REASON = 0, "No reason specified";
    /// The key is superseded (1).
    const KEY_SUPERSEDED = 1, "Key is superseded";
    /// The key material has been compromised (2).
    const KEY_COMPROMISED = 2, "Key material has been compromised";
    /// The key is retired and no longer used (3).
    const KEY_RETIRED = 3, "Key is retired and no longer used";
    /// The user ID is no longer valid (32).
    const USER_ID_INVALID = 32, "User ID information is no longer valid";
}

/// A Reason for Revocation subpacket (RFC 9580 §5.2.3.31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationReason<'a> {
    code: RevocationCode,
    message: &'a [u8],
}

impl<'a> RevocationReason<'a> {
    /// The machine-readable reason.
    pub fn code(&self) -> RevocationCode {
        self.code
    }

    /// The reason in human-readable form, possibly empty. RFC 9580 says it is
    /// UTF-8; it is not checked.
    pub fn message(&self) -> &'a [u8] {
        self.message
    }
}

/// A four-octet time field: a creation time, or an expiration time's
/// interval.
pub(super) fn time(body: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(body).ok().map(u32::from_be_bytes)
}

pub(super) fn key_id(body: &[u8]) -> Option<KeyId> {
    <[u8; 8]>::try_from(body).ok().map(KeyId::from_bytes)
}

/// An issuer fingerprint: a key version, then that version's fingerprint. The
/// version must be the signature's (RFC 9580 §5.2.3.35).
pub(super) fn fingerprint(body: &[u8], version: Version) -> Option<Fingerprint> {
    match (version, body) {
        (Version::V4, [4, fingerprint @ ..]) => fingerprint.try_into().ok().map(Fingerprint::V4),
        (Version::V6, [6, fingerprint @ ..]) => fingerprint.try_into().ok().map(Fingerprint::V6),
        _ => None,
    }
}

/// A Primary User ID's one octet, a Boolean (RFC 9580 §5.2.3.27): 1 for
/// true, 0 for false. Any other value is not well formed, rather than read
/// as either.
pub(super) fn primary_user_id(body: &[u8]) -> Option<bool> {
    match body {
        [0] => Some(false),
        [1] => Some(true),
        _ => None,
    }
}

pub(super) fn key_flags(body: &[u8]) -> KeyFlags<'_> {
    KeyFlags(body)
}

pub(super) fn revocation_reason(body: &[u8]) -> Option<RevocationReason<'_>> {
    let (&code, message) = body.split_first()?;
    Some(RevocationReason {
        code: RevocationCode(code),
        message,
    })
}

/// Whether irongall honors a subpacket of `subpacket_type` marked critical
/// (RFC 9580 §5.2.3.7): it implements the type's meaning, or the meaning
/// cannot change whether a signature verifies.
///
/// `embedded` is whether the subpacket is in an embedded signature, whose own
/// embedded signatures are not read.
const fn honors_critical(subpacket_type: SubpacketType, embedded: bool) -> bool {
    match subpacket_type {
        // Read, and acted on by whatever judges the signature.
        SubpacketType::SIGNATURE_CREATION_TIME
        | SubpacketType::SIGNATURE_EXPIRATION_TIME
        | SubpacketType::KEY_EXPIRATION_TIME
        | SubpacketType::ISSUER_KEY_ID
        | SubpacketType::ISSUER_FINGERPRINT
        | SubpacketType::PRIMARY_USER_ID
        | SubpacketType::KEY_FLAGS
        | SubpacketType::REASON_FOR_REVOCATION => true,
        SubpacketType::EMBEDDED_SIGNATURE => !embedded,
        // Preferences for whoever encrypts to the key, and statements for a
        // person to read: none bears on whether a signature verifies.
        SubpacketType::PREFERRED_SYMMETRIC_CIPHERS
        | SubpacketType::PREFERRED_HASH_ALGORITHMS
        | SubpacketType::PREFERRED_COMPRESSION_ALGORITHMS
        | SubpacketType::PREFERRED_AEAD_CIPHERSUITES
        | SubpacketType::FEATURES
        | SubpacketType::KEY_SERVER_PREFERENCES
        | SubpacketType::PREFERRED_KEY_SERVER
        | SubpacketType::POLICY_URI
        | SubpacketType::SIGNERS_USER_ID => true,
        // Every other type, including those RFC 9580 defines whose meaning
        // irongall does not implement: exportability, trust signatures and
        // their regular expressions, revocability, revocation keys, notations
        // (irongall knows no notation's name), signature targets, and intended
        // recipients.
        _ => false,
    }
}

/// Where a subpacket area is, which decides what its subpackets may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Area {
    /// The hashed area, which the signature covers.
    Hashed,
    /// The unhashed area, which anyone handling the signature can change.
    Unhashed,
}

/// Reads a subpacket area (RFC 9580 §5.2.3.7) to its end.
///
/// A subpacket of a type irongall decodes is checked to be well formed in
/// either area. In the hashed area, a subpacket marked critical must be one
/// irongall honors; the bit carries no weight in the unhashed area, which
/// anyone can change. An embedded signature is read as a signature, under
/// the same `unhonored`, and appended to `embedded_signatures`, unless the
/// area is itself an embedded signature's (`embedded`): one level only, so
/// reading never recurses past it. Where `unhonored` says to overlook what
/// irongall cannot honor, a malformed subpacket is kept as it is, one marked
/// critical is kept, and an embedded signature that does not read is left
/// out.
pub(super) fn read_area(
    mut area: Fields<'_>,
    which: Area,
    version: Version,
    embedded: bool,
    unhonored: Unhonored,
    embedded_signatures: &mut Vec<Signature>,
) -> Result<Vec<Subpacket>, PacketError> {
    let mut subpackets = Vec::new();
    while !area.is_empty() {
        let start = area.offset();
        let length = match area.u8()? {
            octet @ 0..=191 => usize::from(octet),
            // At most 16319, so the addition cannot wrap. `& 0x3F` is
            // `- 192` over this range.
            octet @ 192..=254 => {
                let second = area.u8()?;
                usize::from(u16::from_be_bytes([octet & 0x3F, second]).wrapping_add(192))
            }
            255 => usize::try_from(area.u32()?).unwrap_or(usize::MAX),
        };
        let invalid = |area: &Fields<'_>| area.error_at(PacketErrorKind::InvalidSubpacket, start);
        // The length counts the type octet, so it is at least one.
        let mut subpacket = area.split(length)?;
        let Ok(octet) = subpacket.u8() else {
            return Err(invalid(&area));
        };
        let subpacket_type = SubpacketType(octet & 0x7F);
        let marked_critical = octet & 0x80 != 0;
        let body_fields = subpacket.clone();
        let body = subpacket.rest();

        let well_formed = match subpacket_type {
            SubpacketType::SIGNATURE_CREATION_TIME
            | SubpacketType::SIGNATURE_EXPIRATION_TIME
            | SubpacketType::KEY_EXPIRATION_TIME => time(body).is_some(),
            SubpacketType::ISSUER_KEY_ID => key_id(body).is_some(),
            SubpacketType::ISSUER_FINGERPRINT => fingerprint(body, version).is_some(),
            SubpacketType::PRIMARY_USER_ID => primary_user_id(body).is_some(),
            SubpacketType::REASON_FOR_REVOCATION => revocation_reason(body).is_some(),
            _ => true,
        };
        let refuse = unhonored == Unhonored::Refuse;
        if !well_formed && refuse {
            return Err(invalid(&area));
        }
        if which == Area::Hashed
            && marked_critical
            && refuse
            && !honors_critical(subpacket_type, embedded)
        {
            return Err(area.error_at(PacketErrorKind::CriticalSubpacket, start));
        }
        if subpacket_type == SubpacketType::EMBEDDED_SIGNATURE && !embedded {
            match Signature::read(body_fields, true, unhonored) {
                Ok(signature) => embedded_signatures.push(signature),
                Err(error) if refuse => return Err(error),
                Err(_) => {}
            }
        }
        subpackets.push(Subpacket {
            subpacket_type,
            critical: marked_critical,
            body: body.to_vec(),
        });
    }
    Ok(subpackets)
}
