//! Signature subpackets (RFC 9580 §5.2.3.7): the typed fields of a version 4
//! or version 6 signature.

use alloc::vec::Vec;
use core::iter::FusedIterator;

use super::{Signature, Unhonored};
use crate::hash::HashAlgorithm;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subpacket<'a> {
    subpacket_type: SubpacketType,
    critical: bool,
    body: &'a [u8],
}

impl<'a> Subpacket<'a> {
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
    pub fn body(&self) -> &'a [u8] {
        self.body
    }
}

/// The subpackets of one of a signature's areas, in the order they appear:
/// see [`Signature::hashed_subpackets`].
#[derive(Debug, Clone)]
pub struct Subpackets<'a> {
    area: Fields<'a>,
}

impl<'a> Subpackets<'a> {
    /// The subpackets of `area`, an area reading the signature found well
    /// framed.
    pub(super) fn of(area: &'a [u8]) -> Subpackets<'a> {
        Subpackets {
            area: Fields::of(area),
        }
    }
}

impl<'a> Iterator for Subpackets<'a> {
    type Item = Subpacket<'a>;

    fn next(&mut self) -> Option<Subpacket<'a>> {
        match next(&mut self.area) {
            Ok(framed) => framed.map(|framed| framed.subpacket),
            // Reading the signature found the area well framed, so this is
            // not reached; the subpackets end rather than go on past a
            // subpacket that does not frame.
            Err(_) => {
                self.area = Fields::of(&[]);
                None
            }
        }
    }
}

impl FusedIterator for Subpackets<'_> {}

/// A subpacket as its area frames it.
struct Framed<'a> {
    /// Where its length begins.
    start: usize,
    subpacket: Subpacket<'a>,
    /// A cursor over its body.
    body: Fields<'a>,
}

/// Frames the next subpacket of `area`, or `None` at the area's end.
fn next<'a>(area: &mut Fields<'a>) -> Result<Option<Framed<'a>>, PacketError> {
    if area.is_empty() {
        return Ok(None);
    }
    let start = area.offset();
    let length = length(area)?;
    // The length counts the type octet, so it is at least one.
    let mut subpacket = area.split(length)?;
    let Ok(octet) = subpacket.u8() else {
        return Err(area.error_at(PacketErrorKind::InvalidSubpacket, start));
    };
    let body = subpacket.clone();
    Ok(Some(Framed {
        start,
        subpacket: Subpacket {
            subpacket_type: SubpacketType(octet & 0x7F),
            critical: octet & 0x80 != 0,
            body: subpacket.rest(),
        },
        body,
    }))
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

/// Whether a subpacket of `subpacket_type`, a type irongall keeps without
/// decoding, is of the length RFC 9580 gives the type, where it gives one:
/// a fixed length, or one the subpacket's own fields set. RFC 9580 §5.2.5
/// counts a subpacket of another length among the malformed signatures a
/// verifier ignores. A type of no fixed length is of any.
fn of_expected_length(subpacket_type: SubpacketType, body: &[u8]) -> bool {
    match subpacket_type {
        // A Boolean (§5.2.3.19, §5.2.3.20).
        SubpacketType::EXPORTABLE_CERTIFICATION | SubpacketType::REVOCABLE => body.len() == 1,
        // A depth and an amount (§5.2.3.21).
        SubpacketType::TRUST_SIGNATURE => body.len() == 2,
        // A class, an algorithm, and a version 4 fingerprint (§5.2.3.23).
        SubpacketType::REVOCATION_KEY => body.len() == 22,
        // Flags, the lengths of a name and a value, then the name and the
        // value (§5.2.3.24).
        SubpacketType::NOTATION_DATA => match body {
            [_, _, _, _, name_0, name_1, value_0, value_1, rest @ ..] => {
                let name = usize::from(u16::from_be_bytes([*name_0, *name_1]));
                let value = usize::from(u16::from_be_bytes([*value_0, *value_1]));
                name.checked_add(value) == Some(rest.len())
            }
            _ => false,
        },
        // Two algorithms, then a digest of the hash algorithm's length, if
        // RFC 9580 assigns the algorithm (§5.2.3.33).
        SubpacketType::SIGNATURE_TARGET => match body {
            [_, hash, digest @ ..] => HashAlgorithm(*hash)
                .digest_length()
                .is_none_or(|length| digest.len() == length),
            _ => false,
        },
        // A key version, then a fingerprint of that version's length, for
        // the versions RFC 9580 gives one (§5.2.3.36).
        SubpacketType::INTENDED_RECIPIENT_FINGERPRINT => match body {
            [4, fingerprint @ ..] => fingerprint.len() == 20,
            [6, fingerprint @ ..] => fingerprint.len() == 32,
            [_, ..] => true,
            [] => false,
        },
        // Pairs of algorithms (§5.2.3.15).
        SubpacketType::PREFERRED_AEAD_CIPHERSUITES => body.len().is_multiple_of(2),
        _ => true,
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
/// either area, and one of a type it keeps without decoding to be of the
/// length RFC 9580 gives the type, where it gives one. In the hashed area, a
/// subpacket marked critical must be one irongall honors; the bit carries no
/// weight in the unhashed area, which anyone can change. An embedded
/// signature is read as a signature, under the same `unhonored`, and appended
/// to `embedded_signatures`, unless the area is itself an embedded
/// signature's (`embedded`): one level only, so reading never recurses past
/// it. Where `unhonored` says to overlook what irongall cannot honor, a
/// malformed subpacket is kept as it is, one marked critical is kept, and an
/// embedded signature that does not read is left out.
///
/// The subpackets themselves are not held: the signature holds its body, and
/// [`Subpackets`] reads them from it again.
pub(super) fn read_area(
    mut area: Fields<'_>,
    which: Area,
    version: Version,
    embedded: bool,
    unhonored: Unhonored,
    embedded_signatures: &mut Vec<Signature>,
) -> Result<(), PacketError> {
    if !embedded {
        embedded_signatures.reserve_exact(count_embedded(area.clone()));
    }
    while let Some(Framed {
        start,
        subpacket,
        body: body_fields,
    }) = next(&mut area)?
    {
        let Subpacket {
            subpacket_type,
            critical: marked_critical,
            body,
        } = subpacket;
        let well_formed = match subpacket_type {
            SubpacketType::SIGNATURE_CREATION_TIME
            | SubpacketType::SIGNATURE_EXPIRATION_TIME
            | SubpacketType::KEY_EXPIRATION_TIME => time(body).is_some(),
            SubpacketType::ISSUER_KEY_ID => key_id(body).is_some(),
            SubpacketType::ISSUER_FINGERPRINT => fingerprint(body, version).is_some(),
            SubpacketType::PRIMARY_USER_ID => primary_user_id(body).is_some(),
            SubpacketType::REASON_FOR_REVOCATION => revocation_reason(body).is_some(),
            other => of_expected_length(other, body),
        };
        let refuse = unhonored == Unhonored::Refuse;
        if !well_formed && refuse {
            return Err(area.error_at(PacketErrorKind::InvalidSubpacket, start));
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
    }
    Ok(())
}

/// How many of `area`'s subpackets may be embedded signatures, counted by
/// their framing alone, up to the first subpacket that does not frame: those
/// of the type whose bodies are as long as a signature's can be. Reading them
/// then allocates once, and never for more signatures than the area's length
/// can hold.
fn count_embedded(mut area: Fields<'_>) -> usize {
    let mut count: usize = 0;
    while let Ok(Some(framed)) = next(&mut area) {
        if framed.subpacket.subpacket_type == SubpacketType::EMBEDDED_SIGNATURE
            && framed.subpacket.body.len() >= Signature::SHORTEST
        {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Reads a subpacket's length (RFC 9580 §5.2.3.7), which counts its type
/// octet and its body.
fn length(area: &mut Fields<'_>) -> Result<usize, PacketError> {
    Ok(match area.u8()? {
        octet @ 0..=191 => usize::from(octet),
        // At most 16319, so the addition cannot wrap. `& 0x3F` is `- 192`
        // over this range.
        octet @ 192..=254 => {
            let second = area.u8()?;
            usize::from(u16::from_be_bytes([octet & 0x3F, second]).wrapping_add(192))
        }
        255 => usize::try_from(area.u32()?).unwrap_or(usize::MAX),
    })
}
