//! How a key or signature packet's body departs from the form RFC 9580 gives
//! it, or holds what irongall reads no further, read here apart from both
//! implementations' readers, so that a packet only one of them reads is told
//! apart by what is in it.
//!
//! Each departure found is named by the [`Divergence`] it explains: a rule
//! one of the two keeps in reading and the other does not. What neither
//! reads, such as a body cut short, is not a departure; both refuse it.

use std::collections::BTreeSet;

use super::Divergence;

/// The departures from its form in the body of a Key or Subkey packet.
pub(crate) fn key(body: &[u8]) -> BTreeSet<Divergence> {
    let mut found = BTreeSet::new();
    key_into(body, &mut found);
    found
}

/// The departures from its form in the body of a Signature packet, and in
/// the bodies of the signatures it embeds.
pub(crate) fn signature(body: &[u8]) -> BTreeSet<Divergence> {
    let mut found = BTreeSet::new();
    signature_into(body, false, &mut found);
    found
}

/// The departures from its form in the packet header that begins `header`
/// (§4.2): a length that streams the packet, which in the OpenPGP format is
/// a partial body length and in the legacy format the indeterminate length
/// type 3, and the reserved packet type 0.
pub(crate) fn header(header: &[u8]) -> BTreeSet<Divergence> {
    let mut found = BTreeSet::new();
    let (kind, streamed) = match header {
        [first, length, ..] if first & 0xC0 == 0xC0 => (first & 0x3F, (224..=254).contains(length)),
        [first, ..] if first & 0xC0 == 0x80 => ((first >> 2) & 0x0F, first & 0x03 == 3),
        _ => return found,
    };
    if streamed {
        found.insert(Divergence::StreamedLength);
    }
    if kind == 0 {
        found.insert(Divergence::ReservedType);
    }
    found
}

/// The octets of a body, read from the front.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(taken)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|octets| octets[0])
    }

    fn u16(&mut self) -> Option<usize> {
        self.take(2)
            .map(|octets| usize::from(u16::from_be_bytes([octets[0], octets[1]])))
    }

    fn u32(&mut self) -> Option<usize> {
        self.take(4)
            .map(|octets| u32::from_be_bytes(octets.try_into().unwrap()) as usize)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The truncated DER encoding of the Ed25519Legacy curve's OID (RFC 9580
/// §9.2).
const ED25519_LEGACY_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

fn key_into(body: &[u8], found: &mut BTreeSet<Divergence>) -> Option<()> {
    let mut body = Cursor(body);
    let version = body.u8()?;
    if version != 4 && version != 6 {
        found.insert(Divergence::OtherVersion);
        return None;
    }
    body.take(4)?;
    let algorithm = body.u8()?;
    if version == 6 {
        // A four-octet count of the material that follows (§5.5.2.3).
        let count = body.u32()?;
        if count != body.0.len() {
            found.insert(Divergence::MaterialCount);
        }
    }
    match algorithm {
        // RSA (§5.5.5.1): the modulus and the exponent.
        1..=3 => {
            let modulus = mpi(&mut body, version, found)?;
            let exponent = mpi(&mut body, version, found)?;
            if !usable_rsa(modulus, exponent) {
                found.insert(Divergence::InvalidRsaKey);
            }
        }
        // Ed25519 (§5.5.5.9): the native point.
        27 => point(body.take(32)?, found),
        // EdDSALegacy over Ed25519Legacy (§5.5.5.5), in version 4 alone:
        // the curve, then the point prefixed with 0x40. The curve's lengths
        // 0 and 0xFF are reserved, for a field of no form RFC 9580 defines.
        22 if version == 4 => {
            let length = body.u8()?;
            if length == 0
                || length == 0xFF
                || body.take(usize::from(length))? != ED25519_LEGACY_OID
            {
                found.insert(Divergence::OpaqueMaterial);
                return None;
            }
            let start = body.0;
            mpi(&mut body, version, found)?;
            if let [_, _, 0x40, native @ ..] = &start[..start.len() - body.0.len()]
                && native.len() == 32
            {
                point(native, found);
            }
        }
        _ => {
            found.insert(Divergence::OpaqueMaterial);
            return None;
        }
    }
    if !body.is_empty() {
        found.insert(Divergence::TrailingMaterial);
    }
    Some(())
}

/// Notes an Ed25519 point that is not a point of the curve.
fn point(encoding: &[u8], found: &mut BTreeSet<Divergence>) {
    let encoding: [u8; 32] = encoding.try_into().unwrap();
    if ed25519_dalek::VerifyingKey::from_bytes(&encoding).is_err() {
        found.insert(Divergence::PointOffCurve);
    }
}

/// Reads an MPI (§3.2), noting one whose length is not its value's: one
/// counting fewer bits than the value has, or, in version 6, more. Returns
/// its value, big-endian, without leading zeros.
fn mpi<'a>(
    body: &mut Cursor<'a>,
    version: u8,
    found: &mut BTreeSet<Divergence>,
) -> Option<&'a [u8]> {
    let bits = body.u16()?;
    let value = body.take(bits.div_ceil(8))?;
    if let Some(&first) = value.first() {
        let counted = match bits % 8 {
            0 => 8,
            partial => partial,
        };
        let has = 8 - first.leading_zeros() as usize;
        if has > counted || (version == 6 && has < counted) {
            found.insert(Divergence::MpiLength);
        }
    }
    let significant = value
        .iter()
        .position(|&octet| octet != 0)
        .unwrap_or(value.len());
    Some(&value[significant..])
}

/// Notes, in a signature `embedded` in another, an MPI at the front of
/// `body` written with a leading zero octet, as a version 4 MPI may be
/// (§3.2): one that is written back shorter without it.
fn padded(body: &Cursor<'_>, embedded: bool, found: &mut BTreeSet<Divergence>) {
    if let [high, low, 0, ..] = body.0
        && (*high, *low) != (0, 0)
        && embedded
    {
        found.insert(Divergence::ReencodedEmbeddedSignature);
    }
}

/// Whether an RSA key of `modulus` and `exponent`, each big-endian without
/// leading zeros, is one RSA verifies with: an odd modulus of at most 8192
/// bits, and an odd exponent from 3 to 2^33 - 1 and below the modulus.
fn usable_rsa(modulus: &[u8], exponent: &[u8]) -> bool {
    let odd = |value: &[u8]| value.last().is_some_and(|low| low & 1 == 1);
    let bits = |value: &[u8]| {
        value
            .first()
            .map_or(0, |first| value.len() * 8 - first.leading_zeros() as usize)
    };
    odd(modulus)
        && bits(modulus) <= 8192
        && odd(exponent)
        && exponent != [1]
        && bits(exponent) <= 33
        && (exponent.len(), exponent) < (modulus.len(), modulus)
}

fn signature_into(body: &[u8], embedded: bool, found: &mut BTreeSet<Divergence>) -> Option<()> {
    let mut body = Cursor(body);
    let version = body.u8()?;
    if version != 4 && version != 6 {
        found.insert(Divergence::OtherVersion);
        return None;
    }
    let signature_type = body.u8()?;
    if embedded && signature_type != 0x19 {
        found.insert(Divergence::EmbeddedSignatureType);
    }
    let algorithm = body.u8()?;
    body.u8()?;
    let area = |body: &mut Cursor<'_>| match version {
        4 => body.u16(),
        _ => body.u32(),
    };
    let length = area(&mut body)?;
    let hashed = subpackets(body.take(length)?, version, embedded, true, found)?;
    if !hashed.contains(&2) {
        found.insert(Divergence::NoCreationTime);
    }
    let length = area(&mut body)?;
    subpackets(body.take(length)?, version, embedded, false, found)?;
    body.take(2)?;
    if version == 6 {
        let salt = body.u8()?;
        body.take(usize::from(salt))?;
    }
    match algorithm {
        // RSA's encrypt-only variant, which signs nothing: noted where its
        // material is not one MPI, which RSA's reading would make it.
        2 => {
            let mut material = Cursor(body.0);
            if mpi(&mut material, version, found).is_none() || !material.is_empty() {
                found.insert(Divergence::EncryptOnlyMaterial);
            }
            return Some(());
        }
        // RSA (§5.2.3.1).
        1 | 3 => {
            padded(&body, embedded, found);
            mpi(&mut body, version, found)?;
        }
        // Ed25519 (§5.2.3.4).
        27 => {
            body.take(64)?;
        }
        // EdDSALegacy (§5.2.3.3), in version 4 alone: R and S.
        22 if version == 4 => {
            padded(&body, embedded, found);
            mpi(&mut body, version, found)?;
            padded(&body, embedded, found);
            mpi(&mut body, version, found)?;
        }
        _ => {
            found.insert(Divergence::OpaqueMaterial);
            return Some(());
        }
    }
    if !body.is_empty() {
        found.insert(Divergence::TrailingMaterial);
    }
    Some(())
}

/// Reads a subpacket area (§5.2.3.7) of a signature of `version`, noting its
/// departures, and returns the types it holds; `None` if its framing fails,
/// which neither reads past.
fn subpackets(
    area: &[u8],
    version: u8,
    embedded: bool,
    hashed: bool,
    found: &mut BTreeSet<Divergence>,
) -> Option<Vec<u8>> {
    let mut area = Cursor(area);
    let mut types = Vec::new();
    while !area.is_empty() {
        let length = match area.u8()? {
            octet @ 0..=191 => usize::from(octet),
            octet @ 192..=254 => (usize::from(octet - 192) << 8) + usize::from(area.u8()?) + 192,
            255 => area.u32()?,
        };
        let subpacket = area.take(length)?;
        let (&octet, body) = subpacket.split_first()?;
        let (critical, kind) = (octet & 0x80 != 0, octet & 0x7F);
        types.push(kind);
        if !decoded_form(kind, body, version) {
            found.insert(Divergence::MalformedSubpacket);
        }
        if !undecoded_form(kind, body) {
            found.insert(Divergence::UndecodedSubpacket);
        }
        if hashed && critical && !honored(kind, embedded) {
            found.insert(Divergence::CriticalSubpacket);
        }
        if kind == 32 {
            if embedded {
                found.insert(Divergence::NestedEmbeddedSignature);
            } else {
                signature_into(body, true, found);
            }
        }
    }
    Some(types)
}

/// Whether a subpacket of a type irongall decodes has the form RFC 9580
/// gives it; every other type passes.
fn decoded_form(kind: u8, body: &[u8], version: u8) -> bool {
    match kind {
        // Creation, expiration, and key expiration times (§5.2.3.11,
        // §5.2.3.18, §5.2.3.13): four octets.
        2 | 3 | 9 => body.len() == 4,
        // An issuer key ID (§5.2.3.12).
        16 => body.len() == 8,
        // An issuer fingerprint (§5.2.3.35): of the signature's version.
        33 => match body.split_first() {
            Some((4, fingerprint)) => version == 4 && fingerprint.len() == 20,
            Some((6, fingerprint)) => version == 6 && fingerprint.len() == 32,
            _ => false,
        },
        // A Primary User ID (§5.2.3.27): a Boolean, 0 or 1.
        25 => matches!(body, [0] | [1]),
        // A reason for revocation (§5.2.3.31): a code, then a message.
        29 => !body.is_empty(),
        _ => true,
    }
}

/// Whether a subpacket of a type irongall keeps as it is, without decoding
/// it, has the form RFC 9580 gives it; every other type passes.
fn undecoded_form(kind: u8, body: &[u8]) -> bool {
    let text = |octets: &[u8]| std::str::from_utf8(octets).is_ok();
    match kind {
        // Exportable Certification and Revocable (§5.2.3.19, §5.2.3.20): a
        // Boolean.
        4 | 7 => body.len() == 1,
        // Trust Signature (§5.2.3.21): a level and an amount.
        5 => body.len() == 2,
        // Regular Expression (§5.2.3.22): text ending with a zero octet.
        6 => body
            .split_last()
            .is_some_and(|(&last, text_part)| last == 0 && text(text_part)),
        // Revocation Key (§5.2.3.23): a class, an algorithm, a fingerprint.
        // The class sets 0x80, and perhaps 0x40; its other bits are kept for
        // a future expansion that gives them a form.
        12 => body.len() == 22 && matches!(body[0], 0x80 | 0xC0),
        // Notation Data (§5.2.3.24): flags, of which only the first bit is
        // defined and the rest must be zero, the two lengths, the name and
        // the value, the name text.
        20 => match body {
            [flags, 0, 0, 0, a, b, c, d, rest @ ..] if flags & 0x7F == 0 => {
                let name = usize::from(u16::from_be_bytes([*a, *b]));
                let value = usize::from(u16::from_be_bytes([*c, *d]));
                rest.len() == name + value && text(&rest[..name])
            }
            _ => false,
        },
        // Preferred Key Server, Policy URI, Signer's User ID (§5.2.3.26,
        // §5.2.3.28, §5.2.3.30): text.
        24 | 26 | 28 => text(body),
        // Signature Target (§5.2.3.33): algorithms, and a hash of the
        // hash algorithm's size.
        31 => match body {
            [_, hash, digest @ ..] => digest_size(*hash).is_none_or(|size| digest.len() == size),
            _ => false,
        },
        // Intended Recipient Fingerprint (§5.2.3.36): a key version, and a
        // fingerprint of that version.
        35 => match body.split_first() {
            Some((4, fingerprint)) => fingerprint.len() == 20,
            Some((6, fingerprint)) => fingerprint.len() == 32,
            _ => false,
        },
        // Preferred AEAD Ciphersuites (§5.2.3.15): pairs of algorithms.
        39 => body.len().is_multiple_of(2),
        _ => true,
    }
}

/// The size of a digest of the hash algorithm numbered `hash` (§9.5), if it
/// is one RFC 9580 assigns.
fn digest_size(hash: u8) -> Option<usize> {
    match hash {
        1 => Some(16),
        2 | 3 => Some(20),
        8 | 12 => Some(32),
        9 => Some(48),
        10 | 14 => Some(64),
        11 => Some(28),
        _ => None,
    }
}

/// Whether irongall honors a subpacket of type `kind` marked critical, in a
/// signature that is `embedded` in another or not: those it decodes, an
/// embedded signature where it reads one, and those whose meaning cannot
/// change whether a signature verifies (§5.2.3.7).
fn honored(kind: u8, embedded: bool) -> bool {
    match kind {
        2 | 3 | 9 | 16 | 25 | 27 | 29 | 33 => true,
        32 => !embedded,
        11 | 21 | 22 | 23 | 24 | 26 | 28 | 30 | 39 => true,
        _ => false,
    }
}
