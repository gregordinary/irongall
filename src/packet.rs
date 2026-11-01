//! OpenPGP packets (RFC 9580 §4): the framing every OpenPGP structure is built
//! from.
//!
//! A packet is a header, carrying the packet's type and the length of its
//! body, followed by the body. [`packets`] reads a byte string as a sequence of
//! packets, each borrowing its body from the input:
//!
//! ```
//! use irongall::packet::{self, Tag};
//!
//! // A User ID packet, `foo`, in the OpenPGP format, then the same in the
//! // legacy format.
//! let input = [0xCD, 0x03, b'f', b'o', b'o', 0xB4, 0x03, b'f', b'o', b'o'];
//! for packet in packet::packets(&input) {
//!     let packet = packet?;
//!     assert_eq!(packet.tag(), Tag::USER_ID);
//!     assert_eq!(packet.body(), b"foo");
//! }
//! # Ok::<(), irongall::packet::PacketError>(())
//! ```
//!
//! # What is accepted
//!
//! - Both header formats: the OpenPGP format, and the legacy format that
//!   RFC 9580 permits a reader to accept.
//! - Lengths that stream a packet of unknown size are refused: partial body
//!   lengths, and the legacy format's indeterminate length. RFC 9580 permits
//!   them only for data packets (literal, compressed, and encrypted data),
//!   which irongall does not read.
//! - Packet type 0, which RFC 9580 reserves, is refused.
//! - A body never extends past the end of the input (RFC 9580 §4.1).
//!
//! Framing does not judge a packet's type. An unknown type is returned like
//! any other, and what to do with it ([`Tag::is_critical`]) is decided by
//! whatever assembles the packets into a certificate or a signature.
//!
//! A failure ends the sequence, since nothing after a damaged header can be
//! located reliably.

use core::fmt;
use core::iter::FusedIterator;

use crate::wire::wire_number;

wire_number! {
    /// A packet's type (RFC 9580 §5).
    ///
    /// A header carries a type from 0 to 63. The constants name the types
    /// RFC 9580 assigns. Type 0 is reserved, and a packet of that type is
    /// refused.
    pub struct Tag;
    unnamed = "type";
    /// Public-Key Encrypted Session Key (1).
    const PUBLIC_KEY_ENCRYPTED_SESSION_KEY = 1, "Public-Key Encrypted Session Key";
    /// Signature (2).
    const SIGNATURE = 2, "Signature";
    /// Symmetric-Key Encrypted Session Key (3).
    const SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY = 3, "Symmetric-Key Encrypted Session Key";
    /// One-Pass Signature (4).
    const ONE_PASS_SIGNATURE = 4, "One-Pass Signature";
    /// Secret Key (5).
    const SECRET_KEY = 5, "Secret Key";
    /// Public Key (6).
    const PUBLIC_KEY = 6, "Public Key";
    /// Secret Subkey (7).
    const SECRET_SUBKEY = 7, "Secret Subkey";
    /// Compressed Data (8).
    const COMPRESSED_DATA = 8, "Compressed Data";
    /// Symmetrically Encrypted Data (9).
    const SYMMETRICALLY_ENCRYPTED_DATA = 9, "Symmetrically Encrypted Data";
    /// Marker (10).
    const MARKER = 10, "Marker";
    /// Literal Data (11).
    const LITERAL_DATA = 11, "Literal Data";
    /// Trust (12).
    const TRUST = 12, "Trust";
    /// User ID (13).
    const USER_ID = 13, "User ID";
    /// Public Subkey (14).
    const PUBLIC_SUBKEY = 14, "Public Subkey";
    /// User Attribute (17).
    const USER_ATTRIBUTE = 17, "User Attribute";
    /// Symmetrically Encrypted and Integrity Protected Data (18).
    const SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA = 18,
        "Symmetrically Encrypted and Integrity Protected Data";
    /// Padding (21).
    const PADDING = 21, "Padding";
}

impl Tag {
    /// Whether the type is critical: types 0 to 39 are, and 40 to 63 are not
    /// (RFC 9580 §4.3).
    ///
    /// A reader that meets a critical packet of a type it does not know must
    /// reject the whole sequence the packet is in, and must ignore an unknown
    /// packet that is not critical.
    pub const fn is_critical(self) -> bool {
        self.0 < 40
    }

    /// Whether a reader passes over a packet of the type in any sequence it
    /// appears in: Marker and Padding packets (RFC 9580 §5.8 and §5.14), and
    /// those of a type that is unknown and not critical (§4.3).
    ///
    /// A Trust packet is not among them. It belongs to a keyring alone
    /// (§5.10), where [`cert`](crate::cert) passes over it, and elsewhere it
    /// is a critical packet of a type the sequence does not admit, which
    /// refuses the sequence (§10).
    pub(crate) const fn is_passed_over(self) -> bool {
        matches!(self, Tag::MARKER | Tag::PADDING) || !self.is_critical()
    }
}

/// The version of a key or signature packet: the versions irongall reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Version {
    /// Version 4 (RFC 9580 §5.5.2.2 and §5.2.3), which every archive signs
    /// with today.
    V4,
    /// Version 6 (RFC 9580 §5.5.2.3 and §5.2.3).
    V6,
}

/// One packet, its body borrowed from the input it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    tag: Tag,
    body: &'a [u8],
    offset: usize,
    body_offset: usize,
}

impl<'a> Packet<'a> {
    /// The packet's type.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// The packet's body: everything after its header.
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Where the packet's header begins in the input it was read from.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// A cursor over the body's fields.
    pub(crate) fn fields(&self) -> Fields<'a> {
        Fields {
            rest: self.body,
            offset: self.body_offset,
            tag: Some(self.tag),
        }
    }

    /// A failure concerning the packet as a whole, at its header.
    pub(crate) fn error(&self, kind: PacketErrorKind) -> PacketError {
        PacketError {
            kind,
            tag: Some(self.tag),
            offset: self.offset,
        }
    }
}

/// Reads `input` as a sequence of packets.
///
/// The iterator yields each packet in turn, and ends at the end of the input
/// or after the first failure, which it yields.
pub fn packets(input: &[u8]) -> Packets<'_> {
    Packets {
        input,
        offset: 0,
        done: false,
    }
}

/// The packets of an input; see [`packets`].
#[derive(Debug, Clone)]
pub struct Packets<'a> {
    input: &'a [u8],
    /// Where the next packet's header begins.
    offset: usize,
    /// Set at the end of the input and after a failure.
    done: bool,
}

impl<'a> Packets<'a> {
    /// Reads the packet whose header begins at `self.offset`.
    fn read(&mut self) -> Result<Option<Packet<'a>>, PacketError> {
        let start = self.offset;
        let rest = self.input.get(start..).unwrap_or_default();
        if rest.is_empty() {
            return Ok(None);
        }
        let mut header = Fields {
            rest,
            offset: start,
            tag: None,
        };
        // Every framing failure is reported at the start of the header.
        let fail = |kind, tag| PacketError {
            kind,
            tag,
            offset: start,
        };
        let truncated = |tag| fail(PacketErrorKind::Truncated, Some(tag));

        let first = header
            .u8()
            .map_err(|_| fail(PacketErrorKind::Truncated, None))?;
        if first & 0x80 == 0 {
            return Err(fail(PacketErrorKind::InvalidHeader, None));
        }
        let (tag, length) = if first & 0x40 != 0 {
            let tag = Tag(first & 0x3F);
            if tag.0 == 0 {
                return Err(fail(PacketErrorKind::ReservedType, Some(tag)));
            }
            let length = match header.u8().map_err(|_| truncated(tag))? {
                octet @ 0..=191 => u32::from(octet),
                // At most 8383, so the addition cannot wrap.
                octet @ 192..=223 => {
                    let second = header.u8().map_err(|_| truncated(tag))?;
                    u32::from(u16::from_be_bytes([octet & 0x1F, second])).wrapping_add(192)
                }
                255 => header.u32().map_err(|_| truncated(tag))?,
                224..=254 => return Err(fail(PacketErrorKind::PartialBodyLength, Some(tag))),
            };
            (tag, length)
        } else {
            let tag = Tag((first >> 2) & 0x0F);
            if tag.0 == 0 {
                return Err(fail(PacketErrorKind::ReservedType, Some(tag)));
            }
            let length = match first & 0x03 {
                0 => u32::from(header.u8().map_err(|_| truncated(tag))?),
                1 => u32::from(header.u16().map_err(|_| truncated(tag))?),
                2 => header.u32().map_err(|_| truncated(tag))?,
                _ => return Err(fail(PacketErrorKind::IndeterminateLength, Some(tag))),
            };
            (tag, length)
        };

        let body_offset = header.offset;
        let body = usize::try_from(length)
            .ok()
            .and_then(|length| header.take(length).ok())
            .ok_or_else(|| truncated(tag))?;
        self.offset = header.offset;
        Ok(Some(Packet {
            tag,
            body,
            offset: start,
            body_offset,
        }))
    }
}

impl<'a> Iterator for Packets<'a> {
    type Item = Result<Packet<'a>, PacketError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let packet = self.read();
        self.done = !matches!(packet, Ok(Some(_)));
        packet.transpose()
    }
}

impl FusedIterator for Packets<'_> {}

/// A cursor over a byte string's fields, which reports a failure at the
/// offset in the original input of the field that failed.
#[derive(Debug, Clone)]
pub(crate) struct Fields<'a> {
    rest: &'a [u8],
    /// Where `rest` begins in the input.
    offset: usize,
    /// The type of the packet the fields belong to, once it is known.
    tag: Option<Tag>,
}

impl<'a> Fields<'a> {
    /// A failure at the cursor.
    pub(crate) fn error(&self, kind: PacketErrorKind) -> PacketError {
        self.error_at(kind, self.offset)
    }

    /// A failure at `offset`, in the same packet.
    pub(crate) fn error_at(&self, kind: PacketErrorKind, offset: usize) -> PacketError {
        PacketError {
            kind,
            tag: self.tag,
            offset,
        }
    }

    /// Where the cursor is in the input.
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    /// Takes the next `len` bytes.
    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], PacketError> {
        let (taken, rest) = self
            .rest
            .split_at_checked(len)
            .ok_or_else(|| self.error(PacketErrorKind::TruncatedBody))?;
        self.rest = rest;
        // No slice of an input in memory ends past `usize::MAX`.
        self.offset = self.offset.saturating_add(len);
        Ok(taken)
    }

    /// Takes the next `len` bytes as a cursor of their own, for a field that
    /// states its length and holds fields of its own.
    pub(crate) fn split(&mut self, len: usize) -> Result<Fields<'a>, PacketError> {
        let offset = self.offset;
        let rest = self.take(len)?;
        Ok(Fields {
            rest,
            offset,
            tag: self.tag,
        })
    }

    /// Takes the next `N` bytes.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], PacketError> {
        let (taken, rest) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or_else(|| self.error(PacketErrorKind::TruncatedBody))?;
        self.rest = rest;
        self.offset = self.offset.saturating_add(N);
        Ok(*taken)
    }

    /// Takes a one-octet scalar.
    pub(crate) fn u8(&mut self) -> Result<u8, PacketError> {
        self.array::<1>().map(u8::from_be_bytes)
    }

    /// Takes a two-octet scalar (RFC 9580 §3.1).
    pub(crate) fn u16(&mut self) -> Result<u16, PacketError> {
        self.array().map(u16::from_be_bytes)
    }

    /// Takes a four-octet scalar (RFC 9580 §3.1).
    pub(crate) fn u32(&mut self) -> Result<u32, PacketError> {
        self.array().map(u32::from_be_bytes)
    }

    /// Takes everything left.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let rest = self.rest;
        self.offset = self.offset.saturating_add(rest.len());
        self.rest = &[];
        rest
    }

    /// Whether nothing is left.
    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Checks that nothing is left.
    pub(crate) fn finish(&self) -> Result<(), PacketError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(self.error(PacketErrorKind::TrailingData))
        }
    }

    /// Takes a multiprecision integer (RFC 9580 §3.2), returning its value as
    /// big-endian bytes without leading zeros.
    ///
    /// The bits the length leaves unused must be zero. In a version 6 packet
    /// the length must also be exact, counting from the most significant bit
    /// that is set; a version 4 packet may overstate it, as some old
    /// implementations did, and the leading zeros are dropped.
    pub(crate) fn mpi(&mut self, version: Version) -> Result<&'a [u8], PacketError> {
        let start = self.offset;
        let bits = self.u16()?;
        let bytes = self.take(usize::from(bits).div_ceil(8))?;
        let Some(&first) = bytes.first() else {
            return Ok(bytes);
        };
        // How many bits of the first byte the length counts: one to eight.
        let counted = match bits & 7 {
            0 => 8,
            partial => u32::from(partial),
        };
        let unused_are_zero = u32::from(first).checked_shr(counted) == Some(0);
        let exact = u32::from(first).checked_shr(counted.saturating_sub(1)) == Some(1);
        if !unused_are_zero || (version == Version::V6 && !exact) {
            return Err(self.error_at(PacketErrorKind::InvalidMpi, start));
        }
        let significant = bytes
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(bytes.len());
        Ok(bytes.get(significant..).unwrap_or_default())
    }
}

/// A failure reading packets: what was wrong, in which packet, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketError {
    kind: PacketErrorKind,
    tag: Option<Tag>,
    offset: usize,
}

impl PacketError {
    /// What was wrong.
    pub fn kind(&self) -> PacketErrorKind {
        self.kind
    }

    /// The type of the packet the failure is in, unless the failure is in the
    /// first octet of its header, which carries the type.
    pub fn tag(&self) -> Option<Tag> {
        self.tag
    }

    /// Where in the input the failure was found: the start of the field that
    /// failed, for a failure inside a packet's body, and otherwise the start
    /// of the packet's header.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The same failure, described by a kind that says more about where it
    /// was found.
    pub(crate) fn with_kind(self, kind: PacketErrorKind) -> PacketError {
        PacketError { kind, ..self }
    }
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tag {
            Some(tag) => write!(f, "{tag} packet, offset {}: {}", self.offset, self.kind),
            None => write!(f, "packet at offset {}: {}", self.offset, self.kind),
        }
    }
}

impl core::error::Error for PacketError {}

/// What was wrong with a packet, as a [`PacketError`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PacketErrorKind {
    /// The first octet of a header lacks the bit every header sets.
    InvalidHeader,
    /// The header carries packet type 0, which RFC 9580 reserves.
    ReservedType,
    /// The header gives a partial body length, which only data packets use.
    PartialBodyLength,
    /// The legacy header gives an indeterminate length, which only data
    /// packets use.
    IndeterminateLength,
    /// The input ends inside the packet.
    Truncated,
    /// The body ends inside a field.
    TruncatedBody,
    /// The body continues after its last field.
    TrailingData,
    /// A multiprecision integer's length disagrees with its value: it leaves
    /// a set bit uncounted, or, in a version 6 packet, counts a zero one.
    InvalidMpi,
    /// The packet is not of a type the reader it was given to reads: a
    /// signature given to the key reader, for example, or secret key material
    /// or a message in a certificate.
    UnexpectedType,
    /// A key or signature packet of a version irongall does not read: only
    /// versions 4 and 6 are read.
    ///
    /// Such a packet is not damaged, and a reader can pass over it.
    UnsupportedVersion,
    /// A version 6 key's material is not the length its packet states.
    MaterialLength,
    /// Key material that is not valid for its algorithm.
    InvalidMaterial,
    /// A version 4 key whose packet body is too long to take a fingerprint:
    /// the fingerprint records the length in two octets.
    KeyTooLong,
    /// A version 6 signature whose salt is not the size its hash algorithm
    /// requires, or whose hash algorithm has no salt size, which version 6
    /// signatures cannot use (RFC 9580 §5.2.3 and §9.5).
    SaltSize,
    /// A signature subpacket that is malformed: empty, of a length its type
    /// does not allow, or an issuer fingerprint of a version other than its
    /// signature's (RFC 9580 §5.2.3.35).
    InvalidSubpacket,
    /// A signature without a creation time in its hashed subpackets, where
    /// RFC 9580 §5.2.3.11 requires one.
    MissingCreationTime,
    /// A signature whose hashed subpackets include one marked critical whose
    /// meaning irongall does not implement (RFC 9580 §5.2.3.7).
    ///
    /// Such a signature is not damaged, and a reader can pass over it.
    CriticalSubpacket,
    /// A signature of a type that does not belong where it is: in a
    /// certificate, a subkey binding after a user ID, for example; with a
    /// document, a signature that is not over one; in a cleartext signed
    /// message, a signature that is not a text signature.
    MisplacedSignature,
    /// A subkey whose version is not its primary key's (RFC 9580 §10.1.1 and
    /// §10.1.3).
    SubkeyVersion,
    /// A user ID in a certificate longer than 2048 octets, the longest
    /// irongall reads there, and the longest GnuPG reads.
    UserIdTooLong,
}

impl fmt::Display for PacketErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PacketErrorKind::InvalidHeader => "a packet header without its leading bit set",
            PacketErrorKind::ReservedType => "the reserved packet type 0",
            PacketErrorKind::PartialBodyLength => {
                "a partial body length, which only data packets use"
            }
            PacketErrorKind::IndeterminateLength => {
                "an indeterminate length, which only data packets use"
            }
            PacketErrorKind::Truncated => "the input ends inside the packet",
            PacketErrorKind::TruncatedBody => "the body ends inside a field",
            PacketErrorKind::TrailingData => "the body continues after its last field",
            PacketErrorKind::InvalidMpi => {
                "a multiprecision integer whose length disagrees with it"
            }
            PacketErrorKind::UnexpectedType => "not a packet of the type expected",
            PacketErrorKind::UnsupportedVersion => "a packet version irongall does not read",
            PacketErrorKind::MaterialLength => {
                "key material of a length other than its packet states"
            }
            PacketErrorKind::InvalidMaterial => "key material that is not valid for its algorithm",
            PacketErrorKind::KeyTooLong => "a version 4 key too long to take a fingerprint",
            PacketErrorKind::SaltSize => {
                "a salt of a size other than the signature's hash algorithm requires"
            }
            PacketErrorKind::InvalidSubpacket => "a malformed signature subpacket",
            PacketErrorKind::MissingCreationTime => {
                "a signature without a creation time in its hashed subpackets"
            }
            PacketErrorKind::CriticalSubpacket => {
                "a critical signature subpacket whose meaning irongall does not implement"
            }
            PacketErrorKind::MisplacedSignature => {
                "a signature of a type that does not belong where it is"
            }
            PacketErrorKind::SubkeyVersion => "a subkey of a version other than its primary key's",
            PacketErrorKind::UserIdTooLong => "a user ID longer than 2048 octets",
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use alloc::{format, vec};

    use super::{Packet, PacketError, PacketErrorKind, Tag, Version, packets};

    /// The first packet of `input`.
    fn first(input: &[u8]) -> Result<Packet<'_>, PacketError> {
        packets(input).next().expect("a packet or a failure")
    }

    /// `header` followed by `len` bytes of body and, after them, one more
    /// packet, so a length that overreads or underreads shows.
    fn framed(header: &[u8], len: usize) -> Vec<u8> {
        [header, &vec![0x5A; len], &[0xCD, 0x01, 0x21]].concat()
    }

    #[test]
    fn openpgp_format_lengths() {
        // The edges of each length form, and RFC 9580 §4.2.3's examples.
        for (header, len) in [
            (&[0xC2, 0x00][..], 0),
            (&[0xC2, 0x64], 100),
            (&[0xC2, 0xBF], 191),
            (&[0xC2, 0xC0, 0x00], 192),
            (&[0xC2, 0xC5, 0xFB], 1723),
            (&[0xC2, 0xDF, 0xFF], 8383),
            (&[0xC2, 0xFF, 0x00, 0x00, 0x00, 0x00], 0),
            (&[0xC2, 0xFF, 0x00, 0x01, 0x86, 0xA0], 100_000),
        ] {
            let input = framed(header, len);
            let mut read = packets(&input);
            let packet = read.next().unwrap().unwrap();
            assert_eq!(packet.tag(), Tag::SIGNATURE, "{header:02X?}");
            assert_eq!(packet.body().len(), len, "{header:02X?}");
            assert_eq!(packet.offset(), 0);
            let next = read.next().unwrap().unwrap();
            assert_eq!((next.tag(), next.body()), (Tag::USER_ID, &b"!"[..]));
            assert_eq!(next.offset(), header.len() + len);
            assert!(read.next().is_none());
        }
    }

    #[test]
    fn legacy_format_lengths() {
        for (header, len) in [
            (&[0x88, 0x00][..], 0),
            (&[0x88, 0xFF], 255),
            (&[0x89, 0x01, 0x00], 256),
            (&[0x89, 0xFF, 0xFF], 65535),
            (&[0x8A, 0x00, 0x01, 0x00, 0x00], 65536),
        ] {
            let input = framed(header, len);
            let packet = first(&input).unwrap();
            assert_eq!(packet.tag(), Tag::SIGNATURE, "{header:02X?}");
            assert_eq!(packet.body().len(), len, "{header:02X?}");
        }
        // The legacy format's type field has four bits.
        assert_eq!(first(&[0xB8, 0x00]).unwrap().tag(), Tag::PUBLIC_SUBKEY);
        assert_eq!(first(&[0xBC, 0x00]).unwrap().tag().number(), 15);
        assert_eq!(first(&[0xFF, 0x00]).unwrap().tag().number(), 63);
    }

    #[test]
    fn framing_failures_end_the_sequence() {
        for (input, kind, tag, offset) in [
            (&[0x00][..], PacketErrorKind::InvalidHeader, None, 0),
            (&[0x7F, 0x00], PacketErrorKind::InvalidHeader, None, 0),
            (&[0xC0, 0x00], PacketErrorKind::ReservedType, Some(0), 0),
            (&[0x80, 0x00], PacketErrorKind::ReservedType, Some(0), 0),
            (&[0xC2], PacketErrorKind::Truncated, Some(2), 0),
            (&[0xC2, 0xC0], PacketErrorKind::Truncated, Some(2), 0),
            (
                &[0xC2, 0xFF, 0x00, 0x00, 0x00],
                PacketErrorKind::Truncated,
                Some(2),
                0,
            ),
            (
                &[0xC2, 0x05, 0x01, 0x02],
                PacketErrorKind::Truncated,
                Some(2),
                0,
            ),
            (&[0x89, 0x00], PacketErrorKind::Truncated, Some(2), 0),
            (
                &[0xCB, 0xE0, 0x00],
                PacketErrorKind::PartialBodyLength,
                Some(11),
                0,
            ),
            (
                &[0xCB, 0xFE, 0x00],
                PacketErrorKind::PartialBodyLength,
                Some(11),
                0,
            ),
            (
                &[0xAF, 0x00],
                PacketErrorKind::IndeterminateLength,
                Some(11),
                0,
            ),
            // After a well-formed packet, at the failing packet's header.
            (
                &[0xCD, 0x01, 0x21, 0x00],
                PacketErrorKind::InvalidHeader,
                None,
                3,
            ),
            (
                &[0xCD, 0x01, 0x21, 0xC2, 0x02, 0x00],
                PacketErrorKind::Truncated,
                Some(2),
                3,
            ),
        ] {
            let mut read = packets(input);
            let error = loop {
                match read.next().unwrap() {
                    Ok(_) => continue,
                    Err(error) => break error,
                }
            };
            assert_eq!(error.kind(), kind, "{input:02X?}");
            assert_eq!(error.tag().map(Tag::number), tag, "{input:02X?}");
            assert_eq!(error.offset(), offset, "{input:02X?}");
            assert!(read.next().is_none(), "{input:02X?}");
            assert!(read.next().is_none(), "{input:02X?}");
        }
        assert!(packets(&[]).next().is_none());
    }

    #[test]
    fn tags() {
        assert!(Tag(39).is_critical());
        assert!(!Tag(40).is_critical());
        assert_eq!(format!("{}", Tag::PUBLIC_SUBKEY), "Public Subkey");
        assert_eq!(format!("{}", Tag(42)), "type 42");
        assert_eq!(format!("{:?}", Tag::SIGNATURE), "Tag(2: Signature)");
    }

    #[test]
    fn errors_name_packet_and_offset() {
        let error = first(&[0xCD, 0x05, 0x00]).unwrap_err();
        assert_eq!(
            format!("{error}"),
            "User ID packet, offset 0: the input ends inside the packet"
        );
        let error = first(&[0x00]).unwrap_err();
        assert_eq!(
            format!("{error}"),
            "packet at offset 0: a packet header without its leading bit set"
        );
    }

    #[test]
    fn mpis() {
        let read = |bytes: &[u8], version| {
            let packet = Packet {
                tag: Tag::SIGNATURE,
                body: bytes,
                offset: 0,
                body_offset: 10,
            };
            let mut fields = packet.fields();
            let value = fields.mpi(version).map(<[u8]>::to_vec);
            value.map(|value| (value, fields.rest().len()))
        };
        // RFC 9580 §3.2's examples, whatever the version.
        for version in [Version::V4, Version::V6] {
            assert_eq!(read(&[0x00, 0x00], version).unwrap(), (Vec::new(), 0));
            assert_eq!(
                read(&[0x00, 0x01, 0x01], version).unwrap(),
                ([0x01].to_vec(), 0)
            );
            assert_eq!(
                read(&[0x00, 0x09, 0x01, 0xFF, 0xAA], version).unwrap(),
                ([0x01, 0xFF].to_vec(), 1)
            );
            let full = [&[0x01, 0x00][..], &[0xFF; 32]].concat();
            assert_eq!(read(&full, version).unwrap(), ([0xFF; 32].to_vec(), 0));
            // A set bit the length does not count.
            let error = read(&[0x00, 0x01, 0x03], version).unwrap_err();
            assert_eq!(
                (error.kind(), error.offset()),
                (PacketErrorKind::InvalidMpi, 10)
            );
            let error = read(&[0x00, 0x09, 0x01], version).unwrap_err();
            assert_eq!(
                (error.kind(), error.offset()),
                (PacketErrorKind::TruncatedBody, 12)
            );
            let error = read(&[0x00], version).unwrap_err();
            assert_eq!(error.kind(), PacketErrorKind::TruncatedBody);
        }
        // A length that counts leading zeros: tolerated in version 4, where the
        // zeros are dropped, and refused in version 6.
        for overstated in [&[0x00, 0x02, 0x01][..], &[0x00, 0x10, 0x00, 0x01]] {
            assert_eq!(read(overstated, Version::V4).unwrap(), ([0x01].to_vec(), 0));
            let error = read(overstated, Version::V6).unwrap_err();
            assert_eq!(error.kind(), PacketErrorKind::InvalidMpi);
        }
        assert_eq!(
            read(&[0x00, 0x08, 0x00], Version::V4).unwrap(),
            (Vec::new(), 0)
        );
        assert_eq!(
            read(&[0x00, 0x08, 0x00], Version::V6).unwrap_err().kind(),
            PacketErrorKind::InvalidMpi
        );
    }
}
