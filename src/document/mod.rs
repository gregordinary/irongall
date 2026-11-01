//! Signed documents: cleartext signed messages (RFC 9580 §7), and detached
//! signatures (RFC 9580 §10.4).
//!
//! A cleartext signed message carries its text as it is, followed by an
//! armored block of signatures over it. [`cleartext`] reads one into a
//! [`Cleartext`]: the text, in the form its signatures are made over it, and
//! the signatures. A detached signature travels apart from the document it is
//! over, in a file of its own; [`detached`] reads such a file, armored or
//! binary, into a [`Detached`].
//!
//! The signatures are then checked with [`Signature::verify`] over
//! [`Subject::Document`], or, for a document too large to hold whole, with
//! [`Signature::document_hash`]:
//!
//! ```
//! use irongall::signature::Subject;
//! use irongall::{armor, cert, document};
//!
//! // The cleartext signed message of RFC 9580 Appendix A.6.
//! let message = "\
//! -----BEGIN PGP SIGNED MESSAGE-----
//!
//! What we need from the grocery store:
//!
//! - - tofu
//! - - vegetables
//! - - noodles
//!
//! -----BEGIN PGP SIGNATURE-----
//!
//! wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
//! 2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
//! /FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
//! NK2ay45cX1IVAQ==
//! -----END PGP SIGNATURE-----
//! ";
//! let message = document::cleartext(message.as_bytes())?;
//! assert_eq!(
//!     message.text(),
//!     b"What we need from the grocery store:\r\n\r\n- tofu\r\n- vegetables\r\n- noodles\r\n"
//! );
//!
//! // The certificate of Appendix A.3, whose primary key made the signature.
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
//! # let data = armor::decode(certificate.as_bytes())?.into_data();
//! # let certificate = cert::certificates(&data).next().unwrap()?;
//! let key = certificate.primary();
//! for signature in message.signatures() {
//!     signature.verify(key, Subject::Document(message.text()))?;
//! }
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # What is read
//!
//! - A cleartext signed message is read as [`armor`] reads a
//!   block, and its text as GnuPG reads it: each line has its dash-escape
//!   removed, then its trailing spaces, tabs, and carriage returns, and the
//!   lines are joined with CR LF, without the line ending before the
//!   signatures. A line of the text that begins with a dash and is not
//!   dash-escaped is refused, as is any armor header but a well-formed
//!   `Hash` header (RFC 9580 §7.1), and anything but blank lines before or
//!   after the message.
//! - A detached signature file is armored if its first octet is not that of
//!   a packet header. Its armor label is not checked; the packets decide what
//!   it holds.
//! - The signature data must hold only Signature packets, apart from Marker
//!   and Padding packets and those of an unknown type that is not critical,
//!   which are passed over (RFC 9580 §4.3 and §10.4). Any other packet, such
//!   as the literal data of an inline-signed message, or a Trust packet,
//!   which belongs to a keyring, refuses the input (§10).
//! - A signature that does not read is passed over, and the others read
//!   without it, as RFC 9580 §5.2.5 requires. So is a signature of a type
//!   that is not made over the document: a cleartext signed message holds
//!   text signatures (§7.1), and a detached signature is a binary or a text
//!   signature. The reasons are kept: [`Cleartext::skipped`] and
//!   [`Detached::skipped`].
//!
//! [`Signature::document_hash`]: crate::signature::Signature::document_hash
//! [`Signature::verify`]: crate::signature::Signature::verify
//! [`Subject::Document`]: crate::signature::Subject::Document

#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use core::fmt;

use crate::armor::{self, ArmorError};
use crate::packet::{self, PacketError, PacketErrorKind, Tag};
use crate::signature::{Signature, SignatureType};

/// A cleartext signed message: a text and the signatures over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cleartext {
    text: Vec<u8>,
    signatures: Vec<Signature>,
    skipped: Vec<PacketError>,
}

impl Cleartext {
    /// The signed text, in the form its signatures are made over it: its
    /// dash-escapes removed, the spaces, tabs, and carriage returns at the
    /// end of each line removed, and its lines joined with CR LF.
    ///
    /// This is not always the text as the message shows it, whose trailing
    /// whitespace and line endings are not signed. A caller that acts on the
    /// text should act on this, which is what the signatures cover.
    pub fn text(&self) -> &[u8] {
        &self.text
    }

    /// The signatures, in the order they appear: text signatures only.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// The signatures that were passed over, each with the reason: those
    /// that do not read, and those that are not text signatures.
    ///
    /// The offset of each is in the data the signature block decodes to.
    pub fn skipped(&self) -> &[PacketError] {
        &self.skipped
    }
}

/// Reads `input` as a cleartext signed message.
///
/// # Errors
///
/// When the input is not exactly one well-formed cleartext signed message, as
/// [`DocumentError::Armor`], or its signature block holds something other
/// than signatures, or its packets are malformed, as
/// [`DocumentError::Packet`].
pub fn cleartext(input: &[u8]) -> Result<Cleartext, DocumentError> {
    let (text, block) = armor::decode_cleartext(input)?;
    let (signatures, skipped) = signatures(block.data(), &[SignatureType::TEXT])?;
    Ok(Cleartext {
        text,
        signatures,
        skipped,
    })
}

/// The signatures of a detached signature file.
///
/// A binary signature (0x00) is made over the file's exact octets, and a
/// text signature (0x01) over the file with its line endings made CR LF, so
/// a text signature verifies over every form of the file that differs only
/// in the CRs before its LFs and at its end. The signer chooses the type. A
/// caller verifying a file whose every octet counts refuses text signatures
/// with [`Policy::with_text_signatures`].
///
/// [`Policy::with_text_signatures`]: crate::policy::Policy::with_text_signatures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detached {
    signatures: Vec<Signature>,
    skipped: Vec<PacketError>,
}

impl Detached {
    /// The signatures, in the order they appear: binary and text signatures
    /// only.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// The signatures that were passed over, each with the reason: those
    /// that do not read, and those that are not made over a document.
    ///
    /// The offset of each is in the binary data: for an armored file, the
    /// data the armor decodes to.
    pub fn skipped(&self) -> &[PacketError] {
        &self.skipped
    }
}

/// Reads `input` as a detached signature file: one or more signatures,
/// binary or armored.
///
/// # Errors
///
/// When armored input is not exactly one well-formed armored block, as
/// [`DocumentError::Armor`], or the data holds something other than
/// signatures, or its packets are malformed, as [`DocumentError::Packet`].
pub fn detached(input: &[u8]) -> Result<Detached, DocumentError> {
    // Every packet header sets the high bit of its first octet, and no
    // armor does.
    let (signatures, skipped) = if input.first().is_some_and(|&octet| octet & 0x80 != 0) {
        signatures(input, DOCUMENT_TYPES)?
    } else {
        signatures(armor::decode(input)?.data(), DOCUMENT_TYPES)?
    };
    Ok(Detached {
        signatures,
        skipped,
    })
}

/// The types of the signatures made over a document (RFC 9580 §5.2.1.1 and
/// §5.2.1.2).
const DOCUMENT_TYPES: &[SignatureType] = &[SignatureType::BINARY, SignatureType::TEXT];

/// Reads the signatures `data` holds, keeping those of `types` and passing
/// over, with the reason, those of any other type and those that do not
/// read.
fn signatures(
    data: &[u8],
    types: &[SignatureType],
) -> Result<(Vec<Signature>, Vec<PacketError>), PacketError> {
    let mut signatures = Vec::new();
    let mut skipped = Vec::new();
    for packet in packet::packets(data) {
        let packet = packet?;
        match packet.tag() {
            Tag::SIGNATURE => match Signature::from_packet(&packet) {
                Ok(signature) if types.contains(&signature.signature_type()) => {
                    signatures.push(signature);
                }
                Ok(_) => skipped.push(packet.error(PacketErrorKind::MisplacedSignature)),
                Err(error) => skipped.push(error),
            },
            tag if tag.is_passed_over() => {}
            _ => return Err(packet.error(PacketErrorKind::UnexpectedType)),
        }
    }
    Ok((signatures, skipped))
}

/// A failure reading a signed document: in its armor, or in its packets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DocumentError {
    /// The armor is malformed, or the cleartext signed message around it.
    Armor(ArmorError),
    /// The signature data holds a packet that is not a signature, or its
    /// framing is malformed. The offset is in the binary data: for armored
    /// input, the data the armor decodes to.
    Packet(PacketError),
}

impl fmt::Display for DocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DocumentError::Armor(error) => error.fmt(f),
            DocumentError::Packet(error) => error.fmt(f),
        }
    }
}

impl core::error::Error for DocumentError {}

impl From<ArmorError> for DocumentError {
    fn from(error: ArmorError) -> DocumentError {
        DocumentError::Armor(error)
    }
}

impl From<PacketError> for DocumentError {
    fn from(error: PacketError) -> DocumentError {
        DocumentError::Packet(error)
    }
}
