//! ASCII armor (RFC 9580 §6.2): OpenPGP data carried as text.
//!
//! An armored block is a header line naming what the block holds, optional
//! armor headers, a blank line, the data in base64, an optional checksum line,
//! and a tail line repeating the header line's label:
//!
//! ```text
//! -----BEGIN PGP SIGNATURE-----
//! Comment: an optional armor header
//!
//! iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/VvkMypjiECY3vZg/2xbBMd/S
//! ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE
//! -----END PGP SIGNATURE-----
//! ```
//!
//! [`decode`] reads one block and [`decode_all`] reads one or more, such as a
//! keyring of concatenated certificates. Both read each line once, so their
//! cost is linear in the input.
//!
//! # What is accepted
//!
//! - The data must be the canonical base64 encoding of the bytes it carries:
//!   padding only at its end, the bits the padding leaves unused all zero, and
//!   nothing after the padding. Every byte string then has exactly one
//!   sequence of base64 characters that decodes to it.
//! - Whitespace anywhere in the data is ignored, as RFC 9580 §6 requires.
//! - The checksum line is recognized so that it is not read as data, and its
//!   content is ignored. RFC 9580 §6.1 forbids rejecting a block because its
//!   checksum is present, missing, malformed, or wrong: integrity is the job of
//!   the signatures the data carries, not of the armor.
//! - Each armor header must be a `Key: Value` pair whose value is UTF-8. No
//!   signature covers the headers, and they are returned as they appear,
//!   uninterpreted.
//! - A block without armor headers may lack the blank line before its data,
//!   as GnuPG, Sequoia, and RNP read it, and as RFC 9580 §6.2.2 asks of a
//!   reader faced with malformed headers. A first line that is not a header
//!   and holds only base64 characters and whitespace begins the data. A
//!   header holds a colon and the data cannot, so a colon-free word there,
//!   such as `Comment`, is read as data.
//! - A `Hash` header must be a comma-separated list of hash algorithm names,
//!   as RFC 9580 Table 23 spells them, each name optionally surrounded by
//!   spaces or tabs. RFC 9580 §6.2.2.3 requires a verifier to decline every
//!   signature in a message whose `Hash` header is anything else, so a block
//!   carrying one is refused. The names themselves are not used: a signature
//!   names its own hash algorithm.
//! - Outside a block, only blank lines may appear. Text before, between, or
//!   after blocks is refused, not skipped.
//! - A line ends with a line feed, optionally preceded by a carriage return,
//!   and whitespace at the end of any line is not significant.
//!
//! The cleartext signed messages of RFC 9580 §7, which carry their text
//! unencoded ahead of an armored signature block, are read by
//! [`document::cleartext`](crate::document::cleartext) with the same rules.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::base64::{self, Base64Error, Decoder};
use crate::hash::HashAlgorithm;

/// What an armored block holds, as its header line names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Label {
    /// `PGP MESSAGE`: a signed, encrypted, or compressed message.
    Message,
    /// `PGP PUBLIC KEY BLOCK`: one or more certificates.
    PublicKey,
    /// `PGP PRIVATE KEY BLOCK`: secret keys.
    PrivateKey,
    /// `PGP SIGNATURE`: detached signatures, or the signatures of a cleartext
    /// signed message.
    Signature,
}

impl Label {
    /// Every label, in the order of the RFC 9580 armor header line registry.
    const ALL: [Label; 4] = [
        Label::Message,
        Label::PublicKey,
        Label::PrivateKey,
        Label::Signature,
    ];

    /// The label as the header and tail lines spell it, such as
    /// `PGP SIGNATURE`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Label::Message => "PGP MESSAGE",
            Label::PublicKey => "PGP PUBLIC KEY BLOCK",
            Label::PrivateKey => "PGP PRIVATE KEY BLOCK",
            Label::Signature => "PGP SIGNATURE",
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An armor header: a `Key: Value` line between the header line and the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    key: String,
    value: String,
}

impl Header {
    /// The key, such as `Comment`.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The value, which may be empty.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Reads a header from a line whose trailing whitespace is already gone.
    ///
    /// The key is one or more printable ASCII characters other than a colon.
    /// A colon and a space separate it from the value, which is UTF-8; an
    /// empty value may drop the space.
    fn parse(line: &[u8]) -> Option<Header> {
        let mut parts = line.splitn(2, |&byte| byte == b':');
        let key = parts.next()?;
        let rest = parts.next()?;
        let value = if rest.is_empty() {
            rest
        } else {
            rest.strip_prefix(b" ")?
        };
        if key.is_empty() || !key.iter().all(u8::is_ascii_graphic) {
            return None;
        }
        Some(Header {
            key: String::from(core::str::from_utf8(key).ok()?),
            value: String::from(core::str::from_utf8(value).ok()?),
        })
    }

    /// Whether the header is a `Hash` header.
    fn is_hash(&self) -> bool {
        self.key == "Hash"
    }

    /// Whether a `Hash` header's value is what RFC 9580 §6.2.2.3 allows: a
    /// comma-separated list of hash algorithm names from Table 23. Spaces and
    /// tabs around a name are allowed, as GnuPG allows them; an empty name,
    /// and so an empty list or a stray comma, is not.
    fn is_conformant_hash(&self) -> bool {
        self.value
            .split(',')
            .all(|name| HashAlgorithm::from_text_name(name.trim_matches([' ', '\t'])).is_some())
    }
}

/// One armored block, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Armor {
    label: Label,
    headers: Vec<Header>,
    data: Vec<u8>,
}

impl Armor {
    /// What the block's header line says it holds.
    ///
    /// The label is the encoder's claim, and decoding does not check it
    /// against the data.
    pub fn label(&self) -> Label {
        self.label
    }

    /// The armor headers, in the order they appear.
    ///
    /// No signature covers them.
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// The decoded data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The decoded data, taken from the block.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

/// Decodes an input holding exactly one armored block.
///
/// Blank lines may surround the block; anything else outside it is an error.
///
/// ```
/// use irongall::armor::{self, Label};
///
/// let input = b"\
/// -----BEGIN PGP SIGNATURE-----
/// Comment: not covered by any signature
///
/// Zm9vYmFy
/// -----END PGP SIGNATURE-----
/// ";
/// let armor = armor::decode(input)?;
/// assert_eq!(armor.label(), Label::Signature);
/// assert_eq!(armor.headers()[0].key(), "Comment");
/// assert_eq!(armor.data(), b"foobar");
/// # Ok::<(), armor::ArmorError>(())
/// ```
///
/// # Errors
///
/// When the input is not a single well-formed block. The error says what was
/// wrong and on which line; see [`ArmorErrorKind`].
pub fn decode(input: &[u8]) -> Result<Armor, ArmorError> {
    let mut reader = Reader::new(input);
    let Some(label) = reader.next_block()? else {
        return Err(reader.at_end(ArmorErrorKind::NoBlock));
    };
    let armor = reader.read_block(label)?;
    match reader.next_block()? {
        None => Ok(armor),
        Some(_) => Err(reader.at_line(ArmorErrorKind::ExtraBlock)),
    }
}

/// Decodes an input holding one or more armored blocks, in order.
///
/// Blank lines may surround and separate the blocks; anything else outside
/// them is an error.
///
/// # Errors
///
/// When the input holds no block, or anything that is not a well-formed block
/// or a blank line. The error says what was wrong and on which line; see
/// [`ArmorErrorKind`].
pub fn decode_all(input: &[u8]) -> Result<Vec<Armor>, ArmorError> {
    let mut reader = Reader::new(input);
    let mut blocks = Vec::new();
    while let Some(label) = reader.next_block()? {
        blocks.push(reader.read_block(label)?);
    }
    if blocks.is_empty() {
        return Err(reader.at_end(ArmorErrorKind::NoBlock));
    }
    Ok(blocks)
}

/// The header line of a cleartext signed message (RFC 9580 §7.1), between
/// its dashes.
const SIGNED_MESSAGE: &[u8] = b"PGP SIGNED MESSAGE";

/// The armor header line that ends the text of a cleartext signed message
/// and opens its signatures.
const SIGNATURE_HEADER_LINE: &[u8] = b"-----BEGIN PGP SIGNATURE-----";

/// Decodes an input holding exactly one cleartext signed message (RFC 9580
/// §7): the text its signatures are made over, in the form they are made
/// over it, and the armored block holding them.
///
/// The text is read as GnuPG reads it, and as RFC 9580 §7.1 and §7.2
/// describe: each line has its dash-escape removed and then its trailing
/// spaces, tabs, and carriage returns, and the lines are joined with CR LF.
/// The line ending before the signature block is not part of the text. RFC
/// 9580 names only spaces and tabs as trailing whitespace; GnuPG removes
/// carriage returns as well, and the text is read as GnuPG reads it, so that
/// a message GnuPG verifies verifies here too.
///
/// Every line that begins with a dash must be dash-escaped, as RFC 9580 §7.2
/// requires of whatever made the message, apart from the line that opens the
/// signature block. A line that is not is refused rather than kept as it is,
/// so that nothing in the text can be taken for armor.
pub(crate) fn decode_cleartext(input: &[u8]) -> Result<(Vec<u8>, Armor), ArmorError> {
    let mut reader = Reader::new(input);
    match reader.next_header_line()? {
        Some(HeaderLine::SignedMessage) => {}
        Some(HeaderLine::Block(_)) => return Err(reader.at_line(ArmorErrorKind::NotCleartext)),
        None => return Err(reader.at_end(ArmorErrorKind::NoBlock)),
    }

    // RFC 9580 §7.1 permits `Hash` headers here and no others.
    loop {
        let line = reader
            .next_line()
            .ok_or_else(|| reader.at_end(ArmorErrorKind::MissingSignature))?;
        if line.is_empty() {
            break;
        }
        let header =
            Header::parse(line).ok_or_else(|| reader.at_line(ArmorErrorKind::InvalidHeader))?;
        if !header.is_hash() {
            return Err(reader.at_line(ArmorErrorKind::ForbiddenHeader));
        }
        if !header.is_conformant_hash() {
            return Err(reader.at_line(ArmorErrorKind::InvalidHashHeader));
        }
    }

    let mut text = Vec::new();
    let mut first = true;
    loop {
        let line = reader
            .next_raw_line()
            .ok_or_else(|| reader.at_end(ArmorErrorKind::MissingSignature))?;
        let content = match line.strip_prefix(b"- ") {
            Some(escaped) => escaped,
            None if line.starts_with(b"-") => {
                if line.trim_ascii_end() == SIGNATURE_HEADER_LINE {
                    break;
                }
                return Err(reader.at_line(ArmorErrorKind::NotDashEscaped));
            }
            None => line,
        };
        if !first {
            text.extend_from_slice(b"\r\n");
        }
        first = false;
        text.extend_from_slice(trim_text_line(content));
    }

    let signature = reader.read_block(Label::Signature)?;
    match reader.next_header_line()? {
        None => Ok((text, signature)),
        Some(_) => Err(reader.at_line(ArmorErrorKind::ExtraBlock)),
    }
}

/// A line of a cleartext signed message's text without its trailing spaces,
/// tabs, and carriage returns, in any order.
fn trim_text_line(line: &[u8]) -> &[u8] {
    let mut line = line;
    while let [rest @ .., b' ' | b'\t' | b'\r'] = line {
        line = rest;
    }
    line
}

/// A failure decoding armor: what was wrong, and on which line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmorError {
    kind: ArmorErrorKind,
    line: usize,
}

impl ArmorError {
    /// What was wrong.
    pub fn kind(&self) -> ArmorErrorKind {
        self.kind
    }

    /// The line the failure was found on, counting from one. A failure found
    /// at the end of the input names the line after its last.
    pub fn line(&self) -> usize {
        self.line
    }
}

impl fmt::Display for ArmorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "armor line {}: {}", self.line, self.kind)
    }
}

impl core::error::Error for ArmorError {}

/// What was wrong with armor, as an [`ArmorError`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArmorErrorKind {
    /// The input holds no armored block, or no cleartext signed message where
    /// one was expected.
    NoBlock,
    /// The input holds a second armored block, or a block after a cleartext
    /// signed message, where only one was expected.
    ExtraBlock,
    /// A line outside an armored block is neither blank nor an armor header
    /// line.
    TextOutsideBlock,
    /// An armor header line lacks the five dashes that close it, or has text
    /// after them.
    InvalidHeaderLine,
    /// An armor header line names a label RFC 9580 does not define.
    UnknownLabel,
    /// The header line opens a cleartext signed message, which is not an
    /// armored block of its own.
    CleartextMessage,
    /// The header line opens an armored block where a cleartext signed
    /// message was expected.
    NotCleartext,
    /// An armor header is not a `Key: Value` pair with a UTF-8 value.
    ///
    /// A block with headers that lacks the blank line ending them fails here,
    /// at the first line of its data.
    InvalidHeader,
    /// A `Hash` armor header is not a comma-separated list of hash algorithm
    /// names (RFC 9580 §6.2.2.3).
    InvalidHashHeader,
    /// A cleartext signed message carries an armor header other than `Hash`,
    /// which RFC 9580 §7.1 forbids.
    ForbiddenHeader,
    /// A line of a cleartext signed message's text begins with a dash and is
    /// not dash-escaped (RFC 9580 §7.2).
    NotDashEscaped,
    /// The input ends before the signatures of a cleartext signed message.
    MissingSignature,
    /// The data holds a character that is neither base64 nor whitespace.
    InvalidCharacter,
    /// The data holds padding where a base64 group cannot end.
    InvalidPadding,
    /// The bits the data's padding leaves unused are not all zero, so it is
    /// not the canonical encoding of any bytes.
    NonCanonicalPadding,
    /// Data follows the padding that ended the base64 data.
    DataAfterPadding,
    /// The data ends part-way through a base64 group.
    TruncatedData,
    /// A line between the checksum line and the tail line is not blank.
    TextAfterChecksum,
    /// The input ends before the block's tail line.
    MissingTail,
    /// A line that can only be the block's tail line is not the one its
    /// header line calls for.
    InvalidTail,
}

impl fmt::Display for ArmorErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ArmorErrorKind::NoBlock => "the input holds no armored block",
            ArmorErrorKind::ExtraBlock => "a second armored block where only one was expected",
            ArmorErrorKind::TextOutsideBlock => {
                "text outside an armored block that is not an armor header line"
            }
            ArmorErrorKind::InvalidHeaderLine => "a malformed armor header line",
            ArmorErrorKind::UnknownLabel => "an armor header line with an unknown label",
            ArmorErrorKind::CleartextMessage => {
                "a cleartext signed message, which is not an armored block"
            }
            ArmorErrorKind::NotCleartext => {
                "an armored block where a cleartext signed message was expected"
            }
            ArmorErrorKind::InvalidHeader => {
                "neither a `Key: Value` armor header nor the blank line that ends them"
            }
            ArmorErrorKind::InvalidHashHeader => {
                "a `Hash` armor header that is not a list of hash algorithm names"
            }
            ArmorErrorKind::ForbiddenHeader => {
                "an armor header other than `Hash` in a cleartext signed message"
            }
            ArmorErrorKind::NotDashEscaped => {
                "a line of signed text that begins with a dash and is not dash-escaped"
            }
            ArmorErrorKind::MissingSignature => {
                "the input ends before the signatures of a cleartext signed message"
            }
            ArmorErrorKind::InvalidCharacter => "a character that is not base64",
            ArmorErrorKind::InvalidPadding => "base64 padding where a group cannot end",
            ArmorErrorKind::NonCanonicalPadding => "base64 padding over bits that are not zero",
            ArmorErrorKind::DataAfterPadding => "base64 data after the padding that ended it",
            ArmorErrorKind::TruncatedData => "base64 data that ends part-way through a group",
            ArmorErrorKind::TextAfterChecksum => "text between the armor checksum and tail line",
            ArmorErrorKind::MissingTail => "the input ends before the armor tail line",
            ArmorErrorKind::InvalidTail => "an armor tail line that does not match its header line",
        })
    }
}

impl From<Base64Error> for ArmorErrorKind {
    fn from(error: Base64Error) -> ArmorErrorKind {
        match error {
            Base64Error::InvalidCharacter => ArmorErrorKind::InvalidCharacter,
            Base64Error::InvalidPadding => ArmorErrorKind::InvalidPadding,
            Base64Error::NonCanonicalPadding => ArmorErrorKind::NonCanonicalPadding,
            Base64Error::DataAfterPadding => ArmorErrorKind::DataAfterPadding,
            Base64Error::Truncated => ArmorErrorKind::TruncatedData,
        }
    }
}

/// Reads armored blocks from an input, a line at a time.
struct Reader<'a> {
    /// The input after the line read last.
    rest: &'a [u8],
    /// The number of the line read last, counting from one, or zero before
    /// the first.
    line: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Reader<'a> {
        Reader {
            rest: input,
            line: 0,
        }
    }

    /// The next line, without its line feed and trailing whitespace.
    ///
    /// The last line's line feed is optional, so an input that ends with one
    /// has no empty line after it, and an empty input has no lines.
    fn next_line(&mut self) -> Option<&'a [u8]> {
        self.next_raw_line().map(<[u8]>::trim_ascii_end)
    }

    /// The next line, without its line feed but with everything else,
    /// including the carriage return of a CR LF line ending.
    fn next_raw_line(&mut self) -> Option<&'a [u8]> {
        if self.rest.is_empty() {
            return None;
        }
        let mut parts = self.rest.splitn(2, |&byte| byte == b'\n');
        let line = parts.next()?;
        self.rest = parts.next().unwrap_or_default();
        self.line = self.line.saturating_add(1);
        Some(line)
    }

    /// An error on the line read last.
    fn at_line(&self, kind: ArmorErrorKind) -> ArmorError {
        ArmorError {
            kind,
            line: self.line,
        }
    }

    /// An error at the end of the input, which names the line after the last.
    fn at_end(&self, kind: ArmorErrorKind) -> ArmorError {
        ArmorError {
            kind,
            line: self.line.saturating_add(1),
        }
    }

    /// Skips blank lines up to the next armor header line and returns what
    /// it opens, or `None` at the end of the input.
    fn next_header_line(&mut self) -> Result<Option<HeaderLine>, ArmorError> {
        while let Some(line) = self.next_line() {
            if !line.is_empty() {
                return header_line(line)
                    .map(Some)
                    .map_err(|kind| self.at_line(kind));
            }
        }
        Ok(None)
    }

    /// [`next_header_line`](Self::next_header_line), where only an armored
    /// block may begin: the label of its header line.
    fn next_block(&mut self) -> Result<Option<Label>, ArmorError> {
        match self.next_header_line()? {
            Some(HeaderLine::Block(label)) => Ok(Some(label)),
            Some(HeaderLine::SignedMessage) => Err(self.at_line(ArmorErrorKind::CleartextMessage)),
            None => Ok(None),
        }
    }

    /// Reads the rest of a block whose header line was read last.
    fn read_block(&mut self, label: Label) -> Result<Armor, ArmorError> {
        let mut headers = Vec::new();
        // The data's first line, when it follows the header line directly.
        let mut first_data_line = None;
        loop {
            let line = self
                .next_line()
                .ok_or_else(|| self.at_end(ArmorErrorKind::MissingTail))?;
            if line.is_empty() {
                break;
            }
            match Header::parse(line) {
                Some(header) => {
                    if header.is_hash() && !header.is_conformant_hash() {
                        return Err(self.at_line(ArmorErrorKind::InvalidHashHeader));
                    }
                    headers.push(header);
                }
                // A header holds a colon, and base64 data cannot, so in a block
                // without headers such a line is the data, with the blank line
                // before it missing.
                None if headers.is_empty() && base64::is_base64(line) => {
                    first_data_line = Some(line);
                    break;
                }
                None => return Err(self.at_line(ArmorErrorKind::InvalidHeader)),
            }
        }

        let mut data = Decoder::new();
        loop {
            let line = match first_data_line.take() {
                Some(line) => line,
                None => self
                    .next_line()
                    .ok_or_else(|| self.at_end(ArmorErrorKind::MissingTail))?,
            };
            // No base64 character is a dash, so a line beginning with one ends
            // the data, and can only be the tail line.
            if line.starts_with(b"-") {
                self.tail_line(label, line)?;
                break;
            }
            // Where the data could end, a line beginning with `=` is the
            // checksum; anywhere else, it is padding wrapped onto a line of its
            // own.
            if data.at_group_boundary() && line.trim_ascii_start().starts_with(b"=") {
                self.after_checksum(label)?;
                break;
            }
            data.update(line)
                .map_err(|error| self.at_line(error.into()))?;
        }
        // On the tail line, where the data was found to end.
        let data = data.finish().map_err(|error| self.at_line(error.into()))?;
        Ok(Armor {
            label,
            headers,
            data,
        })
    }

    /// Reads past the lines that may follow the checksum line: blank lines,
    /// then the tail line.
    fn after_checksum(&mut self, label: Label) -> Result<(), ArmorError> {
        loop {
            let line = self
                .next_line()
                .ok_or_else(|| self.at_end(ArmorErrorKind::MissingTail))?;
            if line.starts_with(b"-") {
                return self.tail_line(label, line);
            }
            if !line.is_empty() {
                return Err(self.at_line(ArmorErrorKind::TextAfterChecksum));
            }
        }
    }

    /// Checks that the line read last is the tail line for `label`.
    fn tail_line(&self, label: Label, line: &[u8]) -> Result<(), ArmorError> {
        let text = line
            .strip_prefix(b"-----END ")
            .and_then(|rest| rest.strip_suffix(b"-----"));
        if text == Some(label.as_str().as_bytes()) {
            Ok(())
        } else {
            Err(self.at_line(ArmorErrorKind::InvalidTail))
        }
    }
}

/// What an armor header line opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderLine {
    /// An armored block holding what the label names.
    Block(Label),
    /// A cleartext signed message (RFC 9580 §7.1).
    SignedMessage,
}

/// Reads an armor header line, whose trailing whitespace is already gone.
fn header_line(line: &[u8]) -> Result<HeaderLine, ArmorErrorKind> {
    let text = line
        .strip_prefix(b"-----BEGIN ")
        .ok_or(ArmorErrorKind::TextOutsideBlock)?
        .strip_suffix(b"-----")
        .ok_or(ArmorErrorKind::InvalidHeaderLine)?;
    if text == SIGNED_MESSAGE {
        return Ok(HeaderLine::SignedMessage);
    }
    Label::ALL
        .into_iter()
        .find(|label| label.as_str().as_bytes() == text)
        .map(HeaderLine::Block)
        .ok_or(ArmorErrorKind::UnknownLabel)
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::{String, ToString as _};
    use alloc::vec::Vec;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::{ArmorErrorKind, Label, decode, decode_all};
    use crate::test_support::hex;
    use crate::test_support::rfc9580::{
        A1_KEY, A1_KEY_PACKET, A2_SIGNATURE, A2_SIGNATURE_PACKET, A3_CERTIFICATE,
    };

    /// The error kind and line `input` fails to decode with.
    fn failure(input: &str) -> (ArmorErrorKind, usize) {
        let error = decode_all(input.as_bytes()).unwrap_err();
        (error.kind(), error.line())
    }

    /// A signature block without armor headers, whose `data` lines begin on
    /// line 3.
    fn signature(data: &[&str]) -> String {
        format!(
            "-----BEGIN PGP SIGNATURE-----\n\n{}\n-----END PGP SIGNATURE-----\n",
            data.join("\n")
        )
    }

    #[test]
    fn rfc_9580_samples() {
        let key = decode(A1_KEY.as_bytes()).unwrap();
        assert_eq!(key.label(), Label::PublicKey);
        assert!(key.headers().is_empty());
        assert_eq!(key.data(), hex(A1_KEY_PACKET));

        let signature = decode(A2_SIGNATURE.as_bytes()).unwrap();
        assert_eq!(signature.label(), Label::Signature);
        assert_eq!(signature.into_data(), hex(A2_SIGNATURE_PACKET));

        let certificate = decode(A3_CERTIFICATE.as_bytes()).unwrap();
        let body: String = A3_CERTIFICATE
            .lines()
            .filter(|line| !line.starts_with('-'))
            .collect();
        assert_eq!(certificate.data(), STANDARD.decode(body).unwrap());
    }

    #[test]
    fn line_endings_and_trailing_whitespace_are_not_significant() {
        let expected = decode(A2_SIGNATURE.as_bytes()).unwrap();
        let crlf = A2_SIGNATURE.replace('\n', "\r\n");
        let padded = A2_SIGNATURE.replace('\n', " \t\n");
        let unterminated = A2_SIGNATURE.trim_end();
        for input in [&crlf[..], &padded, unterminated] {
            assert_eq!(decode(input.as_bytes()).unwrap(), expected, "{input:?}");
        }
    }

    #[test]
    fn whitespace_inside_the_data_is_ignored() {
        let spaced = signature(&[
            "  iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/ VvkMypjiECY3vZg/2xbBMd/S",
            "",
            "\tftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZf\tps60iehUuuYbQE",
        ]);
        assert_eq!(
            decode(spaced.as_bytes()).unwrap(),
            decode(A2_SIGNATURE.as_bytes()).unwrap()
        );
    }

    /// RFC 9580 §6.1 forbids rejecting a block over its checksum, whatever
    /// state the checksum is in.
    #[test]
    fn the_checksum_is_ignored() {
        let data = ["Zm9vYmFy"];
        let expected = decode(signature(&data).as_bytes()).unwrap();
        for checksum in ["=ZxGy", "=AAAA", "=", "=!!", "=ZxGy extra", " =ZxGy"] {
            let input = signature(&[data[0], checksum]);
            assert_eq!(decode(input.as_bytes()).unwrap(), expected, "{checksum}");
        }
        // Blank lines may follow it; nothing else may.
        let blank = signature(&[data[0], "=ZxGy", "", " "]);
        assert_eq!(decode(blank.as_bytes()).unwrap(), expected);
        assert_eq!(
            failure(&signature(&[data[0], "=ZxGy", "Zm9v"])),
            (ArmorErrorKind::TextAfterChecksum, 5)
        );
    }

    /// Padding wrapped onto a line of its own begins with `=` as a checksum
    /// line does; where it falls in the data is what tells them apart.
    #[test]
    fn padding_on_its_own_line_is_not_the_checksum() {
        let expected = decode(signature(&["Zm9vYg=="]).as_bytes()).unwrap();
        assert_eq!(expected.data(), b"foob");
        for data in [
            &["Zm9vYg", "=="][..],
            &["Zm9vYg=", "="],
            &["Zm9vYg", "=", "="],
            &["Zm9vYg", "==", "=ZxGy"],
            &["Zm9vYg=", "=", "=ZxGy"],
        ] {
            assert_eq!(
                decode(signature(data).as_bytes()).unwrap(),
                expected,
                "{data:?}"
            );
        }
        assert_eq!(
            decode(signature(&["Zm9vYmE", "=", "=AAAA"]).as_bytes())
                .unwrap()
                .data(),
            b"fooba"
        );
    }

    #[test]
    fn headers_are_returned_in_order() {
        let input = "\
-----BEGIN PGP SIGNATURE-----
Version: 1.0
Comment: first\x20\x20
Comment:  second, with a leading space
Comment: \u{e9}t\u{e9}
Empty:

Zm9v
-----END PGP SIGNATURE-----
";
        let armor = decode(input.as_bytes()).unwrap();
        let headers: Vec<_> = armor
            .headers()
            .iter()
            .map(|header| (header.key(), header.value()))
            .collect();
        assert_eq!(
            headers,
            [
                ("Version", "1.0"),
                ("Comment", "first"),
                ("Comment", " second, with a leading space"),
                ("Comment", "\u{e9}t\u{e9}"),
                ("Empty", ""),
            ]
        );
        assert_eq!(armor.data(), b"foo");
    }

    #[test]
    fn every_label_is_read() {
        for label in Label::ALL {
            let input = format!("-----BEGIN {label}-----\n\nZm9v\n-----END {label}-----\n");
            assert_eq!(decode(input.as_bytes()).unwrap().label(), label);
        }
    }

    #[test]
    fn several_blocks_are_read_in_order() {
        let input = format!("\n{A1_KEY}\n \n{A2_SIGNATURE}{A3_CERTIFICATE}\n");
        let blocks = decode_all(input.as_bytes()).unwrap();
        let labels: Vec<_> = blocks.iter().map(|block| block.label()).collect();
        assert_eq!(
            labels,
            [Label::PublicKey, Label::Signature, Label::PublicKey]
        );
        assert_eq!(blocks[0].data(), hex(A1_KEY_PACKET));
        assert_eq!(blocks[1].data(), hex(A2_SIGNATURE_PACKET));

        // The second block's header line, after a leading blank line, the
        // first block's five lines, and two blank lines.
        let error = decode(input.as_bytes()).unwrap_err();
        assert_eq!(
            (error.kind(), error.line()),
            (ArmorErrorKind::ExtraBlock, 9)
        );
    }

    #[test]
    fn an_empty_block_decodes_to_nothing() {
        let armor =
            decode(b"-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n").unwrap();
        assert!(armor.data().is_empty());
    }

    #[test]
    fn malformed_framing_is_refused() {
        for (input, kind, line) in [
            ("", ArmorErrorKind::NoBlock, 1),
            ("\n \n", ArmorErrorKind::NoBlock, 3),
            (
                "text\n-----BEGIN PGP SIGNATURE-----\n",
                ArmorErrorKind::TextOutsideBlock,
                1,
            ),
            (
                " -----BEGIN PGP SIGNATURE-----\n",
                ArmorErrorKind::TextOutsideBlock,
                1,
            ),
            (
                "-----BEGIN PGP SIGNATURE----\n",
                ArmorErrorKind::InvalidHeaderLine,
                1,
            ),
            (
                "-----BEGIN PGP SIGNATURE----- text\n",
                ArmorErrorKind::InvalidHeaderLine,
                1,
            ),
            (
                "\n-----BEGIN PGP MESSAGE, PART 1/2-----\n",
                ArmorErrorKind::UnknownLabel,
                2,
            ),
            (
                "-----BEGIN PGP ARMORED FILE-----\n",
                ArmorErrorKind::UnknownLabel,
                1,
            ),
            (
                "-----BEGIN pgp signature-----\n",
                ArmorErrorKind::UnknownLabel,
                1,
            ),
            (
                "-----BEGIN PGP SIGNED MESSAGE-----\n",
                ArmorErrorKind::CleartextMessage,
                1,
            ),
            (
                "-----BEGIN PGP SIGNATURE-----\n",
                ArmorErrorKind::MissingTail,
                2,
            ),
            (
                "-----BEGIN PGP SIGNATURE-----\n\nZm9v\n",
                ArmorErrorKind::MissingTail,
                4,
            ),
            (
                "-----BEGIN PGP SIGNATURE-----\n\nZm9v\n=ZxGy",
                ArmorErrorKind::MissingTail,
                5,
            ),
        ] {
            assert_eq!(failure(input), (kind, line), "{input:?}");
        }
        let after = format!("{A2_SIGNATURE}text\n");
        assert_eq!(failure(&after), (ArmorErrorKind::TextOutsideBlock, 6));
    }

    #[test]
    fn malformed_headers_are_refused() {
        for header in [
            "Comment:no space",
            ": no key",
            "Com ment: a space in the key",
            "Comment, without a colon",
        ] {
            let input = format!(
                "-----BEGIN PGP SIGNATURE-----\n{header}\n\nZm9v\n-----END PGP SIGNATURE-----\n"
            );
            assert_eq!(
                failure(&input),
                (ArmorErrorKind::InvalidHeader, 2),
                "{header}"
            );
        }
        let latin1 = b"-----BEGIN PGP SIGNATURE-----\nComment: \xe9t\xe9\n\nZm9v\n-----END PGP SIGNATURE-----\n";
        let error = decode(latin1).unwrap_err();
        assert_eq!(
            (error.kind(), error.line()),
            (ArmorErrorKind::InvalidHeader, 2)
        );
        // A header line directly followed by the tail line.
        assert_eq!(
            failure("-----BEGIN PGP SIGNATURE-----\n-----END PGP SIGNATURE-----\n"),
            (ArmorErrorKind::InvalidHeader, 2)
        );
    }

    /// The data of a block without headers may follow its header line
    /// directly; after a header, the blank line is still required.
    #[test]
    fn the_blank_line_may_be_missing_without_headers() {
        let expected = decode(A2_SIGNATURE.as_bytes()).unwrap();
        let joined = A2_SIGNATURE.replacen("-----\n\n", "-----\n", 1);
        assert_ne!(joined, A2_SIGNATURE);
        let indented = joined.replacen("-----\n", "-----\n \t", 1);
        for input in [&joined, &indented, &joined.replace('\n', "\r\n")] {
            assert_eq!(decode(input.as_bytes()).unwrap(), expected, "{input:?}");
        }
        let key = format!("{A1_KEY}{joined}").replacen("-----\n\n", "-----\n", 1);
        let blocks = decode_all(key.as_bytes()).unwrap();
        assert_eq!(blocks[0].data(), hex(A1_KEY_PACKET));
        assert_eq!(blocks[1], expected);

        // Padding, and the checksum line of a block with no data, are read as
        // they are where the blank line is present.
        let padded = "-----BEGIN PGP SIGNATURE-----\nZm9vYg==\n-----END PGP SIGNATURE-----\n";
        assert_eq!(decode(padded.as_bytes()).unwrap().data(), b"foob");
        let empty = "-----BEGIN PGP SIGNATURE-----\n=ZxGy\n-----END PGP SIGNATURE-----\n";
        assert!(decode(empty.as_bytes()).unwrap().data().is_empty());

        // After a header, data is not a header.
        let after_header = "-----BEGIN PGP SIGNATURE-----\nComment: a header\nZm9v\n\
                            -----END PGP SIGNATURE-----\n";
        assert_eq!(failure(after_header), (ArmorErrorKind::InvalidHeader, 3));

        // A colon-free word of base64 characters is data, and fails as data:
        // `Comment`, a blank line, and `Zm9v` are eleven characters.
        let word = "-----BEGIN PGP SIGNATURE-----\nComment\n\nZm9v\n-----END PGP SIGNATURE-----\n";
        assert_eq!(failure(word), (ArmorErrorKind::TruncatedData, 5));
    }

    /// RFC 9580 §6.2.2.3: a verifier declines every signature in a message
    /// whose `Hash` header is not a list of hash algorithm names, and every
    /// block may hold signatures, so a block of any label with such a header
    /// is refused. A well-formed one is returned like any other header.
    #[test]
    fn a_hash_header_must_list_hash_algorithms() {
        for label in Label::ALL {
            let block = |value: &str| {
                format!("-----BEGIN {label}-----\nHash: {value}\n\nZm9v\n-----END {label}-----\n")
            };
            let armor = decode(block("SHA256, SHA512").as_bytes()).unwrap();
            assert_eq!(armor.headers()[0].value(), "SHA256, SHA512");
            for value in ["FOO", "sha256", "SHA256,", ""] {
                assert_eq!(
                    failure(&block(value)),
                    (ArmorErrorKind::InvalidHashHeader, 2),
                    "{label} {value:?}"
                );
            }
        }
        // Only the key `Hash` is held to the rule.
        assert!(
            decode(
                b"-----BEGIN PGP SIGNATURE-----\nhash: FOO\n\nZm9v\n-----END PGP SIGNATURE-----\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn malformed_data_is_refused() {
        for (data, kind, line) in [
            (&["a=a=a=a="][..], ArmorErrorKind::InvalidPadding, 3),
            (&["Zm9v", "Zg=x"], ArmorErrorKind::InvalidPadding, 4),
            (&["Zh=="], ArmorErrorKind::NonCanonicalPadding, 3),
            (&["Zg==", "Zm9v"], ArmorErrorKind::DataAfterPadding, 4),
            (&["Zg==Zm9v"], ArmorErrorKind::DataAfterPadding, 3),
            (&["Zm9v", "Zg"], ArmorErrorKind::TruncatedData, 5),
            (&["Zm9v", "Zg", "=ZxGy"], ArmorErrorKind::InvalidPadding, 5),
            (&["Zm9v*"], ArmorErrorKind::InvalidCharacter, 3),
            (
                &["Zm9v", " -----END PGP SIGNATURE-----"],
                ArmorErrorKind::InvalidCharacter,
                4,
            ),
        ] {
            assert_eq!(failure(&signature(data)), (kind, line), "{data:?}");
        }
    }

    #[test]
    fn the_tail_line_must_match_the_header_line() {
        for tail in [
            "-----END PGP MESSAGE-----",
            "-----END PGP SIGNATURE----",
            "-----END PGP SIGNATURE----- text",
            "----END PGP SIGNATURE-----",
            "- Zm9v",
        ] {
            let input = format!("-----BEGIN PGP SIGNATURE-----\n\nZm9v\n{tail}\n");
            assert_eq!(failure(&input), (ArmorErrorKind::InvalidTail, 4), "{tail}");
            let input = format!("-----BEGIN PGP SIGNATURE-----\n\nZm9v\n=ZxGy\n{tail}\n");
            assert_eq!(failure(&input), (ArmorErrorKind::InvalidTail, 5), "{tail}");
        }
    }

    #[test]
    fn errors_name_their_line() {
        let error = decode(signature(&["Zm9v", "Zm9v*"]).as_bytes()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "armor line 4: a character that is not base64"
        );
    }
}
