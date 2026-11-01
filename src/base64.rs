//! Base64 decoding (RFC 4648 §4), strict about the encoding and blind to
//! whitespace.
//!
//! Strict: the text must be the canonical encoding of the bytes it decodes
//! to. Padding appears only in the final group, the bits it leaves unused are
//! zero, and nothing follows it. Every byte string then has exactly one
//! sequence of base64 characters this decoder accepts for it, so two readers
//! of the same text cannot come away with different data. Lenient decoders
//! differ on all three points, and one that accepts `a=a=a=a=` has to decide
//! what it means.
//!
//! Blind to whitespace: RFC 9580 §6 requires an OpenPGP implementation to
//! ignore all whitespace when it decodes base64, so ASCII whitespace is skipped
//! wherever it appears, between lines or inside them.
//!
//! The decoder takes its input in pieces, which is how armor delivers it: a
//! line at a time, where whether the next line is data or the armor checksum
//! depends on where the previous one left the decoder.

use alloc::vec::Vec;

/// Why a text is not the canonical base64 encoding of any byte string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Base64Error {
    /// A byte that is neither in the alphabet nor whitespace.
    InvalidCharacter,
    /// A pad character where the group cannot end: as one of its first two
    /// characters, or followed by data in the same group.
    InvalidPadding,
    /// The padded group's unused bits are not all zero.
    NonCanonicalPadding,
    /// Data, or more padding, after the padding that ended the text.
    DataAfterPadding,
    /// The text ends part-way through a group.
    Truncated,
}

/// How far into the text a [`Decoder`] has read.
#[derive(Debug, Clone, Copy)]
enum State {
    /// Reading data. The low bits of `bits` hold the `count` sextets read so
    /// far of the current group, zero to three of them.
    Data { bits: u32, count: u8 },
    /// Two sextets and one pad character of the final group have been read,
    /// and the group still needs its second pad character.
    Padding { bits: u32 },
    /// Padding has ended the text.
    Ended,
}

/// An incremental base64 decoder.
#[derive(Debug)]
pub(crate) struct Decoder {
    state: State,
    output: Vec<u8>,
}

impl Decoder {
    pub(crate) fn new() -> Decoder {
        Decoder {
            state: State::Data { bits: 0, count: 0 },
            output: Vec::new(),
        }
    }

    /// Decodes `text`, continuing from where the previous call stopped.
    ///
    /// After an error the decoder is in no defined state, and the caller
    /// abandons it.
    pub(crate) fn update(&mut self, text: &[u8]) -> Result<(), Base64Error> {
        for &byte in text {
            if !byte.is_ascii_whitespace() {
                self.state = self.step(byte)?;
            }
        }
        Ok(())
    }

    /// Whether the text read so far is complete: no group is part-way read.
    ///
    /// This is what tells the armor checksum line, which begins with `=`, from
    /// padding wrapped onto a line of its own, which also does.
    pub(crate) fn at_group_boundary(&self) -> bool {
        matches!(self.state, State::Data { count: 0, .. } | State::Ended)
    }

    /// The decoded bytes, once the text has ended.
    pub(crate) fn finish(self) -> Result<Vec<u8>, Base64Error> {
        if self.at_group_boundary() {
            Ok(self.output)
        } else {
            Err(Base64Error::Truncated)
        }
    }

    /// Reads one character that is not whitespace, returning the state it
    /// leaves the decoder in.
    fn step(&mut self, byte: u8) -> Result<State, Base64Error> {
        match self.state {
            State::Ended => Err(Base64Error::DataAfterPadding),
            State::Padding { bits } => match byte {
                // `xx==`: twelve bits, of which the first eight are the byte.
                b'=' => {
                    if bits & 0xF != 0 {
                        return Err(Base64Error::NonCanonicalPadding);
                    }
                    let [.., byte] = (bits >> 4).to_be_bytes();
                    self.output.push(byte);
                    Ok(State::Ended)
                }
                _ => Err(Base64Error::InvalidPadding),
            },
            State::Data { bits, count } => match (byte, count) {
                (b'=', 2) => Ok(State::Padding { bits }),
                // `xxx=`: eighteen bits, of which the first sixteen are the
                // two bytes.
                (b'=', 3) => {
                    if bits & 0x3 != 0 {
                        return Err(Base64Error::NonCanonicalPadding);
                    }
                    let [.., first, second] = (bits >> 2).to_be_bytes();
                    self.output.extend_from_slice(&[first, second]);
                    Ok(State::Ended)
                }
                (b'=', _) => Err(Base64Error::InvalidPadding),
                (_, 3) => {
                    let [_, first, second, third] = (bits << 6 | sextet(byte)?).to_be_bytes();
                    self.output.extend_from_slice(&[first, second, third]);
                    Ok(State::Data { bits: 0, count: 0 })
                }
                (_, _) => Ok(State::Data {
                    bits: bits << 6 | sextet(byte)?,
                    // At most two here: three is the arm above.
                    count: count.wrapping_add(1),
                }),
            },
        }
    }
}

/// Whether `text` holds only what base64 data may: characters of the
/// alphabet, the pad character, and whitespace.
pub(crate) fn is_base64(text: &[u8]) -> bool {
    text.iter()
        .all(|&byte| byte == b'=' || byte.is_ascii_whitespace() || sextet(byte).is_ok())
}

/// The value of a character of the base64 alphabet (RFC 4648, Table 1).
fn sextet(byte: u8) -> Result<u32, Base64Error> {
    // Each subtraction is of the low end of the range the byte was just
    // matched against, so none of them wraps.
    let value = match byte {
        b'A'..=b'Z' => byte.wrapping_sub(b'A'),
        b'a'..=b'z' => byte.wrapping_sub(b'a').wrapping_add(26),
        b'0'..=b'9' => byte.wrapping_sub(b'0').wrapping_add(52),
        b'+' => 62,
        b'/' => 63,
        _ => return Err(Base64Error::InvalidCharacter),
    };
    Ok(u32::from(value))
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::{Base64Error, Decoder};
    use crate::test_support::Rng;

    fn decode(text: &[u8]) -> Result<Vec<u8>, Base64Error> {
        let mut decoder = Decoder::new();
        decoder.update(text)?;
        decoder.finish()
    }

    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    #[test]
    fn rfc_4648_vectors() {
        for (text, bytes) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            assert_eq!(decode(text.as_bytes()).unwrap(), bytes.as_bytes(), "{text}");
        }
    }

    #[test]
    fn whitespace_is_ignored_anywhere() {
        assert_eq!(decode(b" Zm 9v\r\nYm\tFy \x0c").unwrap(), b"foobar");
        assert_eq!(decode(b"Zg=\n=").unwrap(), b"f");
        assert_eq!(decode(b" \n\t").unwrap(), b"");
    }

    #[test]
    fn malformed_texts_are_refused() {
        for (text, error) in [
            // The text the strictness is for: four groups, each padded.
            (&b"a=a=a=a="[..], Base64Error::InvalidPadding),
            (b"=", Base64Error::InvalidPadding),
            (b"Z===", Base64Error::InvalidPadding),
            (b"Zg=g", Base64Error::InvalidPadding),
            (b"Zh==", Base64Error::NonCanonicalPadding),
            (b"Zm9=", Base64Error::NonCanonicalPadding),
            (b"Zg===", Base64Error::DataAfterPadding),
            (b"Zg==Zm9v", Base64Error::DataAfterPadding),
            (b"Zm8=Zg==", Base64Error::DataAfterPadding),
            (b"Zg", Base64Error::Truncated),
            (b"Zg=", Base64Error::Truncated),
            (b"Zm9vY", Base64Error::Truncated),
            (b"Zm9v-", Base64Error::InvalidCharacter),
            (b"Zm9v_", Base64Error::InvalidCharacter),
            (b"Zm\x009v", Base64Error::InvalidCharacter),
            (b"Zm\xc3\xa9v", Base64Error::InvalidCharacter),
        ] {
            assert_eq!(
                decode(text),
                Err(error),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
    }

    /// Every one- and two-byte string has exactly one padded group the decoder
    /// accepts for it.
    #[test]
    fn padded_groups_are_canonical() {
        for &first in ALPHABET {
            for &second in ALPHABET {
                let text = [first, second, b'=', b'='];
                let canonical =
                    decode(&text).is_ok_and(|bytes| STANDARD.encode(bytes).as_bytes() == text);
                assert_eq!(decode(&text).is_ok(), canonical);
                for &third in ALPHABET {
                    let text = [first, second, third, b'='];
                    let canonical =
                        decode(&text).is_ok_and(|bytes| STANDARD.encode(bytes).as_bytes() == text);
                    assert_eq!(decode(&text).is_ok(), canonical);
                }
            }
        }
    }

    #[test]
    fn agrees_with_a_reference_on_encoded_data() {
        let mut rng = Rng::new(0x6261_7365);
        for _ in 0..2000 {
            let len = rng.below(200);
            let bytes = rng.bytes(len);
            let text = STANDARD.encode(&bytes);

            // Whole, and in pieces with whitespace between them, as armor
            // delivers it.
            assert_eq!(decode(text.as_bytes()).unwrap(), bytes);
            let mut decoder = Decoder::new();
            let mut rest = text.as_bytes();
            while !rest.is_empty() {
                let (piece, tail) = rest.split_at(1 + rng.below(rest.len()));
                decoder.update(piece).unwrap();
                decoder
                    .update([&b"\n"[..], b" ", b"\t", b"\r\n"][rng.below(4)])
                    .unwrap();
                rest = tail;
            }
            assert_eq!(decoder.finish().unwrap(), bytes);
        }
    }

    /// On text without whitespace, which the reference does not skip, the two
    /// accept exactly the same strings and decode them alike.
    #[test]
    fn agrees_with_a_reference_on_arbitrary_text() {
        let mut rng = Rng::new(0x7465_7874);
        let characters = [ALPHABET, b"=", b"-_.!"].concat();
        for _ in 0..200_000 {
            let len = rng.below(13);
            let text: Vec<u8> = (0..len)
                .map(|_| {
                    // Pad characters often enough to reach the padding states.
                    if rng.below(4) == 0 {
                        b'='
                    } else {
                        characters[rng.below(characters.len())]
                    }
                })
                .collect();
            assert_eq!(
                decode(&text).ok(),
                STANDARD.decode(&text).ok(),
                "{}",
                String::from_utf8_lossy(&text)
            );
        }
    }
}
