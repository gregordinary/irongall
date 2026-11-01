//! Helpers the unit tests share.

use alloc::string::String;
use alloc::vec::Vec;

use crate::hash::{
    Digest, HashAlgorithm, HashFunction, Sha1, Sha3_256, Sha3_512, Sha224, Sha256, Sha384, Sha512,
};
use crate::packet::Version;
use crate::signature::Signature;

/// Decodes a hexadecimal string.
///
/// Panics on anything else: a malformed vector is a broken test, not a case
/// to handle.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd-length hex: {text:?}");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digit pair"))
        .collect()
}

/// Reads a vendored test-vector file, named relative to `tests/vectors`.
pub(crate) fn vector(path: &str) -> String {
    String::from_utf8(vector_bytes(path)).unwrap_or_else(|err| panic!("{path}: {err}"))
}

/// [`vector`], for a binary file.
pub(crate) fn vector_bytes(path: &str) -> Vec<u8> {
    let full = std::format!("{}/tests/vectors/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&full).unwrap_or_else(|err| panic!("reading {full}: {err}"))
}

/// The digest of `data` under `algorithm`, one of the seven irongall
/// implements.
///
/// The library's own dispatch, `hash::Context`, answers the same question.
/// This one is written separately so that a test of a signature's hash does
/// not depend on the dispatch it checks.
pub(crate) fn digest(algorithm: HashAlgorithm, data: &[u8]) -> Digest {
    match algorithm {
        HashAlgorithm::SHA1 => Digest::Sha1(Sha1::digest(data)),
        HashAlgorithm::SHA224 => Digest::Sha224(Sha224::digest(data)),
        HashAlgorithm::SHA256 => Digest::Sha256(Sha256::digest(data)),
        HashAlgorithm::SHA384 => Digest::Sha384(Sha384::digest(data)),
        HashAlgorithm::SHA512 => Digest::Sha512(Sha512::digest(data)),
        HashAlgorithm::SHA3_256 => Digest::Sha3_256(Sha3_256::digest(data)),
        HashAlgorithm::SHA3_512 => Digest::Sha3_512(Sha3_512::digest(data)),
        _ => panic!("a hash algorithm irongall does not implement: {algorithm}"),
    }
}

/// A key as a signature hashes it, given its packet's body (RFC 9580
/// §5.2.4): `0x99` and a two-octet length before a version 4 key, `0x9B`
/// and a four-octet length before a version 6 key.
pub(crate) fn hashed_key(body: &[u8]) -> Vec<u8> {
    match body.first() {
        Some(4) => {
            let length = u16::try_from(body.len()).unwrap();
            [&[0x99][..], &length.to_be_bytes(), body].concat()
        }
        Some(6) => {
            let length = u32::try_from(body.len()).unwrap();
            [&[0x9B][..], &length.to_be_bytes(), body].concat()
        }
        version => panic!("a key of version {version:?}"),
    }
}

/// A user ID as a certification hashes it (RFC 9580 §5.2.4): `0xB4`, a
/// four-octet length, and the packet's body.
pub(crate) fn hashed_user_id(body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len()).unwrap();
    [&[0xB4][..], &length.to_be_bytes(), body].concat()
}

/// What a signature's hash is computed over (RFC 9580 §5.2.4): a version 6
/// signature's salt, then `data`, then the signature's fields from its
/// version through its hashed subpackets, and a trailer of the version,
/// `0xFF`, and the length of those fields in four octets.
///
/// Written out here from the RFC, rather than taken from the library, so a
/// test does not depend on what it checks.
pub(crate) fn signature_input(signature: &Signature, data: &[u8]) -> Vec<u8> {
    let hashed = signature.hashed_fields();
    let version = match signature.version() {
        Version::V4 => 4,
        Version::V6 => 6,
    };
    let length = u32::try_from(hashed.len()).unwrap();
    [
        signature.salt(),
        data,
        hashed,
        &[version, 0xFF],
        &length.to_be_bytes(),
    ]
    .concat()
}

/// The digest a signature is made over: [`signature_input`] under the
/// signature's hash algorithm, checked against the two octets of it the
/// signature carries.
pub(crate) fn signature_digest(signature: &Signature, data: &[u8]) -> Digest {
    let digest = digest(
        signature.hash_algorithm(),
        &signature_input(signature, data),
    );
    assert_eq!(
        digest.as_bytes()[..2],
        signature.hash_prefix(),
        "the hash context is wrong"
    );
    digest
}

/// A JSON value (RFC 8259), as the vector files that use JSON hold them.
///
/// The accessors panic on a value of another shape: a vector file that does
/// not match its schema is a broken test, not a case to handle.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    /// A number, as written.
    Number(String),
    String(String),
    Array(Vec<Json>),
    /// An object's members, in order.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Parses a whole JSON text.
    pub(crate) fn parse(text: &str) -> Json {
        let mut parser = JsonParser {
            text: text.as_bytes(),
            at: 0,
        };
        let value = parser.value();
        parser.whitespace();
        assert_eq!(parser.at, text.len(), "JSON continues after its value");
        value
    }

    /// The member `key` of an object, if it has one.
    pub(crate) fn get(&self, key: &str) -> Option<&Json> {
        let Json::Object(members) = self else {
            panic!("not a JSON object: {self:?}");
        };
        members
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// The member `key` of an object, which it must have.
    pub(crate) fn member(&self, key: &str) -> &Json {
        self.get(key)
            .unwrap_or_else(|| panic!("no member {key:?} in a JSON object"))
    }

    pub(crate) fn as_str(&self) -> &str {
        match self {
            Json::String(string) => string,
            _ => panic!("not a JSON string: {self:?}"),
        }
    }

    pub(crate) fn as_array(&self) -> &[Json] {
        match self {
            Json::Array(elements) => elements,
            _ => panic!("not a JSON array: {self:?}"),
        }
    }

    pub(crate) fn as_usize(&self) -> usize {
        match self {
            Json::Number(number) => number.parse().unwrap(),
            _ => panic!("not a JSON number: {self:?}"),
        }
    }
}

/// A recursive-descent reader of JSON text, over its bytes.
struct JsonParser<'a> {
    text: &'a [u8],
    at: usize,
}

impl JsonParser<'_> {
    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn next(&mut self) -> u8 {
        let byte = self.peek().expect("JSON ends inside a value");
        self.at += 1;
        byte
    }

    fn expect(&mut self, literal: &str) {
        for &byte in literal.as_bytes() {
            assert_eq!(self.next(), byte, "JSON: expected {literal:?}");
        }
    }

    fn value(&mut self) -> Json {
        self.whitespace();
        match self.peek().expect("JSON ends before a value") {
            b'{' => {
                self.at += 1;
                let mut members = Vec::new();
                self.whitespace();
                if self.peek() == Some(b'}') {
                    self.at += 1;
                    return Json::Object(members);
                }
                loop {
                    self.whitespace();
                    let name = self.string();
                    self.whitespace();
                    self.expect(":");
                    members.push((name, self.value()));
                    self.whitespace();
                    match self.next() {
                        b',' => {}
                        b'}' => return Json::Object(members),
                        other => panic!("JSON: {:?} in an object", other as char),
                    }
                }
            }
            b'[' => {
                self.at += 1;
                let mut elements = Vec::new();
                self.whitespace();
                if self.peek() == Some(b']') {
                    self.at += 1;
                    return Json::Array(elements);
                }
                loop {
                    elements.push(self.value());
                    self.whitespace();
                    match self.next() {
                        b',' => {}
                        b']' => return Json::Array(elements),
                        other => panic!("JSON: {:?} in an array", other as char),
                    }
                }
            }
            b'"' => Json::String(self.string()),
            b't' => {
                self.expect("true");
                Json::Bool(true)
            }
            b'f' => {
                self.expect("false");
                Json::Bool(false)
            }
            b'n' => {
                self.expect("null");
                Json::Null
            }
            _ => {
                let start = self.at;
                while matches!(
                    self.peek(),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.at += 1;
                }
                assert!(self.at > start, "JSON: no value at offset {start}");
                Json::Number(String::from_utf8(self.text[start..self.at].to_vec()).unwrap())
            }
        }
    }

    fn string(&mut self) -> String {
        self.expect("\"");
        let mut bytes = Vec::new();
        loop {
            match self.next() {
                b'"' => return String::from_utf8(bytes).expect("JSON strings are UTF-8"),
                b'\\' => match self.next() {
                    b'u' => {
                        let digits =
                            core::str::from_utf8(&self.text[self.at..self.at + 4]).unwrap();
                        self.at += 4;
                        let unit = u32::from_str_radix(digits, 16).unwrap();
                        let character =
                            char::from_u32(unit).expect("a \\u escape outside a surrogate pair");
                        bytes.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
                    }
                    escaped => bytes.push(match escaped {
                        b'"' | b'\\' | b'/' => escaped,
                        b'b' => 0x08,
                        b'f' => 0x0C,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        other => panic!("JSON: the escape \\{}", other as char),
                    }),
                },
                byte => bytes.push(byte),
            }
        }
    }
}

/// A small deterministic generator (SplitMix64), so a randomized test runs
/// the same cases every time without a dependency to produce them.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`. The slight bias of a modulus is irrelevant to
    /// choosing test cases.
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }
}

/// The samples of RFC 9580 Appendix A.
pub(crate) mod rfc9580 {
    /// The version 4 Ed25519Legacy public key of Appendix A.1, armored.
    pub(crate) const A1_KEY: &str = "\
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku
Q+47JAY=
-----END PGP PUBLIC KEY BLOCK-----
";

    /// The packet [`A1_KEY`] encodes, in hexadecimal.
    ///
    /// The appendix prints the packet with a legacy packet header, `0x98`,
    /// and armors it with an OpenPGP one, `0xC6`. The two encodings differ in
    /// that byte alone, and this is the armored one.
    pub(crate) const A1_KEY_PACKET: &str = "\
        c6330453f35f0b16092b06010401da47\
        0f010107403f098994bdd916ed405319\
        7934e4a87c80733a1280d62f8010992e\
        43ee3b2406";

    /// The version 4 Ed25519Legacy signature of Appendix A.2, armored.
    pub(crate) const A2_SIGNATURE: &str = "\
-----BEGIN PGP SIGNATURE-----

iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/VvkMypjiECY3vZg/2xbBMd/S
ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE
-----END PGP SIGNATURE-----
";

    /// The packet [`A2_SIGNATURE`] encodes, in hexadecimal.
    pub(crate) const A2_SIGNATURE_PACKET: &str = "\
        885e040016080006050255f95f95000a\
        09108cfde12197965a9af62200ff56f9\
        0cca98e2102637bd983fdb16c131dfd2\
        7ed82bf4dde5606e0d756aed33660100\
        d09c4fa11527f038e0f57f2201d82f2e\
        a2c9033265fa6ceb489e854bae61b404";

    /// The version 6 certificate of Appendix A.3, armored: an Ed25519 primary
    /// key, its direct-key signature, an X25519 subkey, and its binding.
    pub(crate) const A3_CERTIFICATE: &str = "\
-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----
";

    /// The version 6 text signature of Appendix A.6, armored: the primary
    /// key of [`A3_CERTIFICATE`] signing [`A6_TEXT`].
    pub(crate) const A6_SIGNATURE: &str = "\
-----BEGIN PGP SIGNATURE-----

wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
NK2ay45cX1IVAQ==
-----END PGP SIGNATURE-----
";

    /// The text Appendix A.6 signs, as its signature hashes it: without the
    /// dash-escapes, and with CRLF line endings.
    pub(crate) const A6_TEXT: &str = "What we need from the grocery store:\r\n\
        \r\n\
        - tofu\r\n\
        - vegetables\r\n\
        - noodles\r\n";
}

/// Certificates, signatures, and documents made for tests, by keys whose
/// secrets the tests hold.
///
/// irongall cannot sign, and the shapes the policy judges, many of them
/// defective, are ones no implementation makes on request. Here a test
/// writes the packets it needs: Ed25519 signatures are made with
/// `ed25519-dalek`, and RSA signatures with `num-bigint` over a fixed test
/// key, each over a hash the test computes from RFC 9580 §5.2.4 itself.
pub(crate) mod forge {
    use alloc::vec;
    use alloc::vec::Vec;

    use ed25519_dalek::{Signer as _, SigningKey};
    use num_bigint::BigUint;

    use super::{digest, hashed_key, hashed_user_id, hex};
    use crate::cert::{self, Certificate};
    use crate::hash::HashAlgorithm;
    use crate::key::PublicKey;
    use crate::packet::{self, Tag, Version};
    use crate::signature::{Signature, SignatureType, SubpacketType};

    /// A packet of type `tag` holding `body`, with an OpenPGP header and a
    /// five-octet length.
    pub(crate) fn packet(tag: Tag, body: &[u8]) -> Vec<u8> {
        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        [&[0xC0 | tag.number(), 0xFF][..], &length, body].concat()
    }

    /// A User ID packet.
    pub(crate) fn user_id(value: &str) -> Vec<u8> {
        packet(Tag::USER_ID, value.as_bytes())
    }

    /// The one certificate the concatenated `packets` make.
    pub(crate) fn certificate(packets: &[&[u8]]) -> Certificate {
        let data = packets.concat();
        let mut certificates = cert::certificates(&data);
        let certificate = certificates.next().unwrap().unwrap();
        assert!(certificates.next().is_none());
        certificate
    }

    /// The signature a Signature packet holds.
    pub(crate) fn read(signature: &[u8]) -> Signature {
        let packet = packet::packets(signature).next().unwrap().unwrap();
        Signature::from_packet(&packet).unwrap()
    }

    /// The Signature packet `signature` with its unhashed area replaced by
    /// what `amend` makes of it, as anyone who handles the signature can
    /// replace it: the hashed fields, the hash prefix, and the material are
    /// as they were.
    pub(crate) fn with_unhashed(signature: &[u8], amend: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
        let mut packets = packet::packets(signature);
        let body = packets.next().unwrap().unwrap().body();
        assert!(packets.next().is_none());
        let width = match body[0] {
            4 => 2,
            6 => 4,
            version => panic!("a version {version} signature"),
        };
        let length = |at: usize| {
            body[at..at + width]
                .iter()
                .fold(0, |length, &octet| length << 8 | usize::from(octet))
        };
        let hashed_end = 4 + width + length(4);
        let (start, end) = (hashed_end + width, hashed_end + width + length(hashed_end));
        let area = amend(&body[start..end]);
        let area_length = area.len().to_be_bytes();
        let body = [
            &body[..hashed_end],
            &area_length[area_length.len() - width..],
            &area,
            &body[end..],
        ]
        .concat();
        packet(Tag::SIGNATURE, &body)
    }

    /// A multiprecision integer (RFC 9580 §3.2) of the big-endian `value`.
    fn mpi(value: &[u8]) -> Vec<u8> {
        let value = &value[value.iter().take_while(|&&octet| octet == 0).count()..];
        let bits = match value.first() {
            Some(first) => value.len() * 8 - first.leading_zeros() as usize,
            None => 0,
        };
        [&u16::try_from(bits).unwrap().to_be_bytes()[..], value].concat()
    }

    /// The modulus of the RSA test key, 2048 bits, generated with OpenSSL
    /// 3.6.4 for these tests.
    const RSA_MODULUS: &str = "\
        A81CB7ABAA4242A7E9C18BB680FCCBE43BDB777FCE9F7ADC60EAB9FBD8D09F6E\
        33EB9FDE995535E850E7D4DF3F3835E26AE484F97384917E8DEEE712044F4860\
        3CE3A2FC9B05E837577FF4647DB27C20698C5A626647E784AEB8E1BCFCBCD32C\
        000328D2C3E5313404AE30FAABD0AEBE1D1FA432BB767708B7670A5B2855FBF7\
        1C8A461AA50AB5C107A2E67FBD2E0CA73C626C2FAFB4C2FD442715669E4B2E10\
        29C4486925D7512A769747C32844502DED533F9349E22E13738F0AE5FE38404A\
        B076CA693E2F431455F0DD93D8AF0E5A3637808054827B062AAB8CD7FC2AA85B\
        8BBF844225C2C3ED53E4D02480F24E939316AD16DF47E924ED3C24697BF5AF5F\
    ";

    /// The private exponent of the RSA test key, whose public exponent is
    /// 65537.
    const RSA_PRIVATE_EXPONENT: &str = "\
        0A2170E564BA8979C4EF123EF5419BFD2CFE3F67F19E500667C612B4728F0A8C\
        818F241B2DF24C9AAB5ACD2131961993D8B7DCAB8BA28ED75430F40BC9E6B288\
        84CD7DA240AAA276734CC0002E484B37F379AF18AEEBE1051B37AE4D77E2DE76\
        E5A94B147DBEEF5ACB22BECB86FF145E05DDEF99D4622C84D748865492A1B12F\
        F73FB1C36281DF8448F0097EE7FC778A10D1576D93F3A63B22DAE9002D327F23\
        F80A322E46E5DC377FEB1BB7E966FACD4A5FFF94EB6AFEC42021EC5D509BA2BA\
        953A9EA391F45005CDD84D88C24055552EDE34200232FF5C7EB46A4E879B121D\
        AADC509CDFCEDD3ECB9A9D8819A8A52CB253C02B72926865B4F9BF298FF5C1C1\
    ";

    /// The DER prefix of an RSA signature's DigestInfo, as RFC 9580 Table 24
    /// prints it.
    fn digest_info(algorithm: HashAlgorithm) -> &'static [u8] {
        match algorithm {
            HashAlgorithm::SHA1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04,
                0x14,
            ],
            HashAlgorithm::SHA224 => &[
                0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x04, 0x05, 0x00, 0x04, 0x1C,
            ],
            HashAlgorithm::SHA256 => &[
                0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            HashAlgorithm::SHA384 => &[
                0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            HashAlgorithm::SHA512 => &[
                0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
            HashAlgorithm::SHA3_256 => &[
                0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x08, 0x05, 0x00, 0x04, 0x20,
            ],
            HashAlgorithm::SHA3_512 => &[
                0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x0A, 0x05, 0x00, 0x04, 0x40,
            ],
            other => panic!("no DigestInfo for {other}"),
        }
    }

    /// The truncated DER encoding of the Ed25519Legacy curve's OID.
    const ED25519_LEGACY_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

    /// A key's secret half.
    #[derive(Debug, Clone)]
    enum Secret {
        Ed25519(SigningKey),
        Rsa { modulus: BigUint, exponent: BigUint },
    }

    /// A key a test can sign with.
    #[derive(Debug, Clone)]
    pub(crate) struct Key {
        secret: Secret,
        public: PublicKey,
    }

    impl Key {
        /// An Ed25519 key from `seed`, created at `created`: of algorithm 27
        /// in version 6, and EdDSALegacy over Ed25519Legacy (22) in version
        /// 4, as GnuPG makes them.
        pub(crate) fn ed25519(seed: u8, version: Version, created: u32) -> Key {
            let secret = SigningKey::from_bytes(&[seed; 32]);
            let point = secret.verifying_key().to_bytes();
            let created = created.to_be_bytes();
            let body = match version {
                Version::V4 => [
                    &[4][..],
                    &created,
                    &[22, 9],
                    ED25519_LEGACY_OID,
                    &mpi(&[&[0x40][..], &point].concat()),
                ]
                .concat(),
                Version::V6 => [&[6][..], &created, &[27, 0, 0, 0, 32], &point].concat(),
            };
            Key::new(Secret::Ed25519(secret), &body)
        }

        /// The RSA test key, of 2048 bits, in a version 4 key created at
        /// `created`.
        pub(crate) fn rsa(created: u32) -> Key {
            let modulus = hex(RSA_MODULUS);
            let body = [
                &[4][..],
                &created.to_be_bytes(),
                &[1],
                &mpi(&modulus),
                &mpi(&[0x01, 0x00, 0x01]),
            ]
            .concat();
            let secret = Secret::Rsa {
                modulus: BigUint::from_bytes_be(&modulus),
                exponent: BigUint::from_bytes_be(&hex(RSA_PRIVATE_EXPONENT)),
            };
            Key::new(secret, &body)
        }

        /// A key of any public material, `body` its packet's body, that signs
        /// as `like` does: a key a test can name but must not be able to sign
        /// with, such as one narrower than RSA allows, made only to be
        /// refused.
        pub(crate) fn with_body(like: &Key, body: &[u8]) -> Key {
            Key::new(like.secret.clone(), body)
        }

        fn new(secret: Secret, body: &[u8]) -> Key {
            let data = packet(Tag::PUBLIC_KEY, body);
            let packet = packet::packets(&data).next().unwrap().unwrap();
            Key {
                secret,
                public: PublicKey::from_packet(&packet).unwrap(),
            }
        }

        /// The public key.
        pub(crate) fn public(&self) -> &PublicKey {
            &self.public
        }

        /// The key as a primary key: a Public Key packet.
        pub(crate) fn primary(&self) -> Vec<u8> {
            packet(Tag::PUBLIC_KEY, self.public.body())
        }

        /// The key as a subkey: a Public Subkey packet.
        pub(crate) fn subkey(&self) -> Vec<u8> {
            packet(Tag::PUBLIC_SUBKEY, self.public.body())
        }

        /// Begins a signature by the key of `signature_type`, made at
        /// `created`, laid out as GnuPG lays one out: the creation time and
        /// the issuer's fingerprint hashed, and in version 4, the issuer's
        /// key ID unhashed. Its hash is SHA2-256 unless changed.
        pub(crate) fn sign(&self, signature_type: SignatureType, created: u32) -> Signing<'_> {
            let version = self.public.version();
            let fingerprint = [
                &[match version {
                    Version::V4 => 4,
                    Version::V6 => 6,
                }][..],
                self.public.fingerprint().as_bytes(),
            ]
            .concat();
            let signing = Signing {
                key: self,
                signature_type,
                hash: HashAlgorithm::SHA256,
                hashed: Vec::new(),
                unhashed: Vec::new(),
            }
            .hashed(
                SubpacketType::SIGNATURE_CREATION_TIME,
                &created.to_be_bytes(),
            )
            .hashed(SubpacketType::ISSUER_FINGERPRINT, &fingerprint);
            match version {
                Version::V4 => signing.unhashed(
                    SubpacketType::ISSUER_KEY_ID,
                    self.public.key_id().as_bytes(),
                ),
                Version::V6 => signing,
            }
        }

        /// The key's signature material over `digest`.
        fn material(&self, algorithm: HashAlgorithm, digest: &[u8]) -> Vec<u8> {
            match (&self.secret, self.public.version()) {
                (Secret::Ed25519(secret), Version::V4) => {
                    let native = secret.sign(digest).to_bytes();
                    [mpi(&native[..32]), mpi(&native[32..])].concat()
                }
                (Secret::Ed25519(secret), Version::V6) => secret.sign(digest).to_bytes().to_vec(),
                (Secret::Rsa { modulus, exponent }, _) => {
                    let size = (modulus.bits() as usize).div_ceil(8);
                    let info = digest_info(algorithm);
                    let padding = size - 3 - info.len() - digest.len();
                    let encoded = [&[0, 1][..], &vec![0xFF; padding], &[0], info, digest].concat();
                    let value = BigUint::from_bytes_be(&encoded).modpow(exponent, modulus);
                    mpi(&value.to_bytes_be())
                }
            }
        }
    }

    /// A signature being made: see [`Key::sign`].
    #[derive(Debug, Clone)]
    pub(crate) struct Signing<'a> {
        key: &'a Key,
        signature_type: SignatureType,
        hash: HashAlgorithm,
        hashed: Vec<u8>,
        unhashed: Vec<u8>,
    }

    /// A subpacket, with its length in the five-octet form.
    fn subpacket(subpacket_type: SubpacketType, critical: bool, body: &[u8]) -> Vec<u8> {
        let length = u32::try_from(body.len() + 1).unwrap().to_be_bytes();
        let octet = subpacket_type.number() | if critical { 0x80 } else { 0 };
        [&[0xFF][..], &length, &[octet], body].concat()
    }

    impl Signing<'_> {
        /// Makes the hash algorithm `hash`.
        pub(crate) fn hash(mut self, hash: HashAlgorithm) -> Self {
            self.hash = hash;
            self
        }

        /// Adds a hashed subpacket.
        pub(crate) fn hashed(self, subpacket_type: SubpacketType, body: &[u8]) -> Self {
            self.hashed_marked(subpacket_type, false, body)
        }

        /// Adds a hashed subpacket, marked critical if `critical`.
        pub(crate) fn hashed_marked(
            mut self,
            subpacket_type: SubpacketType,
            critical: bool,
            body: &[u8],
        ) -> Self {
            self.hashed
                .extend(subpacket(subpacket_type, critical, body));
            self
        }

        /// Adds an unhashed subpacket.
        pub(crate) fn unhashed(mut self, subpacket_type: SubpacketType, body: &[u8]) -> Self {
            self.unhashed.extend(subpacket(subpacket_type, false, body));
            self
        }

        /// Removes every subpacket, the creation time and issuers included,
        /// for a test of a signature that lacks them.
        pub(crate) fn bare(mut self) -> Self {
            self.hashed.clear();
            self.unhashed.clear();
            self
        }

        /// States key flags.
        pub(crate) fn key_flags(self, flags: u8) -> Self {
            self.hashed(SubpacketType::KEY_FLAGS, &[flags])
        }

        /// States a key expiration, `seconds` after the key's creation.
        pub(crate) fn key_expiration(self, seconds: u32) -> Self {
            self.hashed(SubpacketType::KEY_EXPIRATION_TIME, &seconds.to_be_bytes())
        }

        /// States a signature expiration, `seconds` after its creation.
        pub(crate) fn expiration(self, seconds: u32) -> Self {
            self.hashed(
                SubpacketType::SIGNATURE_EXPIRATION_TIME,
                &seconds.to_be_bytes(),
            )
        }

        /// Marks a certification's user ID as the primary one.
        pub(crate) fn primary_user_id(self) -> Self {
            self.hashed(SubpacketType::PRIMARY_USER_ID, &[1])
        }

        /// Embeds the signature `packet` holds, in the unhashed area, where
        /// GnuPG puts a back-signature.
        pub(crate) fn embed(self, signature: &[u8]) -> Self {
            let packet = packet::packets(signature).next().unwrap().unwrap();
            self.unhashed(SubpacketType::EMBEDDED_SIGNATURE, packet.body())
        }

        /// Adds a hashed notation marked critical, which irongall does not
        /// honor.
        pub(crate) fn critical_notation(self) -> Self {
            let name = b"policy@example.invalid";
            let value = b"strict";
            let body = [
                &[0x80, 0, 0, 0][..],
                &u16::try_from(name.len()).unwrap().to_be_bytes(),
                &u16::try_from(value.len()).unwrap().to_be_bytes(),
                name,
                value,
            ]
            .concat();
            self.hashed_marked(SubpacketType::NOTATION_DATA, true, &body)
        }

        /// The Signature packet over a key alone: a direct-key signature, a
        /// key revocation, or a certification revocation of a direct-key
        /// signature.
        pub(crate) fn over_key(self, key: &Key) -> Vec<u8> {
            self.over(&hashed_key(key.public.body()))
        }

        /// The Signature packet over `primary` and one of its user IDs.
        pub(crate) fn over_user_id(self, primary: &Key, user_id: &str) -> Vec<u8> {
            let data = [
                hashed_key(primary.public.body()),
                hashed_user_id(user_id.as_bytes()),
            ]
            .concat();
            self.over(&data)
        }

        /// The Signature packet over `primary` and one of its subkeys: a
        /// binding, a back-signature, or a subkey revocation.
        pub(crate) fn over_subkey(self, primary: &Key, subkey: &Key) -> Vec<u8> {
            let data = [
                hashed_key(primary.public.body()),
                hashed_key(subkey.public.body()),
            ]
            .concat();
            self.over(&data)
        }

        /// The Signature packet over a document: as it is for a binary
        /// signature, and with a CR before every LF that lacks one for a
        /// text signature.
        pub(crate) fn over_document(self, document: &[u8]) -> Vec<u8> {
            if self.signature_type != SignatureType::TEXT {
                return self.over(document);
            }
            let mut text = Vec::new();
            for (at, &octet) in document.iter().enumerate() {
                if octet == b'\n' && (at == 0 || document[at - 1] != b'\r') {
                    text.push(b'\r');
                }
                text.push(octet);
            }
            self.over(&text)
        }

        /// The Signature packet over `data`, the subject's data as RFC 9580
        /// §5.2.4 hashes it.
        pub(crate) fn over(self, data: &[u8]) -> Vec<u8> {
            let public = &self.key.public;
            let version = public.version();
            let area = |area: &[u8]| match version {
                Version::V4 => {
                    [&u16::try_from(area.len()).unwrap().to_be_bytes()[..], area].concat()
                }
                Version::V6 => {
                    [&u32::try_from(area.len()).unwrap().to_be_bytes()[..], area].concat()
                }
            };
            let (version_octet, salt) = match version {
                Version::V4 => (4, Vec::new()),
                Version::V6 => {
                    let size = self.hash.v6_salt_size().expect("a version 6 hash");
                    (6, vec![0x5A; usize::from(size)])
                }
            };
            let hashed_fields = [
                &[
                    version_octet,
                    self.signature_type.number(),
                    public.algorithm().number(),
                    self.hash.number(),
                ][..],
                &area(&self.hashed),
            ]
            .concat();
            let length = u32::try_from(hashed_fields.len()).unwrap().to_be_bytes();
            let input = [&salt, data, &hashed_fields, &[version_octet, 0xFF], &length].concat();
            let digest = digest(self.hash, &input);
            let digest = digest.as_bytes();

            let mut body = [hashed_fields, area(&self.unhashed), digest[..2].to_vec()].concat();
            if version == Version::V6 {
                body.push(u8::try_from(salt.len()).unwrap());
                body.extend(&salt);
            }
            body.extend(self.key.material(self.hash, digest));
            packet(Tag::SIGNATURE, &body)
        }
    }
}
