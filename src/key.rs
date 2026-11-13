//! Public keys (RFC 9580 §5.5): key packets, and the fingerprints and key IDs
//! that name them.
//!
//! [`PublicKey::from_packet`] reads a Public Key or Public Subkey packet of
//! version 4 or 6:
//!
//! ```
//! use irongall::key::{PublicKey, PublicKeyAlgorithm};
//! use irongall::packet;
//!
//! // The version 4 Ed25519Legacy key of RFC 9580 Appendix A.1.
//! let input = [
//!     0x98, 0x33, 0x04, 0x53, 0xF3, 0x5F, 0x0B, 0x16, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01,
//!     0xDA, 0x47, 0x0F, 0x01, 0x01, 0x07, 0x40, 0x3F, 0x09, 0x89, 0x94, 0xBD, 0xD9, 0x16,
//!     0xED, 0x40, 0x53, 0x19, 0x79, 0x34, 0xE4, 0xA8, 0x7C, 0x80, 0x73, 0x3A, 0x12, 0x80,
//!     0xD6, 0x2F, 0x80, 0x10, 0x99, 0x2E, 0x43, 0xEE, 0x3B, 0x24, 0x06,
//! ];
//! let packet = packet::packets(&input).next().unwrap()?;
//! let key = PublicKey::from_packet(&packet)?;
//! assert_eq!(key.algorithm(), PublicKeyAlgorithm::EDDSA_LEGACY);
//! assert_eq!(
//!     key.fingerprint().to_string(),
//!     "C959BDBAFA32A2F89A153B678CFDE12197965A9A"
//! );
//! assert_eq!(key.key_id().to_string(), "8CFDE12197965A9A");
//! # Ok::<(), irongall::packet::PacketError>(())
//! ```
//!
//! A key of any algorithm parses and has a fingerprint, so that a
//! certificate's encryption subkeys, and keys of algorithms irongall does not
//! implement, can still be named. Only the material of the algorithms irongall
//! verifies with is read: RSA, Ed25519, and EdDSALegacy over Ed25519Legacy.
//! Any other material is [`KeyMaterial::Opaque`]. So is an EdDSALegacy key of
//! version 6, since RFC 9580 §9.2 forbids the deprecated curves there.
//!
//! A key of another version is refused as
//! [`UnsupportedVersion`](PacketErrorKind::UnsupportedVersion): versions 3 and
//! 5 take their fingerprints differently, so irongall cannot name them.

use alloc::boxed::Box;
use core::fmt;

use crate::hash::{HashFunction as _, Sha1, Sha256};
use crate::packet::{Fields, Packet, PacketError, PacketErrorKind, Tag, Version};
use crate::wire::wire_number;

wire_number! {
    /// A public-key algorithm (RFC 9580 §9.1).
    ///
    /// Every octet is an algorithm a packet can name; the constants name the
    /// ones RFC 9580 assigns.
    pub struct PublicKeyAlgorithm;
    unnamed = "public-key algorithm";
    /// RSA, for encryption or signing (1).
    const RSA = 1, "RSA";
    /// RSA for encryption only (2), deprecated.
    const RSA_ENCRYPT_ONLY = 2, "RSA (encrypt only)";
    /// RSA for signing only (3), deprecated.
    const RSA_SIGN_ONLY = 3, "RSA (sign only)";
    /// Elgamal, for encryption only (16).
    const ELGAMAL_ENCRYPT_ONLY = 16, "Elgamal (encrypt only)";
    /// DSA (17).
    const DSA = 17, "DSA";
    /// ECDH (18).
    const ECDH = 18, "ECDH";
    /// ECDSA (19).
    const ECDSA = 19, "ECDSA";
    /// EdDSALegacy (22), deprecated: EdDSA over a curve named by an OID.
    const EDDSA_LEGACY = 22, "EdDSALegacy";
    /// X25519 (25).
    const X25519 = 25, "X25519";
    /// X448 (26).
    const X448 = 26, "X448";
    /// Ed25519 (27).
    const ED25519 = 27, "Ed25519";
    /// Ed448 (28).
    const ED448 = 28, "Ed448";
}

impl PublicKeyAlgorithm {
    /// Whether the algorithm is one of RSA's three, whose keys and
    /// signatures carry the same material: RSA, and its encrypt-only and
    /// sign-only variants.
    pub(crate) const fn is_rsa(self) -> bool {
        matches!(
            self,
            PublicKeyAlgorithm::RSA
                | PublicKeyAlgorithm::RSA_ENCRYPT_ONLY
                | PublicKeyAlgorithm::RSA_SIGN_ONLY
        )
    }

    /// Whether the algorithm signs with RSA: RSA, or its sign-only variant.
    /// The encrypt-only variant carries RSA material, but does not sign.
    pub(crate) const fn signs_with_rsa(self) -> bool {
        matches!(
            self,
            PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSA_SIGN_ONLY
        )
    }

    /// Whether the algorithm signs with Ed25519: Ed25519, or EdDSALegacy,
    /// whose only curve RFC 9580 defines is Ed25519Legacy (§9.2).
    pub(crate) const fn signs_with_ed25519(self) -> bool {
        matches!(
            self,
            PublicKeyAlgorithm::ED25519 | PublicKeyAlgorithm::EDDSA_LEGACY
        )
    }
}

/// A key's public material, for the algorithms irongall verifies with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyMaterial<'a> {
    /// An RSA key, of any of the three RSA algorithms.
    Rsa {
        /// The modulus n, big-endian, without leading zeros.
        modulus: &'a [u8],
        /// The public exponent e, big-endian, without leading zeros.
        exponent: &'a [u8],
    },
    /// An Ed25519 key, in its native 32-octet encoding (RFC 8032 §5.1.5).
    ///
    /// An Ed25519 key carries the encoding as it is; an EdDSALegacy key over
    /// Ed25519Legacy carries it as a prefixed native point.
    Ed25519(&'a [u8; 32]),
    /// Material irongall does not read: an algorithm it does not verify with,
    /// or a curve it does not know. The key has a fingerprint, and verifies
    /// nothing.
    Opaque,
}

/// The truncated DER encoding of the Ed25519Legacy curve's OID,
/// 1.3.6.1.4.1.11591.15.1 (RFC 9580 §9.2).
const ED25519_LEGACY_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

/// A public key: the content of a Public Key or Public Subkey packet.
///
/// A key holds its packet's body, and its material is read from that on
/// demand. Two keys are equal when their bodies are, octet for octet. Its
/// [`Debug`](fmt::Debug) form shows what the accessors read, not the body's
/// octets.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// The packet's body, which a signature over the key hashes (RFC 9580
    /// §5.2.4), and which the material is read from.
    body: Box<[u8]>,
    fingerprint: Fingerprint,
    creation_time: u32,
    version: Version,
    algorithm: PublicKeyAlgorithm,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("version", &self.version)
            .field("creation_time", &self.creation_time)
            .field("algorithm", &self.algorithm)
            .field("material", &self.material())
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl PublicKey {
    /// Reads a Public Key or Public Subkey packet.
    ///
    /// # Errors
    ///
    /// When the packet is of another type, of a version other than 4 or 6,
    /// or malformed. A key of an algorithm irongall does not read is not an
    /// error; its material is [`KeyMaterial::Opaque`].
    pub fn from_packet(packet: &Packet<'_>) -> Result<PublicKey, PacketError> {
        if packet.tag() != Tag::PUBLIC_KEY && packet.tag() != Tag::PUBLIC_SUBKEY {
            return Err(packet.error(PacketErrorKind::UnexpectedType));
        }
        let (version, creation_time, algorithm, _) = read(packet.fields())?;
        let fingerprint = Fingerprint::of(version, packet.body())
            .ok_or_else(|| packet.error(PacketErrorKind::KeyTooLong))?;
        Ok(PublicKey {
            body: packet.body().into(),
            fingerprint,
            creation_time,
            version,
            algorithm,
        })
    }

    /// The key's version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// When the key was created, in seconds since the Unix epoch.
    pub fn creation_time(&self) -> u32 {
        self.creation_time
    }

    /// The key's algorithm.
    pub fn algorithm(&self) -> PublicKeyAlgorithm {
        self.algorithm
    }

    /// The key's material.
    pub fn material(&self) -> KeyMaterial<'_> {
        // Read when the key was, so this does not fail.
        read(Fields::of(&self.body)).map_or(KeyMaterial::Opaque, |(.., material)| material)
    }

    /// The key's fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// The key's ID, derived from its fingerprint.
    pub fn key_id(&self) -> KeyId {
        self.fingerprint.key_id()
    }

    /// The body of the packet the key was read from.
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Reads a key packet's body: its version, creation time, algorithm, and
/// material (RFC 9580 §5.5.2).
fn read(
    mut fields: Fields<'_>,
) -> Result<(Version, u32, PublicKeyAlgorithm, KeyMaterial<'_>), PacketError> {
    let at = fields.offset();
    let version = Version::from_number(fields.u8()?)
        .ok_or_else(|| fields.error_at(PacketErrorKind::UnsupportedVersion, at))?;
    let creation_time = fields.u32()?;
    let algorithm = PublicKeyAlgorithm(fields.u8()?);
    let material = match version {
        Version::V4 => read_material(&mut fields, algorithm, version)?,
        Version::V6 => {
            // A failure to fit the material to its stated length, either
            // way, is the length's.
            let fit = |error: PacketError| match error.kind() {
                PacketErrorKind::TruncatedBody | PacketErrorKind::TrailingData => {
                    error.with_kind(PacketErrorKind::MaterialLength)
                }
                _ => error,
            };
            let length = usize::try_from(fields.u32()?).unwrap_or(usize::MAX);
            let mut material = fields.split(length).map_err(fit)?;
            let read = read_material(&mut material, algorithm, version).map_err(fit)?;
            material.finish().map_err(fit)?;
            read
        }
    };
    fields.finish()?;
    Ok((version, creation_time, algorithm, material))
}

/// Reads the algorithm-specific material of a key (RFC 9580 §5.5.5), up to
/// the end of `fields`.
fn read_material<'a>(
    fields: &mut Fields<'a>,
    algorithm: PublicKeyAlgorithm,
    version: Version,
) -> Result<KeyMaterial<'a>, PacketError> {
    match algorithm {
        rsa if rsa.is_rsa() => {
            let modulus = fields.mpi(version)?;
            let exponent = fields.mpi(version)?;
            Ok(KeyMaterial::Rsa { modulus, exponent })
        }
        PublicKeyAlgorithm::ED25519 => {
            let at = fields.offset();
            <&[u8; 32]>::try_from(fields.take(32)?)
                .map(KeyMaterial::Ed25519)
                .map_err(|_| fields.error_at(PacketErrorKind::InvalidMaterial, at))
        }
        PublicKeyAlgorithm::EDDSA_LEGACY if version == Version::V4 => read_eddsa_legacy(fields),
        _ => {
            fields.rest();
            Ok(KeyMaterial::Opaque)
        }
    }
}

/// Reads an EdDSALegacy key's curve and point (RFC 9580 §5.5.5.5).
fn read_eddsa_legacy<'a>(fields: &mut Fields<'a>) -> Result<KeyMaterial<'a>, PacketError> {
    let oid_length = fields.u8()?;
    // Lengths 0 and 0xFF are reserved for extensions RFC 9580 does not
    // define, so the field's format is unknown, as is any curve but one.
    if oid_length == 0
        || oid_length == 0xFF
        || fields.take(usize::from(oid_length))? != ED25519_LEGACY_OID
    {
        fields.rest();
        return Ok(KeyMaterial::Opaque);
    }
    let at = fields.offset();
    // A prefixed native point (RFC 9580 §11.2.2): 0x40, then the native
    // encoding.
    match fields.mpi(Version::V4)? {
        [0x40, native @ ..] => <&[u8; 32]>::try_from(native)
            .map(KeyMaterial::Ed25519)
            .map_err(|_| fields.error_at(PacketErrorKind::InvalidMaterial, at)),
        _ => Err(fields.error_at(PacketErrorKind::InvalidMaterial, at)),
    }
}

/// A key's fingerprint (RFC 9580 §5.5.4): what names a key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Fingerprint {
    /// A version 4 key's fingerprint: SHA-1 over the key packet.
    V4([u8; 20]),
    /// A version 6 key's fingerprint: SHA2-256 over the key packet.
    V6([u8; 32]),
}

/// Passes a key's packet body to `update` as RFC 9580 frames a key for hashing
/// under `version`: after `0x99` and the body's length in two octets for
/// version 4, and after `0x9B` and the length in four octets for version 6.
///
/// A fingerprint frames a key by the key's own version (§5.5.4), and a
/// signature over a key by the signature's version (§5.2.4).
///
/// Returns `None`, having passed nothing, when the length does not fit its
/// field.
pub(crate) fn frame_for_hashing(
    version: Version,
    body: &[u8],
    mut update: impl FnMut(&[u8]),
) -> Option<()> {
    match version {
        Version::V4 => {
            let length = u16::try_from(body.len()).ok()?;
            update(&[0x99]);
            update(&length.to_be_bytes());
        }
        Version::V6 => {
            let length = u32::try_from(body.len()).ok()?;
            update(&[0x9B]);
            update(&length.to_be_bytes());
        }
    }
    update(body);
    Some(())
}

impl Fingerprint {
    /// The fingerprint of a key of `version` whose packet body is `body`, or
    /// `None` for a version 4 body too long to take one.
    fn of(version: Version, body: &[u8]) -> Option<Fingerprint> {
        match version {
            Version::V4 => {
                let mut hash = Sha1::new();
                frame_for_hashing(version, body, |data| hash.update(data))?;
                Some(Fingerprint::V4(hash.finalize()))
            }
            Version::V6 => {
                let mut hash = Sha256::new();
                frame_for_hashing(version, body, |data| hash.update(data))?;
                Some(Fingerprint::V6(hash.finalize()))
            }
        }
    }

    /// The version of the key the fingerprint names.
    pub fn version(&self) -> Version {
        match self {
            Fingerprint::V4(_) => Version::V4,
            Fingerprint::V6(_) => Version::V6,
        }
    }

    /// The fingerprint's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Fingerprint::V4(bytes) => bytes,
            Fingerprint::V6(bytes) => bytes,
        }
    }

    /// The key ID the fingerprint determines: its last eight octets for a
    /// version 4 key, and its first eight for a version 6 key.
    pub fn key_id(&self) -> KeyId {
        match *self {
            Fingerprint::V4([.., a, b, c, d, e, f, g, h]) => KeyId([a, b, c, d, e, f, g, h]),
            Fingerprint::V6([a, b, c, d, e, f, g, h, ..]) => KeyId([a, b, c, d, e, f, g, h]),
        }
    }
}

/// Uppercase hexadecimal without separators, as `gpg --with-colons` prints
/// it.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, self.as_bytes())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fingerprint::V4(_) => write!(f, "Fingerprint::V4({self})"),
            Fingerprint::V6(_) => write!(f, "Fingerprint::V6({self})"),
        }
    }
}

/// A key ID (RFC 9580 §5.5.4): eight octets of a key's fingerprint.
///
/// Key IDs are not unique, and a match on one is a hint about which key to
/// try, never evidence of which key signed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId([u8; 8]);

impl KeyId {
    /// The key ID with these octets.
    pub const fn from_bytes(bytes: [u8; 8]) -> KeyId {
        KeyId(bytes)
    }

    /// The key ID's octets.
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

/// Uppercase hexadecimal without separators, as `gpg --with-colons` prints
/// it.
impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({self})")
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    bytes.iter().try_for_each(|byte| write!(f, "{byte:02X}"))
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString as _;
    use alloc::vec::Vec;

    use super::{Fingerprint, KeyId, KeyMaterial, PublicKey, PublicKeyAlgorithm};
    use crate::armor;
    use crate::hash::{HashFunction as _, Sha1};
    use crate::packet::{PacketError, PacketErrorKind, Tag, Version, packets};
    use crate::test_support::hex;
    use crate::test_support::rfc9580::{A1_KEY, A3_CERTIFICATE};

    /// The keys among the packets of an armored block.
    fn keys(armored: &str) -> Vec<PublicKey> {
        let data = armor::decode(armored.as_bytes()).unwrap().into_data();
        packets(&data)
            .map(Result::unwrap)
            .filter(|packet| matches!(packet.tag(), Tag::PUBLIC_KEY | Tag::PUBLIC_SUBKEY))
            .map(|packet| PublicKey::from_packet(&packet).unwrap())
            .collect()
    }

    /// Reads `body` as the body of a Public Key packet whose header is six
    /// octets long, so that the body's fields begin at offset 6: the version
    /// at 6, the creation time at 7, the algorithm at 11, and the material
    /// (or a version 6 key's material length) at 12.
    fn parse(body: &[u8]) -> Result<PublicKey, PacketError> {
        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        let input = [&[0xC6, 0xFF][..], &length, body].concat();
        let packet = packets(&input).next().unwrap().unwrap();
        PublicKey::from_packet(&packet)
    }

    /// A key body of `version`, created at 0x01020304, of `algorithm`, with
    /// `material` (a version 6 body states its length first).
    fn body(version: u8, algorithm: u8, material: &[u8]) -> Vec<u8> {
        let mut body = [&[version, 0x01, 0x02, 0x03, 0x04, algorithm][..]].concat();
        if version == 6 {
            body.extend_from_slice(&u32::try_from(material.len()).unwrap().to_be_bytes());
        }
        body.extend_from_slice(material);
        body
    }

    fn failure(body: &[u8]) -> (PacketErrorKind, usize) {
        let error = parse(body).unwrap_err();
        (error.kind(), error.offset())
    }

    /// The EdDSALegacy material for `point` on Ed25519Legacy: the curve OID,
    /// then the point as an MPI of 263 bits.
    fn eddsa_legacy(point: &[u8]) -> Vec<u8> {
        let oid = [0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
        [&oid[..], &[0x01, 0x07], point].concat()
    }

    #[test]
    fn rfc_9580_version_4_key() {
        let [key] = keys(A1_KEY).try_into().unwrap();
        assert_eq!(key.version(), Version::V4);
        // 2014-08-19 14:28:27 UTC.
        assert_eq!(key.creation_time(), 1_408_458_507);
        assert_eq!(key.algorithm(), PublicKeyAlgorithm::EDDSA_LEGACY);
        let point = hex("3f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406");
        assert_eq!(
            key.material(),
            KeyMaterial::Ed25519(&point.try_into().unwrap())
        );
        assert_eq!(
            key.fingerprint().to_string(),
            "C959BDBAFA32A2F89A153B678CFDE12197965A9A"
        );
        assert_eq!(key.key_id().to_string(), "8CFDE12197965A9A");
    }

    #[test]
    fn rfc_9580_version_6_certificate() {
        let [primary, subkey] = keys(A3_CERTIFICATE).try_into().unwrap();
        assert_eq!(primary.version(), Version::V6);
        assert_eq!(primary.creation_time(), 0x6387_7FE3);
        assert_eq!(primary.algorithm(), PublicKeyAlgorithm::ED25519);
        let native = hex("f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3");
        assert_eq!(
            primary.material(),
            KeyMaterial::Ed25519(&native.try_into().unwrap())
        );
        assert_eq!(
            primary.fingerprint().to_string(),
            "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"
        );
        assert_eq!(primary.key_id().to_string(), "CB186C4F0609A697");

        assert_eq!(subkey.algorithm(), PublicKeyAlgorithm::X25519);
        assert_eq!(subkey.material(), KeyMaterial::Opaque);
        assert_eq!(
            subkey.fingerprint().to_string(),
            "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"
        );
    }

    #[test]
    fn rsa_material() {
        // A version 4 MPI may count leading zeros; the value drops them.
        let material = [0x00, 0x10, 0x00, 0xC5, 0x00, 0x11, 0x01, 0x00, 0x01];
        let key = parse(&body(4, 1, &material)).unwrap();
        assert_eq!(
            key.material(),
            KeyMaterial::Rsa {
                modulus: &[0xC5],
                exponent: &[0x01, 0x00, 0x01],
            }
        );
        for algorithm in [2, 3] {
            let key = parse(&body(4, algorithm, &material)).unwrap();
            assert!(matches!(key.material(), KeyMaterial::Rsa { .. }));
        }
        // Version 6 requires the exact length.
        assert_eq!(
            failure(&body(6, 1, &material)),
            (PacketErrorKind::InvalidMpi, 16)
        );
        let exact = [0x00, 0x08, 0xC5, 0x00, 0x11, 0x01, 0x00, 0x01];
        assert!(matches!(
            parse(&body(6, 1, &exact)).unwrap().material(),
            KeyMaterial::Rsa { .. }
        ));
    }

    /// A key's `Debug` form shows what the accessors read, the material
    /// among them, rather than the body it reads them from.
    #[test]
    fn debug_shows_what_the_accessors_read() {
        let key = parse(&body(4, 27, &[0x11; 32])).unwrap();
        let shown = format!("{key:?}");
        for field in [
            format!("material: {:?}", key.material()),
            format!("fingerprint: {:?}", key.fingerprint()),
        ] {
            assert!(shown.contains(&field), "{field} in {shown}");
        }
        assert!(!shown.contains("body"), "{shown}");
    }

    #[test]
    fn ed25519_material() {
        let key = parse(&body(4, 27, &[0x11; 32])).unwrap();
        assert_eq!(key.material(), KeyMaterial::Ed25519(&[0x11; 32]));
        let key = parse(&body(6, 27, &[0x11; 32])).unwrap();
        assert_eq!(key.material(), KeyMaterial::Ed25519(&[0x11; 32]));

        let point = [&[0x40][..], &[0x22; 32]].concat();
        let key = parse(&body(4, 22, &eddsa_legacy(&point))).unwrap();
        assert_eq!(key.material(), KeyMaterial::Ed25519(&[0x22; 32]));
    }

    #[test]
    fn unread_material_is_opaque() {
        let unknown_curve = [0x03, 0x2B, 0x65, 0x71, 0x00, 0x01, 0x01];
        for (version, algorithm, material) in [
            // Algorithms irongall does not verify with, known or not.
            (4, 17, &[0xFF, 0xFF, 0xFF][..]),
            (4, 25, &[0x33; 32]),
            (4, 100, &[]),
            (6, 25, &[0x33; 32]),
            (6, 18, &[0x01, 0x02]),
            // A curve other than Ed25519Legacy, and the reserved OID lengths.
            (4, 22, &unknown_curve),
            (4, 22, &[0x00, 0x01]),
            (4, 22, &[0xFF, 0x01]),
            // RFC 9580 §9.2 forbids the deprecated curves in version 6.
            (6, 22, &eddsa_legacy(&[&[0x40][..], &[0x22; 32]].concat())),
        ] {
            let key = parse(&body(version, algorithm, material)).unwrap();
            assert_eq!(key.material(), KeyMaterial::Opaque, "{version} {algorithm}");
        }
    }

    #[test]
    fn malformed_keys_are_refused() {
        let point = [&[0x40][..], &[0x22; 32]].concat();
        for (body, kind, offset) in [
            // Versions 3 and 5 take their fingerprints differently.
            (body(3, 1, &[]), PacketErrorKind::UnsupportedVersion, 6),
            (
                body(5, 27, &[0x11; 32]),
                PacketErrorKind::UnsupportedVersion,
                6,
            ),
            (
                [0x04, 0x01, 0x02].to_vec(),
                PacketErrorKind::TruncatedBody,
                7,
            ),
            (
                [0x04, 0x01, 0x02, 0x03, 0x04].to_vec(),
                PacketErrorKind::TruncatedBody,
                11,
            ),
            (body(4, 27, &[0x11; 31]), PacketErrorKind::TruncatedBody, 12),
            (body(4, 27, &[0x11; 33]), PacketErrorKind::TrailingData, 44),
            (
                body(4, 1, &[0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00]),
                PacketErrorKind::TrailingData,
                18,
            ),
            (
                body(4, 1, &[0x00, 0x01, 0x03, 0x00, 0x01, 0x01]),
                PacketErrorKind::InvalidMpi,
                12,
            ),
            (
                body(4, 1, &[0x00, 0x01, 0x01]),
                PacketErrorKind::TruncatedBody,
                15,
            ),
            // A point without its prefix, or of the wrong length.
            (
                body(4, 22, &eddsa_legacy(&[0x41; 33])),
                PacketErrorKind::InvalidMaterial,
                22,
            ),
            (
                body(
                    4,
                    22,
                    &[&eddsa_legacy(&[0x40])[..10], &[0x00, 0xFF], &point[..32]].concat(),
                ),
                PacketErrorKind::InvalidMaterial,
                22,
            ),
            // Version 6 material of a length other than its packet states, in
            // either direction: at the field that does not fit, or at what
            // follows the last field.
            (
                body(6, 27, &[0x11; 31]),
                PacketErrorKind::MaterialLength,
                16,
            ),
            (
                body(6, 27, &[0x11; 33]),
                PacketErrorKind::MaterialLength,
                48,
            ),
            (
                [body(6, 27, &[0x11; 32]), [0x00].to_vec()].concat(),
                PacketErrorKind::TrailingData,
                48,
            ),
            (
                [
                    &[0x06, 0x01, 0x02, 0x03, 0x04, 27, 0x00, 0x00, 0x00, 0x21][..],
                    &[0x11; 32],
                ]
                .concat(),
                PacketErrorKind::MaterialLength,
                16,
            ),
        ] {
            assert_eq!(failure(&body), (kind, offset), "{body:02X?}");
        }

        // Another type of packet.
        let input = [0xC2, 0x00];
        let packet = packets(&input).next().unwrap().unwrap();
        let error = PublicKey::from_packet(&packet).unwrap_err();
        assert_eq!(
            (error.kind(), error.offset()),
            (PacketErrorKind::UnexpectedType, 0)
        );
    }

    #[test]
    fn version_4_fingerprints_cover_the_body_up_to_65535_octets() {
        let longest = body(4, 100, &[0x44; 65535 - 6]);
        let key = parse(&longest).unwrap();
        let mut hash = Sha1::new();
        hash.update(&[0x99, 0xFF, 0xFF]);
        hash.update(&longest);
        assert_eq!(key.fingerprint(), Fingerprint::V4(hash.finalize()));

        let error = parse(&body(4, 100, &[0x44; 65536 - 6])).unwrap_err();
        assert_eq!(
            (error.kind(), error.offset()),
            (PacketErrorKind::KeyTooLong, 0)
        );
    }

    #[test]
    fn formatting() {
        let key = parse(&body(4, 27, &[0x11; 32])).unwrap();
        let fingerprint = key.fingerprint().to_string();
        assert_eq!(fingerprint.len(), 40);
        assert!(fingerprint.ends_with(&key.key_id().to_string()));
        assert_eq!(
            format!("{:?}", key.fingerprint()),
            format!("Fingerprint::V4({fingerprint})")
        );
        let id = KeyId::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        assert_eq!(id.to_string(), "0123456789ABCDEF");
        assert_eq!(format!("{id:?}"), "KeyId(0123456789ABCDEF)");
        assert_eq!(PublicKeyAlgorithm::ED25519.to_string(), "Ed25519");
        assert_eq!(
            format!("{:?}", PublicKeyAlgorithm(100)),
            "PublicKeyAlgorithm(100: public-key algorithm 100)"
        );
    }

    /// The families of algorithms, over every octet.
    #[test]
    fn algorithm_families() {
        for number in 0..=u8::MAX {
            let algorithm = PublicKeyAlgorithm(number);
            assert_eq!(algorithm.is_rsa(), matches!(number, 1..=3), "{number}");
            assert_eq!(
                algorithm.signs_with_rsa(),
                matches!(number, 1 | 3),
                "{number}"
            );
            assert_eq!(
                algorithm.signs_with_ed25519(),
                matches!(number, 22 | 27),
                "{number}"
            );
        }
    }
}
