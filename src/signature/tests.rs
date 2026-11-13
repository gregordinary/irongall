use alloc::string::ToString as _;
use alloc::vec::Vec;
use alloc::{format, vec};

use super::{RevocationCode, Signature, SignatureMaterial, SignatureType, SubpacketType};
use crate::armor;
use crate::hash::HashAlgorithm;
use crate::key::{Fingerprint, KeyId, PublicKeyAlgorithm};
use crate::packet::{Packet, PacketError, PacketErrorKind, Tag, Version, packets};
use crate::test_support::hex;
use crate::test_support::rfc9580::{A2_SIGNATURE, A2_SIGNATURE_PACKET, A3_CERTIFICATE};

/// Reads `body` as the body of a Signature packet whose header is six octets
/// long, so that the body's fields begin at offset 6.
fn parse(body: &[u8]) -> Result<Signature, PacketError> {
    parse_with(body, Signature::from_packet)
}

/// [`parse`], reading with `read`.
fn parse_with(
    body: &[u8],
    read: fn(&Packet<'_>) -> Result<Signature, PacketError>,
) -> Result<Signature, PacketError> {
    let length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let input = [&[0xC2, 0xFF][..], &length, body].concat();
    let packet = packets(&input).next().unwrap().unwrap();
    read(&packet)
}

fn failure(body: &[u8]) -> (PacketErrorKind, usize) {
    let error = parse(body).unwrap_err();
    (error.kind(), error.offset())
}

/// A subpacket: its length in one, two, or five octets, whichever it needs,
/// then `type_octet` and `body`.
fn subpacket(type_octet: u8, body: &[u8]) -> Vec<u8> {
    let length = body.len() + 1;
    let mut encoded = match length {
        0..192 => vec![length as u8],
        192..16320 => {
            let over = length - 192;
            vec![(over >> 8) as u8 + 192, over as u8]
        }
        _ => [&[0xFF][..], &u32::try_from(length).unwrap().to_be_bytes()].concat(),
    };
    encoded.push(type_octet);
    encoded.extend_from_slice(body);
    encoded
}

/// A Signature Creation Time subpacket for 0x01020304: six octets.
fn created() -> Vec<u8> {
    subpacket(0x02, &[0x01, 0x02, 0x03, 0x04])
}

/// The salt size a version 6 signature over `hash` carries.
fn salt_size(hash: u8) -> usize {
    match hash {
        9 => 24,
        10 | 14 => 32,
        _ => 16,
    }
}

/// A signature body of `version` and type `signature_type`, by `algorithm`
/// over `hash`, with the subpacket areas `hashed` and `unhashed`, the hash
/// prefix 0xABCD, for version 6 a salt of `hash`'s size filled with 0x5A, and
/// `material`.
fn body(
    version: u8,
    signature_type: u8,
    algorithm: u8,
    hash: u8,
    hashed: &[u8],
    unhashed: &[u8],
    material: &[u8],
) -> Vec<u8> {
    let mut body = vec![version, signature_type, algorithm, hash];
    for area in [hashed, unhashed] {
        if version == 6 {
            body.extend_from_slice(&u32::try_from(area.len()).unwrap().to_be_bytes());
        } else {
            body.extend_from_slice(&u16::try_from(area.len()).unwrap().to_be_bytes());
        }
        body.extend_from_slice(area);
    }
    body.extend_from_slice(&[0xAB, 0xCD]);
    if version == 6 {
        let size = salt_size(hash);
        body.push(u8::try_from(size).unwrap());
        body.extend_from_slice(&vec![0x5A; size]);
    }
    body.extend_from_slice(material);
    body
}

/// A version 4 binary signature by an Ed25519 key over SHA2-256. With
/// [`created`] as its hashed area and nothing unhashed, its fields fall at:
/// the version at 6, the hashed area's length at 10 and its subpackets at 12,
/// the unhashed area's length at 18, the hash prefix at 20, and the material
/// at 22.
fn v4(hashed: &[u8], unhashed: &[u8]) -> Vec<u8> {
    body(4, 0x00, 27, 8, hashed, unhashed, &[0x11; 64])
}

/// [`v4`], in version 6: the hashed area's length at 10 and its subpackets at
/// 14, the unhashed area's length at 20, the hash prefix at 24, the salt size
/// at 26, the salt at 27, and the material at 43.
fn v6(hashed: &[u8], unhashed: &[u8]) -> Vec<u8> {
    body(6, 0x00, 27, 8, hashed, unhashed, &[0x11; 64])
}

/// The signatures among the packets of an armored block.
fn signatures(armored: &str) -> Vec<Signature> {
    let data = armor::decode(armored.as_bytes()).unwrap().into_data();
    packets(&data)
        .map(Result::unwrap)
        .filter(|packet| packet.tag() == Tag::SIGNATURE)
        .map(|packet| Signature::from_packet(&packet).unwrap())
        .collect()
}

#[test]
fn rfc_9580_version_4_signature() {
    let [signature] = signatures(A2_SIGNATURE).try_into().unwrap();
    assert_eq!(signature.version(), Version::V4);
    assert_eq!(signature.signature_type(), SignatureType::BINARY);
    assert_eq!(
        signature.public_key_algorithm(),
        PublicKeyAlgorithm::EDDSA_LEGACY
    );
    assert_eq!(signature.hash_algorithm(), HashAlgorithm::SHA256);
    assert_eq!(signature.creation_time(), 0x55F9_5F95);
    assert_eq!(signature.hash_prefix(), [0xF6, 0x22]);
    assert!(signature.salt().is_empty());
    let native = hex(
        "56f90cca98e2102637bd983fdb16c131dfd27ed82bf4dde5606e0d756aed3366\
         d09c4fa11527f038e0f57f2201d82f2ea2c9033265fa6ceb489e854bae61b404",
    );
    assert_eq!(
        signature.material(),
        SignatureMaterial::Ed25519(native.try_into().unwrap())
    );
    let issuer = KeyId::from_bytes(hex("8cfde12197965a9a").try_into().unwrap());
    assert_eq!(signature.issuer_key_ids().collect::<Vec<_>>(), [issuer]);
    assert_eq!(signature.issuer_fingerprints().count(), 0);
    let [unhashed] = signature.unhashed_subpackets().collect::<Vec<_>>()[..] else {
        panic!("one unhashed subpacket");
    };
    assert_eq!(unhashed.subpacket_type(), SubpacketType::ISSUER_KEY_ID);
    assert!(!unhashed.is_critical());
    // The version through the hashed subpackets, after the packet's two-octet
    // header.
    assert_eq!(
        signature.hashed_fields(),
        &hex(A2_SIGNATURE_PACKET)[2..2 + 6 + 6]
    );
    assert!(signature.embedded_signatures().is_empty());
}

#[test]
fn rfc_9580_version_6_signatures() {
    let [direct, binding] = signatures(A3_CERTIFICATE).try_into().unwrap();
    let primary = Fingerprint::V6(
        hex("cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9")
            .try_into()
            .unwrap(),
    );

    assert_eq!(direct.version(), Version::V6);
    assert_eq!(direct.signature_type(), SignatureType::DIRECT_KEY);
    assert_eq!(direct.public_key_algorithm(), PublicKeyAlgorithm::ED25519);
    assert_eq!(direct.hash_algorithm(), HashAlgorithm::SHA512);
    // 2022-11-30 16:08:03 UTC.
    assert_eq!(direct.creation_time(), 0x6387_7FE3);
    assert_eq!(direct.hash_prefix(), [0xAD, 0x28]);
    // The salt and hashed fields are those RFC 9580 Appendix A.3.1 hashes.
    assert_eq!(
        direct.salt(),
        hex("103e2d7d227ec0e6d7ce4471db36bfc97083253690271498a7ef0576c07faae1")
    );
    assert_eq!(direct.hashed_fields().len(), 0x4A);
    assert_eq!(direct.hashed_fields()[..8], hex("061f1b0a00000042"));
    let flags = direct.key_flags().unwrap();
    assert!(flags.may_certify() && flags.may_sign());
    assert_eq!(flags.as_bytes(), [0x03]);
    assert_eq!(direct.issuer_fingerprints().collect::<Vec<_>>(), [primary]);
    assert_eq!(direct.issuer_key_ids().count(), 0);
    let hashed: Vec<_> = direct
        .hashed_subpackets()
        .map(|subpacket| (subpacket.subpacket_type().number(), subpacket.is_critical()))
        .collect();
    assert_eq!(
        hashed,
        [
            (2, true),
            (11, false),
            (21, false),
            (22, false),
            (27, true),
            (30, false),
            (33, false),
            (39, false),
        ]
    );
    assert!(direct.unhashed_subpackets().next().is_none());
    assert_eq!(
        direct.material(),
        SignatureMaterial::Ed25519(
            hex(
                "4585b3b903b0127ec4fda2f023045a2ec76bcb4f9571a9651e14aee1137a1d66\
                 8442c88f951e33c4ffd33fb9a17d511eed758fc6d9cc50cb5fd793b2039d5804"
            )
            .try_into()
            .unwrap()
        )
    );

    assert_eq!(binding.signature_type(), SignatureType::SUBKEY_BINDING);
    assert_eq!(binding.hash_prefix(), [0x04, 0x01]);
    assert_eq!(
        binding.salt(),
        hex("a6e9186d9d5935fc8fe56314cdb527486a5a5120f9b762a235a729f039010a56")
    );
    let flags = binding.key_flags().unwrap();
    assert!(!flags.may_certify() && !flags.may_sign());
    assert_eq!(flags.as_bytes(), [0x0C]);
    assert_eq!(binding.issuer_fingerprints().collect::<Vec<_>>(), [primary]);
    assert!(binding.embedded_signatures().is_empty());
}

#[test]
fn subpacket_lengths_in_each_encoding() {
    // A creation time with its length in the five-octet form.
    let five = [&[0xFF, 0x00, 0x00, 0x00, 0x05][..], &created()[1..]].concat();
    let signature = parse(&v4(&five, &[])).unwrap();
    assert_eq!(signature.creation_time(), 0x0102_0304);
    // The edges of each form: one octet up to 191, two up to 16319, and five
    // beyond.
    for (length, header) in [(1, 1), (191, 1), (192, 2), (16319, 2), (16320, 5)] {
        let encoded = subpacket(26, &vec![b'u'; length - 1]);
        assert_eq!(encoded.len(), header + length, "{length}");
        let signature = parse(&v4(&[created(), encoded].concat(), &[])).unwrap();
        let policy = signature.hashed_subpackets().nth(1).unwrap();
        assert_eq!(policy.subpacket_type(), SubpacketType::POLICY_URI);
        assert_eq!(policy.body().len(), length - 1, "{length}");
    }
}

#[test]
fn typed_subpackets_read_the_last_in_the_hashed_area() {
    let issuer = [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE];
    let hashed_fingerprint = [&[0x04][..], &[0x44; 20]].concat();
    let unhashed_fingerprint = [&[0x04][..], &[0x55; 20]].concat();
    let hashed = [
        created(),
        subpacket(0x03, &[0, 0, 0, 10]),
        subpacket(0x83, &[0, 0, 0, 20]),
        subpacket(0x09, &[0, 0, 1, 0]),
        subpacket(0x09, &[0, 0, 0, 0]),
        subpacket(0x1B, &[0x03]),
        subpacket(0x9B, &[0x02, 0x00]),
        subpacket(0x19, &[0x01]),
        subpacket(0x1D, b"\x02lost"),
        subpacket(0x21, &hashed_fingerprint),
    ]
    .concat();
    let unhashed = [
        subpacket(0x03, &[0, 0, 0, 99]),
        subpacket(0x10, &issuer),
        subpacket(0x21, &unhashed_fingerprint),
    ]
    .concat();
    let signature = parse(&v4(&hashed, &unhashed)).unwrap();
    assert_eq!(signature.expiration_time(), Some(20));
    // The last key expiration is zero: the key does not expire.
    assert_eq!(signature.key_expiration_time(), None);
    let flags = signature.key_flags().unwrap();
    assert!(flags.may_sign() && !flags.may_certify());
    assert_eq!(flags.as_bytes(), [0x02, 0x00]);
    assert!(signature.is_primary_user_id());
    let reason = signature.revocation_reason().unwrap();
    assert_eq!(reason.code(), RevocationCode::KEY_COMPROMISED);
    assert_eq!(reason.message(), b"lost");
    // Issuers come from both areas, hashed first.
    assert_eq!(
        signature.issuer_key_ids().collect::<Vec<_>>(),
        [KeyId::from_bytes(issuer)]
    );
    assert_eq!(
        signature.issuer_fingerprints().collect::<Vec<_>>(),
        [Fingerprint::V4([0x44; 20]), Fingerprint::V4([0x55; 20])]
    );
    assert_eq!(signature.hashed_subpackets().count(), 10);
    assert_eq!(signature.unhashed_subpackets().count(), 3);

    // Subpackets only in the unhashed area are not read as the signature's.
    let unhashed = [
        subpacket(0x03, &[0, 0, 0, 10]),
        subpacket(0x09, &[0, 0, 0, 10]),
        subpacket(0x1B, &[0x03]),
        subpacket(0x19, &[0x01]),
        subpacket(0x1D, &[0x00]),
    ]
    .concat();
    let signature = parse(&v4(&created(), &unhashed)).unwrap();
    assert_eq!(signature.expiration_time(), None);
    assert_eq!(signature.key_expiration_time(), None);
    assert!(signature.key_flags().is_none());
    assert!(!signature.is_primary_user_id());
    assert!(signature.revocation_reason().is_none());

    // An absent or zero signature expiration, and an empty Key Flags.
    let signature = parse(&v4(
        &[created(), subpacket(0x03, &[0; 4]), subpacket(0x1B, &[])].concat(),
        &[],
    ))
    .unwrap();
    assert_eq!(signature.expiration_time(), None);
    let flags = signature.key_flags().unwrap();
    assert!(!flags.may_sign() && !flags.may_certify());
}

/// A well-formed body for a subpacket of type `number`.
fn well_formed(number: u8) -> Vec<u8> {
    match number {
        2 | 3 | 9 => vec![0, 0, 0, 1],
        5 => vec![1, 120],
        12 => [&[0x80, 0x01][..], &[0x33; 20]].concat(),
        16 => vec![0x22; 8],
        20 => [&[0x80, 0, 0, 0, 0, 1, 0, 1][..], b"nv"].concat(),
        25 => vec![0x01],
        29 => vec![0x00],
        31 => [&[0x01, 0x08][..], &[0x44; 32]].concat(),
        32 => v4(&created(), &[]),
        33 => [&[0x04][..], &[0x33; 20]].concat(),
        35 => [&[0x04][..], &[0x55; 20]].concat(),
        39 => vec![0x09, 0x02],
        _ => vec![0x00],
    }
}

/// A subpacket of a type irongall keeps without decoding is held to the
/// length RFC 9580 gives the type, where it gives one, in either area
/// (§5.2.5), and to nothing else. Read only to weigh what it restricts, the
/// signature reads regardless.
#[test]
fn undecoded_subpackets_are_held_to_their_length() {
    let notation = |name: &[u8], value: &[u8], said: (u16, u16)| {
        [
            &[0x80, 0, 0, 0][..],
            &said.0.to_be_bytes(),
            &said.1.to_be_bytes(),
            name,
            value,
        ]
        .concat()
    };
    // Each type with bodies of its length, and of others.
    type Bodies<'a> = &'a [&'a [u8]];
    let cases: [(u8, Bodies<'_>, Bodies<'_>); 9] = [
        (4, &[&[0x00], &[0x01], &[0x07]], &[&[], &[0x01, 0x00]]),
        (7, &[&[0x01]], &[&[], &[0x01, 0x01]]),
        (5, &[&[0x01, 0x78]], &[&[0x01], &[0x01, 0x78, 0x00]]),
        (
            12,
            &[&well_formed(12), &[&[0x00, 0x01][..], &[0x33; 20]].concat()],
            &[
                &well_formed(12)[..21],
                &[&well_formed(12)[..], &[0]].concat(),
            ],
        ),
        (
            20,
            // Lengths that add up, whatever the name holds.
            &[
                &notation(b"n", b"v", (1, 1)),
                &notation(&[0xFF], b"", (1, 0)),
            ],
            &[
                &notation(b"n", b"v", (1, 2)),
                &notation(b"n", b"v", (2, 1)),
                &notation(b"n", b"vv", (1, 1)),
                &notation(b"n", b"v", (0xFFFF, 0xFFFF)),
                &[0x80, 0, 0, 0, 0, 0, 0],
            ],
        ),
        (
            31,
            // A hash RFC 9580 does not assign is of any length.
            &[&well_formed(31), &[0x01, 100, 0x44]],
            &[
                &well_formed(31)[..33],
                &[&well_formed(31)[..], &[0x44]].concat(),
                &[0x01],
                &[0x01, 0x02],
                &[0x01, 0x02, 0x44],
            ],
        ),
        (
            35,
            // A key version RFC 9580 does not define is of any length.
            &[
                &well_formed(35),
                &[&[0x06][..], &[0x55; 32]].concat(),
                &[0x05, 0x55],
            ],
            &[
                &[],
                &well_formed(35)[..20],
                &[&well_formed(35)[..], &[0x55]].concat(),
                &[&[0x06][..], &[0x55; 20]].concat(),
            ],
        ),
        (
            39,
            &[&[], &[0x09, 0x02, 0x07, 0x01]],
            &[&[0x09], &[0x09, 0x02, 0x07]],
        ),
        // A type of no fixed length is of any.
        (11, &[&[], &[0x09], &[0x09, 0x08, 0x07]], &[]),
    ];
    let mut checked = 0;
    for (number, good, bad) in cases {
        for body in good {
            let hashed = [created(), subpacket(number, body)].concat();
            assert!(parse(&v4(&hashed, &[])).is_ok(), "{number} {body:02X?}");
            assert!(parse(&v4(&created(), &subpacket(number, body))).is_ok());
            checked += 1;
        }
        for body in bad {
            let hashed = [created(), subpacket(number, body)].concat();
            for (signature, at) in [
                (v4(&hashed, &[]), 18),
                (v4(&created(), &subpacket(number, body)), 20),
            ] {
                assert_eq!(
                    failure(&signature),
                    (PacketErrorKind::InvalidSubpacket, at),
                    "{number} {body:02X?}"
                );
                assert!(parse_with(&signature, Signature::from_packet_unhonored).is_ok());
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 43);
}

#[test]
fn critical_subpackets_must_be_honored() {
    // The types implemented, and those whose meaning cannot change whether a
    // signature verifies.
    let honored = [
        2, 3, 9, 16, 25, 27, 29, 32, 33, 11, 21, 22, 23, 24, 26, 28, 30, 39,
    ];
    let mut checked = 0;
    for number in 0..=0x7F {
        let critical = subpacket(0x80 | number, &well_formed(number));
        let result = parse(&v4(&[created(), critical.clone()].concat(), &[]));
        if honored.contains(&number) {
            let signature = result.unwrap();
            assert!(
                signature.hashed_subpackets().nth(1).unwrap().is_critical(),
                "{number}"
            );
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                (error.kind(), error.offset()),
                (PacketErrorKind::CriticalSubpacket, 18),
                "{number}"
            );
        }
        // The bit carries no weight in the unhashed area.
        assert!(parse(&v4(&created(), &critical)).is_ok(), "{number}");
        checked += 1;
    }
    assert_eq!(checked, 128);
}

#[test]
fn malformed_signatures_are_refused() {
    let fingerprint_v6 = [&[0x06][..], &[0x66; 32]].concat();
    for (body, kind, offset) in [
        // Version 3 and those RFC 9580 leaves unspecified.
        (
            body(3, 0, 1, 8, &[], &[], &[]),
            PacketErrorKind::UnsupportedVersion,
            6,
        ),
        (
            body(5, 0, 27, 8, &created(), &[], &[0x11; 64]),
            PacketErrorKind::UnsupportedVersion,
            6,
        ),
        ([0x04].to_vec(), PacketErrorKind::TruncatedBody, 7),
        // An area longer than what follows.
        (
            [&[0x04, 0x00, 27, 8, 0x00, 0x10][..], &created()].concat(),
            PacketErrorKind::TruncatedBody,
            12,
        ),
        // A subpacket of length zero, and one longer than its area.
        (v4(&[0x00], &[]), PacketErrorKind::InvalidSubpacket, 12),
        (
            v4(&[0x06, 0x02, 0x01, 0x02, 0x03, 0x04], &[]),
            PacketErrorKind::TruncatedBody,
            13,
        ),
        (v4(&[0xC0], &[]), PacketErrorKind::TruncatedBody, 13),
        // Decoded subpackets of the wrong length, in either area.
        (
            v4(&subpacket(0x02, &[1, 2, 3]), &[]),
            PacketErrorKind::InvalidSubpacket,
            12,
        ),
        (
            v4(&subpacket(0x02, &[1, 2, 3, 4, 5]), &[]),
            PacketErrorKind::InvalidSubpacket,
            12,
        ),
        (
            v4(&created(), &subpacket(0x10, &[0x22; 7])),
            PacketErrorKind::InvalidSubpacket,
            20,
        ),
        (
            v4(&created(), &subpacket(0x19, &[0x01, 0x00])),
            PacketErrorKind::InvalidSubpacket,
            20,
        ),
        // A Boolean that is neither 0 nor 1.
        (
            v4(&created(), &subpacket(0x19, &[0x02])),
            PacketErrorKind::InvalidSubpacket,
            20,
        ),
        (
            v4(&created(), &subpacket(0x1D, &[])),
            PacketErrorKind::InvalidSubpacket,
            20,
        ),
        (
            v4(&created(), &subpacket(0x21, &[0x04; 20])),
            PacketErrorKind::InvalidSubpacket,
            20,
        ),
        // An issuer fingerprint of another version than its signature's.
        (
            v4(&created(), &subpacket(0x21, &fingerprint_v6)),
            PacketErrorKind::InvalidSubpacket,
            20,
        ),
        // No creation time, or one only in the unhashed area.
        (v4(&[], &[]), PacketErrorKind::MissingCreationTime, 10),
        (
            v4(&subpacket(0x03, &[0; 4]), &created()),
            PacketErrorKind::MissingCreationTime,
            10,
        ),
        // A truncated hash prefix, and material of the wrong length.
        (
            v4(&created(), &[])[..14].to_vec(),
            PacketErrorKind::TruncatedBody,
            20,
        ),
        (
            body(4, 0, 27, 8, &created(), &[], &[0x11; 63]),
            PacketErrorKind::TruncatedBody,
            22,
        ),
        (
            body(4, 0, 27, 8, &created(), &[], &[0x11; 65]),
            PacketErrorKind::TrailingData,
            86,
        ),
        (
            body(4, 0, 1, 8, &created(), &[], &[0x00, 0x01, 0x01, 0x00]),
            PacketErrorKind::TrailingData,
            25,
        ),
    ] {
        assert_eq!(failure(&body), (kind, offset), "{body:02X?}");
    }

    // Another type of packet.
    let input = [0xC6, 0x00];
    let packet = packets(&input).next().unwrap().unwrap();
    let error = Signature::from_packet(&packet).unwrap_err();
    assert_eq!(
        (error.kind(), error.offset()),
        (PacketErrorKind::UnexpectedType, 0)
    );
}

#[test]
fn version_6_salts() {
    for (hash, algorithm, size) in [
        (8, HashAlgorithm::SHA256, 16),
        (9, HashAlgorithm::SHA384, 24),
        (10, HashAlgorithm::SHA512, 32),
        (11, HashAlgorithm::SHA224, 16),
        (12, HashAlgorithm::SHA3_256, 16),
        (14, HashAlgorithm::SHA3_512, 32),
    ] {
        let signature = parse(&body(6, 0, 27, hash, &created(), &[], &[0x11; 64])).unwrap();
        assert_eq!(signature.hash_algorithm(), algorithm);
        assert_eq!(signature.salt(), vec![0x5A; size]);
        assert_eq!(signature.hash_prefix(), [0xAB, 0xCD]);
    }
    let signature = parse(&v6(&created(), &[])).unwrap();
    assert_eq!(signature.version(), Version::V6);
    assert_eq!(signature.material(), SignatureMaterial::Ed25519([0x11; 64]));
    assert_eq!(signature.hashed_fields(), &v6(&created(), &[])[..14]);

    // A salt of the wrong size, and hash algorithms version 6 cannot use.
    let mut short = v6(&created(), &[]);
    short[20] = 15;
    short.remove(21);
    assert_eq!(failure(&short), (PacketErrorKind::SaltSize, 26));
    for hash in [1, 2, 3, 100] {
        let body = body(6, 0, 27, hash, &created(), &[], &[0x11; 64]);
        assert_eq!(failure(&body), (PacketErrorKind::SaltSize, 26), "{hash}");
    }
    let truncated = &v6(&created(), &[])[..30];
    assert_eq!(failure(truncated), (PacketErrorKind::TruncatedBody, 27));
}

#[test]
fn material() {
    let read = |version: u8, algorithm: u8, material: &[u8]| {
        parse(&body(version, 0, algorithm, 8, &created(), &[], material))
    };
    // An RSA value: version 4 tolerates an overstated length and drops the
    // leading zeros, version 6 does not.
    let overstated = [0x00, 0x10, 0x00, 0xC5];
    for algorithm in [1, 2, 3] {
        assert_eq!(
            read(4, algorithm, &overstated).unwrap().material(),
            SignatureMaterial::Rsa(&[0xC5])
        );
    }
    assert_eq!(
        read(6, 1, &overstated).unwrap_err().kind(),
        PacketErrorKind::InvalidMpi
    );
    assert_eq!(
        read(6, 1, &[0x00, 0x08, 0xC5]).unwrap().material(),
        SignatureMaterial::Rsa(&[0xC5])
    );

    // EdDSALegacy's R and S, each restored to 32 octets: here R's native
    // encoding begins with two zero octets, which its integer encoding drops.
    let r = [&[0x7F][..], &[0x22; 29]].concat();
    let legacy = [&[0x00, 0xEF][..], &r, &[0x00, 0xFE], &[0x33; 32]].concat();
    let mut native = [0; 64];
    native[2] = 0x7F;
    native[3..32].fill(0x22);
    native[32..].fill(0x33);
    assert_eq!(
        read(4, 22, &legacy).unwrap().material(),
        SignatureMaterial::Ed25519(native)
    );
    // Longer than 32 octets, as on Ed448Legacy: another curve.
    let ed448 = [&[0x01, 0xC7][..], &[0x44; 57], &[0x01, 0xC7], &[0x44; 57]].concat();
    assert_eq!(
        read(4, 22, &ed448).unwrap().material(),
        SignatureMaterial::Opaque
    );
    // RFC 9580 §5.2.3.3.1 forbids EdDSALegacy in version 6.
    assert_eq!(
        read(6, 22, &legacy).unwrap().material(),
        SignatureMaterial::Opaque
    );

    // Algorithms irongall does not verify with, known or not.
    for algorithm in [17, 19, 28, 100] {
        assert_eq!(
            read(4, algorithm, &[0x00, 0x01, 0x01, 0x00, 0x01, 0x01])
                .unwrap()
                .material(),
            SignatureMaterial::Opaque
        );
    }
    assert_eq!(
        read(4, 17, &[]).unwrap().material(),
        SignatureMaterial::Opaque
    );
}

/// How a part of a signature that no signature covers is written refuses
/// the signature where it is read to be honored, and not where it is read
/// only to weigh what it restricts, which reads the same values: octets
/// after the material, which the packet's length counts, and an integer
/// whose length leaves a bit its value sets uncounted, in either version, or
/// is not exact, in version 6.
#[test]
fn how_an_uncovered_part_is_written_refuses_only_an_honored_reading() {
    let both = |body: &[u8]| {
        (
            parse(body),
            parse_with(body, Signature::from_packet_unhonored).unwrap(),
        )
    };
    // Octets after the material, counted in the signature's length.
    for (version, at) in [(4, 86), (6, 107)] {
        for appended in [&[0x00][..], &[0x11; 64]] {
            let material = [&[0x11; 64][..], appended].concat();
            let body = body(version, 0, 27, 8, &created(), &[], &material);
            let (honored, unhonored) = both(&body);
            let error = honored.unwrap_err();
            assert_eq!(
                (error.kind(), error.offset()),
                (PacketErrorKind::TrailingData, at)
            );
            assert_eq!(unhonored.material(), SignatureMaterial::Ed25519([0x11; 64]));
            assert_eq!(unhonored.length(), body.len());
        }
    }
    // An RSA value of eight bits, 0xC5, written with a length that leaves its
    // top bit uncounted, with one that counts a leading zero octet, and
    // with one a bit longer than the value.
    for (version, material, refused) in [
        (4, &[0x00, 0x07, 0xC5][..], true),
        (6, &[0x00, 0x07, 0xC5], true),
        (4, &[0x00, 0x10, 0x00, 0xC5], false),
        (6, &[0x00, 0x10, 0x00, 0xC5], true),
        (4, &[0x00, 0x09, 0x00, 0xC5], false),
        (6, &[0x00, 0x09, 0x00, 0xC5], true),
    ] {
        let (honored, unhonored) = both(&body(version, 0, 1, 8, &created(), &[], material));
        assert_eq!(
            honored.map_err(|error| error.kind()).err(),
            refused.then_some(PacketErrorKind::InvalidMpi),
            "{version} {material:02X?}"
        );
        assert_eq!(unhonored.material(), SignatureMaterial::Rsa(&[0xC5]));
    }
    // EdDSALegacy's R, of 32 octets, with its top bit uncounted.
    let r = [&[0xC0][..], &[0x22; 31]].concat();
    let legacy = [&[0x00, 0xFF][..], &r, &[0x00, 0xFE], &[0x33; 32]].concat();
    let (honored, unhonored) = both(&body(4, 0, 22, 8, &created(), &[], &legacy));
    assert_eq!(honored.unwrap_err().kind(), PacketErrorKind::InvalidMpi);
    let mut native = [0x33; 64];
    native[..32].copy_from_slice(&r);
    assert_eq!(unhonored.material(), SignatureMaterial::Ed25519(native));
}

#[test]
fn embedded_signatures_are_read_one_level_deep() {
    let back = body(4, 0x19, 27, 8, &created(), &[], &[0x22; 64]);
    for (hashed, unhashed) in [
        ([created(), subpacket(32, &back)].concat(), Vec::new()),
        (created(), subpacket(32, &back)),
        (created(), subpacket(0x80 | 32, &back)),
    ] {
        let binding = parse(&body(4, 0x18, 27, 8, &hashed, &unhashed, &[0x11; 64])).unwrap();
        let [embedded] = binding.embedded_signatures() else {
            panic!("one embedded signature");
        };
        assert_eq!(
            embedded.signature_type(),
            SignatureType::PRIMARY_KEY_BINDING
        );
        assert_eq!(embedded.material(), SignatureMaterial::Ed25519([0x22; 64]));
        let raw = binding
            .hashed_subpackets()
            .chain(binding.unhashed_subpackets())
            .find(|subpacket| subpacket.subpacket_type() == SubpacketType::EMBEDDED_SIGNATURE)
            .unwrap();
        assert_eq!(raw.body(), back);
    }

    // An embedded signature's own embedded signatures are kept unread, so
    // even an unreadable one is no failure, unless it is marked critical in
    // the hashed area.
    let nested = body(
        4,
        0x19,
        27,
        8,
        &created(),
        &subpacket(32, &[0xFF; 3]),
        &[0x22; 64],
    );
    let binding = parse(&v4(&created(), &subpacket(32, &nested))).unwrap();
    let [embedded] = binding.embedded_signatures() else {
        panic!("one embedded signature");
    };
    assert!(embedded.embedded_signatures().is_empty());
    assert_eq!(
        embedded.unhashed_subpackets().next().unwrap().body(),
        [0xFF; 3]
    );
    let nested = body(
        4,
        0x19,
        27,
        8,
        &[created(), subpacket(0x80 | 32, &back)].concat(),
        &[],
        &[0x22; 64],
    );
    // The outer signature's unhashed area holds the subpacket at 20; the
    // embedded body begins at 22, and its second hashed subpacket at 34.
    assert_eq!(
        failure(&v4(&created(), &subpacket(32, &nested))),
        (PacketErrorKind::CriticalSubpacket, 34)
    );

    // An embedded signature that fails to read fails its signature, at the
    // offset inside it.
    let unread = body(4, 0x19, 27, 8, &[], &[], &[0x22; 64]);
    assert_eq!(
        failure(&v4(&created(), &subpacket(32, &unread))),
        (PacketErrorKind::MissingCreationTime, 26)
    );
}

#[test]
fn formatting() {
    assert_eq!(
        SignatureType::SUBKEY_BINDING.to_string(),
        "Subkey Binding Signature"
    );
    assert_eq!(SignatureType(0x03).to_string(), "signature type 3");
    assert_eq!(
        format!("{:?}", SignatureType::BINARY),
        "SignatureType(0: Binary Signature)"
    );
    assert_eq!(SubpacketType::KEY_FLAGS.to_string(), "Key Flags");
    assert_eq!(SubpacketType(100).to_string(), "subpacket type 100");
    assert_eq!(HashAlgorithm::SHA256.to_string(), "SHA2-256");
    assert_eq!(
        format!("{:?}", HashAlgorithm(100)),
        "HashAlgorithm(100: hash algorithm 100)"
    );
    assert_eq!(
        RevocationCode::KEY_RETIRED.to_string(),
        "Key is retired and no longer used"
    );
    assert_eq!(RevocationCode(4).to_string(), "revocation code 4");
    let error = parse(&v4(&[], &[])).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Signature packet, offset 10: a signature without a creation time in its hashed subpackets"
    );
}

/// Two signatures are equal when their bodies are, octet for octet: the same
/// material written with two bit counts makes two signatures.
#[test]
fn signatures_are_equal_when_their_bodies_are() {
    let read = |material: &[u8]| parse(&body(4, 0, 1, 8, &created(), &[], material)).unwrap();
    let nine = read(&[0x00, 0x09, 0x00, 0xC5]);
    let sixteen = read(&[0x00, 0x10, 0x00, 0xC5]);
    assert_eq!(nine.material(), sixteen.material());
    assert_eq!(nine.length(), sixteen.length());
    assert_ne!(nine, sixteen);
    assert_eq!(nine, read(&[0x00, 0x09, 0x00, 0xC5]));
}

/// A signature's `Debug` form shows what the accessors read from its body,
/// each area's subpackets and the material among them, rather than where it
/// keeps them.
#[test]
fn debug_shows_what_the_accessors_read() {
    let issuer = subpacket(16, &[0x77; 8]);
    let signature = parse(&v6(&created(), &issuer)).unwrap();
    let shown = format!("{signature:?}");
    let unhashed = format!("{:?}", signature.unhashed_subpackets());
    let only = signature.unhashed_subpackets().next().unwrap();
    assert_eq!(unhashed, format!("[{only:?}]"));
    for field in [
        format!("unhashed_subpackets: {unhashed}"),
        format!("hashed_subpackets: {:?}", signature.hashed_subpackets()),
        format!("salt: {:?}", signature.salt()),
        format!("material: {:?}", signature.material()),
        "honored: true".to_string(),
    ] {
        assert!(shown.contains(&field), "{field} in {shown}");
    }
    for kept in ["hashed_end", "material_start", "unhashed_read"] {
        assert!(!shown.contains(kept), "{kept} in {shown}");
    }
}
