//! Tests for certificate assembly, over real packets rearranged.

use alloc::string::ToString as _;
use alloc::vec::Vec;
use alloc::{format, vec};

use super::{Certificate, certificates, combine, merge_repeats};
use crate::armor;
use crate::key::PublicKey;
use crate::packet::{self, PacketError, PacketErrorKind, Tag, Version};
use crate::signature::{Signature, SignatureType, Subject};
use crate::test_support::rfc9580::A3_CERTIFICATE;
use crate::test_support::{forge, vector_bytes};

/// A packet: its type and its body.
type Part = (Tag, Vec<u8>);

/// The packets of `data`.
fn parts_of(data: &[u8]) -> Vec<Part> {
    packet::packets(data)
        .map(|packet| {
            let packet = packet.unwrap();
            (packet.tag(), packet.body().to_vec())
        })
        .collect()
}

/// The packets of a GnuPG certificate: the primary key, its user ID and the
/// certification, and its subkey and the binding.
fn gnupg(name: &str) -> [Part; 5] {
    parts_of(&vector_bytes(&format!("gnupg/{name}.pgp")))
        .try_into()
        .unwrap()
}

/// The packets of the RFC 9580 Appendix A.3 certificate: the primary key, its
/// direct-key signature, and its subkey and the binding.
fn a3() -> [Part; 4] {
    let data = armor::decode(A3_CERTIFICATE.as_bytes())
        .unwrap()
        .into_data();
    parts_of(&data).try_into().unwrap()
}

/// `parts` framed as packets in the OpenPGP format, one after another.
fn framed(parts: &[&Part]) -> Vec<u8> {
    let mut data = Vec::new();
    for (tag, body) in parts {
        data.push(0xC0 | tag.number());
        data.push(0xFF);
        data.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        data.extend_from_slice(body);
    }
    data
}

/// Where the packet at `index` begins in [`framed`]`(parts)`.
fn offset_of(parts: &[&Part], index: usize) -> usize {
    parts[..index].iter().map(|(_, body)| 6 + body.len()).sum()
}

/// Every certificate in `data`, or why it was refused.
fn read(data: &[u8]) -> Vec<Result<Certificate, PacketError>> {
    let mut read = certificates(data);
    let all: Vec<_> = read.by_ref().collect();
    assert!(read.next().is_none());
    all
}

/// The one certificate in `data`.
fn only(data: &[u8]) -> Certificate {
    let [certificate] = <[_; 1]>::try_from(read(data)).unwrap();
    certificate.unwrap()
}

fn failure(error: &PacketError) -> (PacketErrorKind, Option<Tag>, usize) {
    (error.kind(), error.tag(), error.offset())
}

fn types(signatures: &[Signature]) -> Vec<SignatureType> {
    signatures.iter().map(Signature::signature_type).collect()
}

#[test]
fn rfc_9580_certificate() {
    let [primary, direct, subkey, binding] = a3();
    let certificate = only(&framed(&[&primary, &direct, &subkey, &binding]));
    assert_eq!(certificate.primary().version(), Version::V6);
    assert_eq!(
        certificate.primary().fingerprint().to_string(),
        "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"
    );
    assert_eq!(
        types(certificate.primary_signatures()),
        [SignatureType::DIRECT_KEY]
    );
    assert!(certificate.user_ids().is_empty());
    let [subkey] = certificate.subkeys() else {
        panic!("one subkey");
    };
    assert_eq!(
        subkey.key().fingerprint().to_string(),
        "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"
    );
    assert_eq!(types(subkey.signatures()), [SignatureType::SUBKEY_BINDING]);
    assert!(certificate.skipped().is_empty());
}

#[test]
fn gnupg_certificates() {
    for name in [
        "rsa",
        "dsa",
        "ed25519",
        "nistp256",
        "brainpoolp256r1",
        "ed25519-signing",
    ] {
        let data = vector_bytes(&format!("gnupg/{name}.pgp"));
        let certificate = only(&data);
        let [user_id] = certificate.user_ids() else {
            panic!("{name}: one user ID");
        };
        let expected = format!("irongall test, {name} <{name}@example.invalid>");
        assert_eq!(user_id.value(), expected.as_bytes());
        assert_eq!(
            types(user_id.signatures()),
            [SignatureType::POSITIVE_CERTIFICATION],
            "{name}"
        );
        let [subkey] = certificate.subkeys() else {
            panic!("{name}: one subkey");
        };
        assert_eq!(
            types(subkey.signatures()),
            [SignatureType::SUBKEY_BINDING],
            "{name}"
        );
        assert!(certificate.primary_signatures().is_empty(), "{name}");
        assert!(certificate.skipped().is_empty(), "{name}");
    }

    // GnuPG's Ed448 keys are version 5, so the certificate's primary key does
    // not read.
    let [error] = <[_; 1]>::try_from(read(&vector_bytes("gnupg/ed448.pgp"))).unwrap();
    assert_eq!(
        failure(&error.unwrap_err()),
        (
            PacketErrorKind::UnsupportedVersion,
            Some(Tag::PUBLIC_KEY),
            2
        )
    );
}

/// The GnuPG certificates concatenated into one keyring: the one that cannot
/// be read is refused, and the rest are read around it.
#[test]
fn a_keyring_of_certificates() {
    let names = [
        "rsa",
        "dsa",
        "ed448",
        "ed25519",
        "nistp256",
        "brainpoolp256r1",
        "ed25519-signing",
    ];
    let mut keyring = Vec::new();
    let mut ed448_at = 0;
    for name in names {
        if name == "ed448" {
            ed448_at = keyring.len();
        }
        keyring.extend(vector_bytes(&format!("gnupg/{name}.pgp")));
    }
    let read = read(&keyring);
    assert_eq!(read.len(), names.len());
    for (name, result) in names.iter().zip(&read) {
        match result {
            Ok(certificate) => {
                let alone = only(&vector_bytes(&format!("gnupg/{name}.pgp")));
                assert_eq!(certificate, &alone, "{name}");
            }
            Err(error) => {
                assert_eq!(*name, "ed448");
                assert_eq!(error.kind(), PacketErrorKind::UnsupportedVersion);
                // The version octet, after the packet's two-octet header.
                assert_eq!(error.offset(), ed448_at + 2);
            }
        }
    }
}

/// Trust, Marker, and Padding packets, and packets of an unknown type that is
/// not critical, are passed over wherever they are.
#[test]
fn packets_passed_over_anywhere() {
    let [primary, user_id, certification, subkey, binding] = gnupg("rsa");
    let plain = only(&framed(&[
        &primary,
        &user_id,
        &certification,
        &subkey,
        &binding,
    ]));
    let marker = (Tag::MARKER, b"PGP".to_vec());
    let trust = (Tag::TRUST, vec![0x00, 0x00]);
    let padding = (Tag::PADDING, vec![0x5A; 40]);
    let unknown = (Tag(60), vec![0x01, 0x02, 0x03]);
    for filler in [&marker, &trust, &padding, &unknown] {
        let mut parts = vec![filler];
        for part in [&primary, &user_id, &certification, &subkey, &binding] {
            parts.extend([part, filler]);
        }
        assert_eq!(only(&framed(&parts)), plain, "{:?}", filler.0);
    }
    // Only filler: no certificate at all.
    assert!(read(&framed(&[&marker, &padding])).is_empty());
    assert!(read(&[]).is_empty());
}

/// The signatures after a User Attribute packet are over it, and are passed
/// over with it.
#[test]
fn user_attributes_take_their_signatures() {
    let [primary, user_id, certification, subkey, binding] = gnupg("rsa");
    let attribute = (Tag::USER_ATTRIBUTE, vec![0x05, 0x01, 0x00]);
    let certificate = only(&framed(&[
        &primary,
        &user_id,
        &attribute,
        &certification,
        &subkey,
        &binding,
    ]));
    assert!(certificate.user_ids()[0].signatures().is_empty());
    assert_eq!(certificate.subkeys()[0].signatures().len(), 1);
    assert!(certificate.skipped().is_empty());
}

/// A User ID or Public Subkey packet that repeats one the certificate holds
/// continues it: the signatures after it are placed with the first, and the
/// certificate holds each once, in the order they first appear. Certificates
/// of the same primary key combine as their packets read together would.
#[test]
fn repeated_parts_are_held_once() {
    let [primary, user_id, certification, subkey, binding] = gnupg("rsa");
    let other = (Tag::USER_ID, b"other".to_vec());
    let certificate = only(&framed(&[
        &primary,
        &user_id,
        &certification,
        &subkey,
        &binding,
        &other,
        &user_id,
        &certification,
        &subkey,
        &binding,
        &other,
    ]));
    let values: Vec<_> = certificate
        .user_ids()
        .iter()
        .map(|user_id| user_id.value())
        .collect();
    assert_eq!(values, [&user_id.1[..], b"other"]);
    assert_eq!(
        types(certificate.user_ids()[0].signatures()),
        [SignatureType::POSITIVE_CERTIFICATION; 2]
    );
    assert!(certificate.user_ids()[1].signatures().is_empty());
    let [held] = certificate.subkeys() else {
        panic!("one subkey");
    };
    assert_eq!(types(held.signatures()), [SignatureType::SUBKEY_BINDING; 2]);
    assert!(certificate.skipped().is_empty());

    let first = only(&framed(&[&primary, &user_id, &certification]));
    let second = only(&framed(&[
        &primary,
        &other,
        &subkey,
        &binding,
        &user_id,
        &certification,
    ]));
    let together = only(&framed(&[
        &primary,
        &user_id,
        &certification,
        &other,
        &subkey,
        &binding,
        &user_id,
        &certification,
    ]));
    assert_eq!(
        &*combine([first.clone(), second.clone()]),
        core::slice::from_ref(&together)
    );
    // Those of another primary key are kept apart, in order.
    let [unrelated, ..] = a3();
    let unrelated = only(&framed(&[&unrelated]));
    assert_eq!(
        &*combine([first, unrelated.clone(), second]),
        [together, unrelated]
    );
}

/// Items that repeat one another are merged into the first of them to
/// appear, in the order they appear, and the items keep the order in which
/// they first appear, however the repeats interleave.
#[test]
fn repeats_merge_into_the_first_in_order() {
    let mut items = vec![
        (3, vec!['a']),
        (1, vec!['b']),
        (3, vec!['c']),
        (2, vec!['d']),
        (1, vec!['e']),
        (3, vec!['f']),
    ];
    merge_repeats(
        &mut items,
        |(key, _), (other, _)| key.cmp(other),
        |items, same| {
            let merged: Vec<char> = same
                .iter()
                .flat_map(|&index| core::mem::take(&mut items[index].1))
                .collect();
            items[same[0]].1 = merged;
        },
    );
    assert_eq!(
        items,
        [
            (3, vec!['a', 'c', 'f']),
            (1, vec!['b', 'e']),
            (2, vec!['d'])
        ]
    );
    // Nothing to merge.
    let mut one = vec![(1, vec!['a'])];
    merge_repeats(
        &mut one,
        |(key, _), (other, _)| key.cmp(other),
        |_, _| panic!("nothing repeats"),
    );
    assert_eq!(one, [(1, vec!['a'])]);
}

/// A signature of a type that does not belong where it is is passed over,
/// except a direct-key signature or a key revocation, which is over the
/// primary key wherever it is.
#[test]
fn signatures_are_placed_by_type() {
    let [primary, user_id, certification, subkey, binding] = gnupg("rsa");
    let misplaced = |parts: &[&Part], index: usize| {
        let certificate = only(&framed(parts));
        let [skipped] = certificate.skipped() else {
            panic!("one signature passed over: {:?}", certificate.skipped());
        };
        assert_eq!(
            failure(skipped),
            (
                PacketErrorKind::MisplacedSignature,
                Some(Tag::SIGNATURE),
                offset_of(parts, index)
            )
        );
        certificate
    };
    // A certification before any user ID.
    let certificate = misplaced(&[&primary, &certification, &user_id, &subkey, &binding], 1);
    assert!(certificate.user_ids()[0].signatures().is_empty());
    // A binding after a user ID.
    let certificate = misplaced(&[&primary, &user_id, &certification, &binding, &subkey], 3);
    assert!(certificate.subkeys()[0].signatures().is_empty());
    // A certification after a subkey.
    misplaced(&[&primary, &user_id, &subkey, &binding, &certification], 4);

    // A direct-key signature, and the same signature as a key revocation,
    // after a subkey's binding.
    let [primary, direct, subkey, binding] = a3();
    let retyped = |signature_type: SignatureType| {
        let mut retyped = direct.clone();
        retyped.1[1] = signature_type.number();
        retyped
    };
    let revocation = retyped(SignatureType::KEY_REVOCATION);
    let certificate = only(&framed(&[
        &primary,
        &subkey,
        &binding,
        &direct,
        &revocation,
    ]));
    assert_eq!(
        types(certificate.primary_signatures()),
        [SignatureType::DIRECT_KEY, SignatureType::KEY_REVOCATION]
    );
    assert_eq!(certificate.subkeys()[0].signatures().len(), 1);
    assert!(certificate.skipped().is_empty());
    let key = certificate.primary();
    assert_eq!(
        certificate.primary_signatures()[0].verify(key, Subject::Key(key)),
        Ok(())
    );

    // A certification revocation is over the primary key, revoking a
    // direct-key signature, wherever it is but after a user ID, where it is
    // placed with the user ID.
    let certification_revocation = retyped(SignatureType::CERTIFICATION_REVOCATION);
    let user_id = (Tag::USER_ID, b"archive".to_vec());
    let attribute = (Tag::USER_ATTRIBUTE, vec![0x05, 0x01, 0x00]);
    for parts in [
        &[&primary, &certification_revocation, &user_id][..],
        &[
            &primary,
            &user_id,
            &subkey,
            &binding,
            &certification_revocation,
        ],
        &[&primary, &user_id, &attribute, &certification_revocation],
    ] {
        let certificate = only(&framed(parts));
        assert_eq!(
            types(certificate.primary_signatures()),
            [SignatureType::CERTIFICATION_REVOCATION]
        );
        assert!(certificate.user_ids()[0].signatures().is_empty());
        assert!(certificate.skipped().is_empty());
    }
    let certificate = only(&framed(&[&primary, &user_id, &certification_revocation]));
    assert!(certificate.primary_signatures().is_empty());
    assert_eq!(
        types(certificate.user_ids()[0].signatures()),
        [SignatureType::CERTIFICATION_REVOCATION]
    );
}

/// A signature that does not read is passed over, with the reason kept,
/// unless it follows something passed over.
#[test]
fn unreadable_signatures() {
    let [primary, user_id, certification, subkey, binding] = gnupg("rsa");
    let critical = parts_of(&vector_bytes("gnupg/critical-notation.sig"))
        .pop()
        .unwrap();
    let mut version_3 = certification.clone();
    version_3.1[0] = 3;
    let attribute = (Tag::USER_ATTRIBUTE, vec![0x05, 0x01, 0x00]);
    for (unreadable, kind) in [
        (&critical, PacketErrorKind::CriticalSubpacket),
        (&version_3, PacketErrorKind::UnsupportedVersion),
    ] {
        let parts = [
            &primary,
            &user_id,
            unreadable,
            &certification,
            &subkey,
            &binding,
        ];
        let certificate = only(&framed(&parts));
        assert_eq!(certificate.user_ids()[0].signatures().len(), 1);
        let [skipped] = certificate.skipped() else {
            panic!("one signature passed over");
        };
        assert_eq!(skipped.kind(), kind);
        assert_eq!(skipped.tag(), Some(Tag::SIGNATURE));
        assert!(skipped.offset() > offset_of(&parts, 2));
        assert!(skipped.offset() < offset_of(&parts, 3));

        let certificate = only(&framed(&[
            &primary, &attribute, unreadable, &subkey, &binding,
        ]));
        assert!(certificate.skipped().is_empty());
    }
}

/// A signature refused only for what irongall cannot honor, a critical
/// subpacket it does not implement or damage in its unhashed area, is passed
/// over, and kept apart where its type and place put it, for judging the
/// certificate; one refused for anything else is not kept.
#[test]
fn unhonored_signatures_are_kept_apart() {
    let [primary, user_id, certification, subkey, binding] = gnupg("rsa");
    let critical = parts_of(&vector_bytes("gnupg/critical-notation.sig"))
        .pop()
        .unwrap();
    let retyped = |signature_type: u8| {
        let mut part = critical.clone();
        part.1[1] = signature_type;
        part
    };
    let (certifying, revoking, binding_type) = (retyped(0x13), retyped(0x20), retyped(0x18));
    let certificate = only(&framed(&[
        &primary,
        &user_id,
        &certification,
        &certifying,
        &revoking,
        &subkey,
        &binding,
        &binding_type,
    ]));
    let kinds: Vec<_> = certificate
        .skipped()
        .iter()
        .map(PacketError::kind)
        .collect();
    assert_eq!(kinds, [PacketErrorKind::CriticalSubpacket; 3]);
    assert!(certificate.primary_signatures().is_empty());
    assert_eq!(
        types(certificate.unhonored_primary_signatures()),
        [SignatureType::KEY_REVOCATION]
    );
    let certified = &certificate.user_ids()[0];
    assert_eq!(
        types(certified.signatures()),
        [SignatureType::POSITIVE_CERTIFICATION]
    );
    assert_eq!(
        types(certified.unhonored_signatures()),
        [SignatureType::POSITIVE_CERTIFICATION]
    );
    let subkey_part = &certificate.subkeys()[0];
    assert_eq!(
        types(subkey_part.signatures()),
        [SignatureType::SUBKEY_BINDING]
    );
    assert_eq!(
        types(subkey_part.unhonored_signatures()),
        [SignatureType::SUBKEY_BINDING]
    );

    // Misplaced, it is passed over once, for its first reason, and not kept;
    // after a user attribute, it goes with the attribute.
    let attribute = (Tag::USER_ATTRIBUTE, vec![0x05, 0x01, 0x00]);
    let certificate = only(&framed(&[&primary, &user_id, &binding_type]));
    let kinds: Vec<_> = certificate
        .skipped()
        .iter()
        .map(PacketError::kind)
        .collect();
    assert_eq!(kinds, [PacketErrorKind::CriticalSubpacket]);
    assert!(certificate.user_ids()[0].unhonored_signatures().is_empty());
    let certificate = only(&framed(&[&primary, &attribute, &certifying]));
    assert!(certificate.skipped().is_empty());
    assert!(certificate.unhonored_primary_signatures().is_empty());
    // A key revocation is over the primary key wherever it is, honored or
    // not: after a user attribute too, it is kept and its refusal recorded.
    let certificate = only(&framed(&[&primary, &attribute, &revoking]));
    let kinds: Vec<_> = certificate
        .skipped()
        .iter()
        .map(PacketError::kind)
        .collect();
    assert_eq!(kinds, [PacketErrorKind::CriticalSubpacket]);
    assert_eq!(
        types(certificate.unhonored_primary_signatures()),
        [SignatureType::KEY_REVOCATION]
    );

    // Damage in the unhashed area, which the signature does not cover: a
    // Signature Expiration Time of one octet, or a subpacket that runs past
    // the area's end.
    for (damage, kind) in [
        (&[0x02, 0x03, 0x00][..], PacketErrorKind::InvalidSubpacket),
        (&[0x05, 0x10], PacketErrorKind::TruncatedBody),
    ] {
        let damaged =
            forge::with_unhashed(&framed(&[&certification]), |area| [area, damage].concat());
        let [damaged] = <[Part; 1]>::try_from(parts_of(&damaged)).unwrap();
        let certificate = only(&framed(&[&primary, &user_id, &damaged]));
        let kinds: Vec<_> = certificate
            .skipped()
            .iter()
            .map(PacketError::kind)
            .collect();
        assert_eq!(kinds, [kind], "{damage:?}");
        let user_id = &certificate.user_ids()[0];
        assert!(user_id.signatures().is_empty());
        assert_eq!(
            types(user_id.unhonored_signatures()),
            [SignatureType::POSITIVE_CERTIFICATION]
        );
    }

    // A signature that does not read for another reason is not kept.
    let mut version_3 = certifying.clone();
    version_3.1[0] = 3;
    let certificate = only(&framed(&[&primary, &user_id, &version_3]));
    assert!(certificate.user_ids()[0].unhonored_signatures().is_empty());
}

/// A user ID longer than 2048 octets is passed over with its signatures,
/// and the reason kept; one of 2048 octets is read.
#[test]
fn long_user_ids_are_passed_over() {
    let [primary, user_id, certification, subkey, binding] = gnupg("rsa");
    for length in [2048, 2049] {
        let long = (Tag::USER_ID, vec![b'a'; length]);
        let parts = [
            &primary,
            &long,
            &certification,
            &user_id,
            &certification,
            &subkey,
            &binding,
        ];
        let certificate = only(&framed(&parts));
        let user_ids: Vec<_> = certificate
            .user_ids()
            .iter()
            .map(|user_id| (user_id.value().len(), user_id.signatures().len()))
            .collect();
        if length == 2048 {
            assert_eq!(user_ids, [(2048, 1), (user_id.1.len(), 1)]);
            assert!(certificate.skipped().is_empty());
        } else {
            assert_eq!(user_ids, [(user_id.1.len(), 1)]);
            let [skipped] = certificate.skipped() else {
                panic!("one user ID passed over: {:?}", certificate.skipped());
            };
            assert_eq!(
                failure(skipped),
                (
                    PacketErrorKind::UserIdTooLong,
                    Some(Tag::USER_ID),
                    offset_of(&parts, 1)
                )
            );
        }
        assert_eq!(certificate.subkeys()[0].signatures().len(), 1);
    }
}

/// A subkey that does not read, or whose version is not the primary key's,
/// is passed over with its signatures.
#[test]
fn unusable_subkeys() {
    let [primary, user_id, certification, subkey, binding] = gnupg("rsa");
    let [_, _, v6_subkey, v6_binding] = a3();
    let [_, _, _, v5_subkey, v5_binding] = gnupg("ed448");
    for (other, other_binding, kind, offset) in [
        (&v6_subkey, &v6_binding, PacketErrorKind::SubkeyVersion, 0),
        (
            &v5_subkey,
            &v5_binding,
            PacketErrorKind::UnsupportedVersion,
            6,
        ),
    ] {
        let parts = [
            &primary,
            &user_id,
            &certification,
            other,
            other_binding,
            &subkey,
            &binding,
        ];
        let certificate = only(&framed(&parts));
        let [skipped] = certificate.skipped() else {
            panic!("one subkey passed over: {:?}", certificate.skipped());
        };
        assert_eq!(
            failure(skipped),
            (
                kind,
                Some(Tag::PUBLIC_SUBKEY),
                offset_of(&parts, 3) + offset
            )
        );
        let [kept] = certificate.subkeys() else {
            panic!("one subkey");
        };
        assert_eq!(kept.key(), &key(&subkey));
        assert_eq!(kept.signatures().len(), 1);
    }
}

fn key((tag, body): &Part) -> PublicKey {
    let data = framed(&[&(*tag, body.clone())]);
    PublicKey::from_packet(&packet::packets(&data).next().unwrap().unwrap()).unwrap()
}

/// `parts`, then the packets of `following`.
fn then<'a>(following: &'a [Part], parts: &[&'a Part]) -> Vec<&'a Part> {
    let mut all = parts.to_vec();
    all.extend(following);
    all
}

/// A certificate holding what no certificate holds, or not beginning with a
/// Public Key packet, is refused, and the keyring read on from the next
/// Public Key packet.
#[test]
fn refused_certificates() {
    let rsa = gnupg("rsa");
    let [primary, user_id, certification, subkey, binding] = &rsa;
    let ed25519 = gnupg("ed25519");
    let critical = (Tag(30), vec![0x00]);
    let literal = (Tag::LITERAL_DATA, b"b\x00\x00\x00\x00\x00".to_vec());
    let mut secret_subkey = subkey.clone();
    secret_subkey.0 = Tag::SECRET_SUBKEY;
    for (parts, index) in [
        // Not beginning with a Public Key packet.
        (then(&ed25519, &[certification, user_id]), 0),
        (then(&ed25519, &[subkey, binding]), 0),
        // A packet of an unknown critical type, a message, secret key
        // material.
        (
            then(&ed25519, &[primary, user_id, &critical, certification]),
            2,
        ),
        (then(&ed25519, &[primary, &literal]), 1),
        (
            then(&ed25519, &[primary, user_id, certification, &secret_subkey]),
            3,
        ),
    ] {
        let read = read(&framed(&parts));
        let [refused, following] = <[_; 2]>::try_from(read).unwrap();
        let error = refused.unwrap_err();
        assert_eq!(
            failure(&error),
            (
                PacketErrorKind::UnexpectedType,
                Some(parts[index].0),
                offset_of(&parts, index)
            )
        );
        assert_eq!(following.unwrap().primary(), &key(&ed25519[0]), "{error}");
    }

    // A Secret Key packet ends the certificate before it, and begins one of
    // its own, which is refused.
    let mut secret = primary.clone();
    secret.0 = Tag::SECRET_KEY;
    let parts = then(
        &ed25519,
        &[
            primary,
            user_id,
            certification,
            &secret,
            user_id,
            &secret_subkey,
        ],
    );
    let [first, refused, following] = <[_; 3]>::try_from(read(&framed(&parts))).unwrap();
    assert_eq!(first.unwrap().user_ids().len(), 1);
    assert_eq!(
        failure(&refused.unwrap_err()),
        (
            PacketErrorKind::UnexpectedType,
            Some(Tag::SECRET_KEY),
            offset_of(&parts, 3)
        )
    );
    assert!(following.is_ok());
}

/// A failure in the framing ends the keyring, and refuses the certificate it
/// is found in.
#[test]
fn framing_failures_end_the_keyring() {
    let rsa = gnupg("rsa");
    let parts: Vec<&Part> = rsa.iter().collect();
    let whole = framed(&parts);
    let ed25519 = vector_bytes("gnupg/ed25519.pgp");
    // Damage that fails whatever follows it, and damage at the end.
    for (damage, following, kind) in [
        (&[0x00][..], &ed25519[..], PacketErrorKind::InvalidHeader),
        (&[0xC0, 0x00], &ed25519, PacketErrorKind::ReservedType),
        (&[0xCB, 0xE1], &ed25519, PacketErrorKind::PartialBodyLength),
        (&[0xC2, 0x05, 0x01], &[], PacketErrorKind::Truncated),
    ] {
        // After a certificate's last packet: the certificate might have gone
        // on, so it is refused.
        let data = [&whole[..], damage, following].concat();
        let [error] = <[_; 1]>::try_from(read(&data)).unwrap();
        let error = error.unwrap_err();
        assert_eq!((error.kind(), error.offset()), (kind, whole.len()));
        // Inside a certificate refused for another reason.
        let data = [&framed(&[&rsa[3]])[..], damage, following].concat();
        let [refused, error] = <[_; 2]>::try_from(read(&data)).unwrap();
        assert_eq!(refused.unwrap_err().kind(), PacketErrorKind::UnexpectedType);
        assert_eq!(error.unwrap_err().kind(), kind);
        // At the start.
        let data = [damage, following].concat();
        let [error] = <[_; 1]>::try_from(read(&data)).unwrap();
        assert_eq!(error.unwrap_err().kind(), kind);
    }
}
