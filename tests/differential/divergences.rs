//! Each divergence `compare` tells apart, made once on purpose and told
//! apart as itself, in a verdict or in a reading, and each difference in
//! reading that it allows.

use std::collections::BTreeSet;

use pgp::composed::{DetachedSignature, KeyType};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{PacketHeader, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::ser::Serialize as _;
use pgp::types::{
    Fingerprint, KeyDetails as _, KeyVersion, Password, SigningKey, Tag as RpgpTag, Timestamp,
};
use sha2::Digest as _;

use super::{DOCUMENTS, Made, framed, made, pair, paired_key};
use crate::compare::{self, Divergence, Key, Over, Verdict};
use crate::forge;
use crate::make::{self, Shape};

/// A signature made with rPGP from `config` over `document` by `signer`,
/// stating its creation time and the issuer `issuer`, as a Signature packet.
fn configured(
    mut config: SignatureConfig,
    signer: &dyn SigningKey,
    issuer: Fingerprint,
    document: &[u8],
) -> Vec<u8> {
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            make::CREATED,
        )))
        .unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(issuer)).unwrap(),
    ];
    let signature = config
        .sign(&Box::new(signer), &Password::empty(), document)
        .unwrap();
    DetachedSignature::new(signature).to_bytes().unwrap()
}

/// The one signature in `data`, as both read it.
fn only_signature(data: &[u8]) -> compare::Signature {
    let mut packets = compare::read(data).unwrap();
    assert_eq!(packets.signatures.len(), 1);
    packets.signatures.remove(0)
}

/// The one key in the packet `data`, as both read it.
fn only_key(data: &[u8]) -> Key {
    let mut packets = compare::read(data).unwrap();
    assert_eq!(packets.keys.len(), 1);
    packets.keys.remove(0)
}

#[test]
fn each_divergence() {
    let document = DOCUMENTS[3].as_bytes();
    let over = Over::Document(document);
    let mut seen = BTreeSet::new();
    let mut expect = |verdict: Option<Verdict>, divergence: Divergence| {
        assert_eq!(verdict, Some(Verdict::Diverged(divergence)));
        seen.insert(divergence);
    };
    let [rsa, _, v4_ed25519, v6_ed25519, _] = made() else {
        panic!("the shapes")
    };
    let signer = |made: &'static Made| made.signers()[0];

    // An RSA signature naming RSA's sign-only variant.
    let (key, secret) = signer(rsa);
    let config = SignatureConfig::v4(
        SignatureType::Binary,
        PublicKeyAlgorithm::RSASign,
        HashAlgorithm::Sha256,
    );
    let data = configured(config, secret, key.rpgp.fingerprint(), document);
    expect(
        compare::verify(&only_signature(&data), key, over).unwrap(),
        Divergence::AlgorithmMismatch,
    );

    // A key of an algorithm irongall does not verify with.
    let shape = Shape {
        name: "ECDSA",
        version: KeyVersion::V4,
        primary: KeyType::ECDSA(ECCCurve::P256),
        signing: KeyType::ECDSA(ECCCurve::P256),
        encryption: KeyType::ECDH(ECCCurve::P256),
    };
    let secret = make::certificate(&shape, 4000);
    let key = &compare::read(&make::public(&secret)).unwrap().keys[0];
    let data = make::detached(&*secret, HashAlgorithm::Sha256, false, document, 4001).unwrap();
    expect(
        compare::verify(&only_signature(&data), key, over).unwrap(),
        Divergence::UnsupportedAlgorithm,
    );

    // An RSA key narrower than 2048 bits, which rPGP will not make.
    let (key_packet, sign) = forge::rsa(1024, 4006, make::CREATED);
    let key = only_key(&key_packet);
    let forger = forge::Forger {
        key: key.rpgp.clone(),
        sign,
    };
    let data = make::detached(&forger, HashAlgorithm::Sha256, false, document, 4007).unwrap();
    expect(
        compare::verify(&only_signature(&data), &key, over).unwrap(),
        Divergence::ShortModulus,
    );

    // A hash irongall does not implement.
    let (key, secret) = signer(rsa);
    let data = make::detached(secret, HashAlgorithm::Ripemd160, false, document, 4002).unwrap();
    expect(
        compare::verify(&only_signature(&data), key, over).unwrap(),
        Divergence::UnsupportedHash,
    );

    // The identity as a key, under which R = B and S = 1 is a signature over
    // every document; and a signature whose R is the identity.
    for version in [KeyVersion::V4, KeyVersion::V6] {
        let key = only_key(&forge::ed25519_key(
            version,
            &forge::IDENTITY,
            make::CREATED,
        ));
        let forger = forge::Forger {
            key: key.rpgp.clone(),
            sign: |digest: &[u8]| forge::ed25519_signature(version, forge::universal(digest)),
        };
        for other in [&b"any"[..], b"document at all"] {
            let data = make::detached(&forger, HashAlgorithm::Sha256, false, other, 4003).unwrap();
            expect(
                compare::verify(&only_signature(&data), &key, Over::Document(other)).unwrap(),
                Divergence::InvalidKey,
            );
        }

        let (point, sign) = forge::small_order_r([7; 32]);
        let key = only_key(&forge::ed25519_key(version, &point, make::CREATED));
        let forger = forge::Forger {
            key: key.rpgp.clone(),
            sign: |digest: &[u8]| forge::ed25519_signature(version, sign(digest)),
        };
        let data = make::detached(&forger, HashAlgorithm::Sha256, false, document, 4004).unwrap();
        expect(
            compare::verify(&only_signature(&data), &key, over).unwrap(),
            Divergence::SmallOrderR,
        );
    }

    // A version 6 primary key binding a version 4 subkey, which rPGP frames
    // by the subkey's version.
    let (primary, secret) = signer(v6_ed25519);
    let subkey = signer(v4_ed25519).0;
    let mut config = SignatureConfig::v6(
        make::rng(4005),
        SignatureType::SubkeyBinding,
        PublicKeyAlgorithm::Ed25519,
        HashAlgorithm::Sha256,
    )
    .unwrap();
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            make::CREATED,
        )))
        .unwrap(),
    ];
    let binding = config
        .sign_subkey_binding(
            &Box::new(secret),
            &primary.rpgp,
            &Password::empty(),
            &subkey.rpgp,
        )
        .unwrap();
    let data = DetachedSignature::new(binding).to_bytes().unwrap();
    expect(
        compare::verify(
            &only_signature(&data),
            primary,
            Over::Subkey { primary, subkey },
        )
        .unwrap(),
        Divergence::FramedBySignatureVersion,
    );

    // A subkey whose modulus is written with a leading zero, which rPGP
    // writes back without it, under the binding made over it as written
    // without.
    let primary = paired_key(&rsa.packets, rsa.certificate.primary());
    let subkey = &rsa.certificate.subkeys()[0];
    let body = framed(&rsa.data)
        .into_iter()
        .map(|packet| {
            irongall::packet::packets(packet)
                .next()
                .unwrap()
                .unwrap()
                .body()
                .to_vec()
        })
        .find(|body| {
            irongall::key::PublicKey::from_packet(
                &irongall::packet::packets(&forge::packet(14, body))
                    .next()
                    .unwrap()
                    .unwrap(),
            )
            .is_ok_and(|key| key == *subkey.key())
        })
        .unwrap();
    // Version, creation time and algorithm, then the modulus as an MPI.
    let bits = u16::from_be_bytes([body[6], body[7]]);
    let octets = usize::from(bits.div_ceil(8));
    let padded = [
        &body[..6],
        &(octets as u16 * 8 + 8).to_be_bytes(),
        &[0],
        &body[8..],
    ]
    .concat();
    let padded = only_key(&forge::packet(14, &padded));
    assert!(padded.reencoded);
    let binding = pair(&rsa.packets, &subkey.signatures()[0]).unwrap();
    expect(
        compare::verify(
            binding,
            primary,
            Over::Subkey {
                primary,
                subkey: &padded,
            },
        )
        .unwrap(),
        Divergence::Reencoded,
    );

    // A signature naming another key as its issuer.
    let (key, secret) = signer(v4_ed25519);
    let other = signer(rsa).0.rpgp.fingerprint();
    let config = SignatureConfig::v4(
        SignatureType::Binary,
        PublicKeyAlgorithm::Ed25519,
        HashAlgorithm::Sha256,
    );
    let data = configured(config, secret, other, document);
    expect(
        compare::verify(&only_signature(&data), key, over).unwrap(),
        Divergence::IssuerNamesAnotherKey,
    );

    // A certification revocation over a key alone. rPGP makes none, so its
    // hash is framed here as RFC 9580 §5.2.4 writes it, and rPGP's key signs
    // the digest.
    let (key, secret) = signer(v4_ed25519);
    let hashed = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            make::CREATED,
        )))
        .unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(key.rpgp.fingerprint())).unwrap(),
    ];
    let mut area = Vec::new();
    for subpacket in &hashed {
        subpacket.to_writer(&mut area).unwrap();
    }
    let body = key.rpgp.to_bytes().unwrap();
    let fields = [
        &[4, 0x30, 27, 8][..],
        &u16::try_from(area.len()).unwrap().to_be_bytes(),
        &area,
    ]
    .concat();
    let digest = sha2::Sha256::digest(
        [
            &[0x99][..],
            &u16::try_from(body.len()).unwrap().to_be_bytes(),
            &body,
            &fields,
            &[4, 0xFF],
            &u32::try_from(fields.len()).unwrap().to_be_bytes(),
        ]
        .concat(),
    );
    let material = secret
        .sign(&Password::empty(), HashAlgorithm::Sha256, &digest)
        .unwrap();
    let revocation = |header| {
        pgp::packet::Signature::v4(
            header,
            SignatureType::CertRevocation,
            PublicKeyAlgorithm::Ed25519,
            HashAlgorithm::Sha256,
            [digest[0], digest[1]],
            material.clone(),
            hashed.clone(),
            Vec::new(),
        )
    };
    let length = revocation(PacketHeader::new_fixed(RpgpTag::Signature, 0)).write_len();
    let revocation = revocation(PacketHeader::new_fixed(
        RpgpTag::Signature,
        u32::try_from(length).unwrap(),
    ));
    let data = DetachedSignature::new(revocation).to_bytes().unwrap();
    expect(
        compare::verify(&only_signature(&data), key, Over::Key(key)).unwrap(),
        Divergence::RevocationOverKey,
    );

    // A text signature over a document, checked over the document with CRs
    // that GnuPG drops: before a line's CR LF, and at the end.
    let (key, secret) = signer(v4_ed25519);
    let data = make::detached(secret, HashAlgorithm::Sha256, true, b"a\r\nb", 4008).unwrap();
    let signature = only_signature(&data);
    for gnupg in [&b"a\r\r\nb"[..], b"a\r\nb\r", b"a\nb\r\r"] {
        expect(
            compare::verify(&signature, key, Over::Document(gnupg)).unwrap(),
            Divergence::GnuPgLineEndings,
        );
    }

    assert_eq!(seen.len(), 11);
}

/// A subpacket of type `kind`, with a one-octet length.
fn subpacket(kind: u8, body: &[u8]) -> Vec<u8> {
    [&[u8::try_from(body.len() + 1).unwrap(), kind][..], body].concat()
}

/// A version 4 signature's body, of type `signature_type`, by an Ed25519
/// key, with the subpacket areas `hashed` and `unhashed` and the material
/// `material`. Both read it whatever its material; nothing verifies it.
fn signature_body(signature_type: u8, hashed: &[u8], unhashed: &[u8], material: &[u8]) -> Vec<u8> {
    [
        &[4, signature_type, 27, 8][..],
        &u16::try_from(hashed.len()).unwrap().to_be_bytes(),
        hashed,
        &u16::try_from(unhashed.len()).unwrap().to_be_bytes(),
        unhashed,
        &[0, 0],
        material,
    ]
    .concat()
}

/// A hashed subpacket area that states when the signature was made, and
/// nothing else.
fn dated() -> Vec<u8> {
    subpacket(2, &make::CREATED.to_be_bytes())
}

/// A Revocation Key (RFC 9580 §5.2.3.23) of the class `class`: Ed25519, and
/// a version 4 fingerprint.
fn revocation_key(class: u8) -> Vec<u8> {
    [&[class, 27][..], &[0x33; 20]].concat()
}

/// A notation (RFC 9580 §5.2.3.24): a flag that it is text, its name and its
/// value.
fn notation() -> Vec<u8> {
    let (name, value) = (&b"note@example.invalid"[..], &b"value"[..]);
    [
        &[0x80, 0, 0, 0][..],
        &u16::try_from(name.len()).unwrap().to_be_bytes(),
        &u16::try_from(value.len()).unwrap().to_be_bytes(),
        name,
        value,
    ]
    .concat()
}

/// Each packet only one of the two reads, for each rule `compare` knows that
/// says why, told apart as itself; and beside each, the same packet without
/// what sets it apart, which both read.
#[test]
fn each_reading_divergence() {
    let signature = |hashed: &[u8], unhashed: &[u8], material: &[u8]| {
        forge::packet(2, &signature_body(0x00, hashed, unhashed, material))
    };
    let native = [0; 64];
    // A subkey binding embedding `embedded`, a signature's body.
    let binding = |embedded: &[u8]| {
        forge::packet(
            2,
            &signature_body(0x18, &dated(), &subpacket(32, embedded), &native),
        )
    };
    let back = |signature_type: u8, unhashed: &[u8]| {
        signature_body(signature_type, &dated(), unhashed, &native)
    };
    // A version 6 Ed25519 key whose point is `point`, and whose count of its
    // material is `count`.
    let key = |point: &[u8; 32], count: u8| {
        let mut packet = forge::ed25519_key(KeyVersion::V6, point, make::CREATED);
        let at = packet.len() - 33;
        packet[at] = count;
        packet
    };
    let on_curve = *ed25519_dalek::SigningKey::from_bytes(&[3; 32])
        .verifying_key()
        .as_bytes();
    let off_curve = (2..=u8::MAX)
        .map(|y| {
            let mut point = [0; 32];
            point[0] = y;
            point
        })
        .find(|point| ed25519_dalek::VerifyingKey::from_bytes(point).is_err())
        .unwrap();
    // A signature naming RSA (1) or RSA's encrypt-only variant (2), with the
    // material `material`.
    let rsa_signature_of = |algorithm: u8, material: &[u8]| {
        let mut body = signature_body(0x00, &dated(), &[], material);
        body[2] = algorithm;
        forge::packet(2, &body)
    };
    let rsa_signature = |material: &[u8]| rsa_signature_of(1, material);
    // GnuPG's NIST P-256 key, and the same key with its material cut to an
    // octet.
    let nistp256 = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/gnupg/nistp256.pgp"),
    )
    .unwrap();
    let ecdsa = framed(&nistp256)[0].to_vec();
    let body = irongall::packet::packets(&ecdsa)
        .next()
        .unwrap()
        .unwrap()
        .body();
    assert_eq!(body[5], 19);
    let cut = forge::packet(6, &[&body[..6], &[0]].concat());

    // A signature's body, under a legacy header of indeterminate length, and
    // under one that gives its length.
    let body = signature_body(0x00, &dated(), &[], &native);
    let indeterminate = [&[0x8B][..], &body].concat();
    let determinate = [&[0x88, u8::try_from(body.len()).unwrap()][..], &body].concat();

    // A signature's body in a packet of the reserved type 0, and in a
    // Signature packet.
    let reserved = [&[0xC0, u8::try_from(body.len()).unwrap()][..], &body].concat();
    let typed = [&[0xC2, u8::try_from(body.len()).unwrap()][..], &body].concat();

    // An RSA key, and the same key with its exponent 65537 made 2.
    let (rsa, _) = forge::rsa(1024, 4009, make::CREATED);
    let body = irongall::packet::packets(&rsa)
        .next()
        .unwrap()
        .unwrap()
        .body();
    assert!(body.ends_with(&[0, 17, 1, 0, 1]));
    let even = forge::packet(6, &[&body[..body.len() - 5], &[0, 2, 2]].concat());

    // A binding embedding an EdDSALegacy back-signature whose R is written
    // with a leading zero octet, and the same with R's first octet nonzero.
    let legacy_back = |first: u8| {
        let mut r = [0x11; 32];
        r[0] = first;
        let material = [&[1, 0][..], &r, &[1, 0], &[0x22; 32]].concat();
        let mut body = signature_body(0x19, &dated(), &[], &material);
        body[2] = 22;
        binding(&body)
    };

    let cases: [(Divergence, Vec<u8>, Vec<u8>); 17] = [
        (
            Divergence::OtherVersion,
            {
                let mut packet = signature(&dated(), &[], &native);
                packet[2] = 12;
                packet
            },
            signature(&dated(), &[], &native),
        ),
        (
            Divergence::NoCreationTime,
            signature(&[], &[], &native),
            signature(&dated(), &[], &native),
        ),
        (
            Divergence::MalformedSubpacket,
            signature(&[dated(), subpacket(25, &[2])].concat(), &[], &native),
            signature(&[dated(), subpacket(25, &[1])].concat(), &[], &native),
        ),
        (
            Divergence::CriticalSubpacket,
            signature(
                &[dated(), subpacket(0x80 | 20, &notation())].concat(),
                &[],
                &native,
            ),
            signature(
                &[dated(), subpacket(20, &notation())].concat(),
                &[],
                &native,
            ),
        ),
        (
            Divergence::MpiLength,
            rsa_signature(&[0, 7, 0xFF]),
            rsa_signature(&[0, 8, 0xFF]),
        ),
        (
            Divergence::TrailingMaterial,
            signature(&dated(), &[], &[0; 65]),
            signature(&dated(), &[], &native),
        ),
        (
            Divergence::MaterialCount,
            key(&on_curve, 33),
            key(&on_curve, 32),
        ),
        (Divergence::StreamedLength, indeterminate, determinate),
        (
            Divergence::EncryptOnlyMaterial,
            rsa_signature_of(2, &[0]),
            rsa_signature_of(2, &[0, 8, 0xFF]),
        ),
        (Divergence::ReservedType, reserved, typed),
        (
            Divergence::UndecodedSubpacket,
            signature(&dated(), &subpacket(12, &revocation_key(0x00)), &native),
            signature(&dated(), &subpacket(12, &revocation_key(0x80)), &native),
        ),
        (
            Divergence::NestedEmbeddedSignature,
            binding(&back(0x19, &subpacket(32, &back(0x19, &[])))),
            binding(&back(0x19, &[])),
        ),
        (
            Divergence::EmbeddedSignatureType,
            binding(&back(0x18, &[])),
            binding(&back(0x19, &[])),
        ),
        (Divergence::OpaqueMaterial, cut, ecdsa),
        (
            Divergence::PointOffCurve,
            key(&off_curve, 32),
            key(&on_curve, 32),
        ),
        (Divergence::InvalidRsaKey, even, rsa),
        (
            Divergence::ReencodedEmbeddedSignature,
            legacy_back(0),
            legacy_back(0x40),
        ),
    ];
    let mut seen = BTreeSet::new();
    for (divergence, apart, together) in cases {
        let read = compare::read(&apart).unwrap();
        assert_eq!(read.one_sided, [divergence]);
        assert_eq!(read.keys.len() + read.signatures.len(), 0, "{divergence:?}");
        let read = compare::read(&together).unwrap();
        assert!(read.one_sided.is_empty(), "{divergence:?}: {read:?}");
        assert_eq!(read.keys.len() + read.signatures.len(), 1, "{divergence:?}");
        seen.insert(divergence);
    }
    assert_eq!(seen.len(), 17);
}

/// A version 6 key whose count covers octets past the material its
/// algorithm gives, which the packet holds, is told apart by its count, as
/// one whose count runs past the packet is: irongall refuses it for the
/// count, and rPGP reads the material and passes over the rest.
#[test]
fn a_count_past_the_material() {
    let point = *ed25519_dalek::SigningKey::from_bytes(&[3; 32])
        .verifying_key()
        .as_bytes();
    let packet = forge::ed25519_key(KeyVersion::V6, &point, make::CREATED);
    let body = irongall::packet::packets(&packet)
        .next()
        .unwrap()
        .unwrap()
        .body();
    // The count is the four octets before the point.
    let (head, point) = body.split_at(body.len() - 32);
    let (head, count) = head.split_at(head.len() - 4);
    assert_eq!(count, 32_u32.to_be_bytes());
    let counted = [head, &33_u32.to_be_bytes(), point, &[0]].concat();
    let read = compare::read(&forge::packet(6, &counted)).unwrap();
    assert_eq!(read.one_sided, [Divergence::MaterialCount]);
    assert!(read.keys.is_empty());
}

#[test]
fn encrypt_only_rsa_material() {
    // A signature naming RSA's encrypt-only variant: irongall reads its
    // material as an RSA signature's, rPGP keeps it as octets, and neither
    // verifies it.
    let [rsa, ..] = made() else {
        panic!("the shapes")
    };
    let (key, secret) = rsa.signers()[0];
    let document = DOCUMENTS[3].as_bytes();
    let config = SignatureConfig::v4(
        SignatureType::Binary,
        PublicKeyAlgorithm::RSAEncrypt,
        HashAlgorithm::Sha256,
    );
    let data = configured(config, secret, key.rpgp.fingerprint(), document);
    let signature = only_signature(&data);
    assert!(matches!(
        signature.irongall.material(),
        irongall::signature::SignatureMaterial::Rsa(_)
    ));
    assert!(matches!(
        signature.rpgp.signature(),
        Some(pgp::types::SignatureBytes::Native(_))
    ));
    assert_eq!(
        compare::verify(&signature, key, Over::Document(document)).unwrap(),
        Some(Verdict::Refused)
    );
}
