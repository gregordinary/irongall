//! Tests for signature verification: the hash of every signature type against
//! an independent construction of it, the verdicts on real signatures, and
//! each reason a signature is refused.

use alloc::vec::Vec;
use alloc::{format, vec};

use super::{
    LineEndings, Over, Prefix, PrimaryChecks, Subject, SubjectKind, VerifyError, kinds,
    statement_kinds,
};
use crate::armor;
use crate::cert::{self, Certificate};
use crate::hash::{Context, Digest, HashAlgorithm, HashFunction as _, Sha256};
use crate::key::{KeyMaterial, PublicKey};
use crate::packet::{self, Packet, Version};
use crate::signature::{Signature, SignatureType};
use crate::test_support::rfc9580::{A1_KEY, A2_SIGNATURE, A3_CERTIFICATE, A6_SIGNATURE, A6_TEXT};
use crate::test_support::{
    Rng, digest, forge, hashed_key, hashed_user_id, signature_digest, signature_input,
    vector_bytes, work,
};

fn dearmor(armored: &str) -> Vec<u8> {
    armor::decode(armored.as_bytes()).unwrap().into_data()
}

/// The one packet in `data`.
fn only_packet(data: &[u8]) -> Packet<'_> {
    let [packet] = <[Packet<'_>; 1]>::try_from(
        packet::packets(data)
            .map(Result::unwrap)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    packet
}

/// The one certificate in `data`, with nothing passed over.
fn only_certificate(data: &[u8]) -> Certificate {
    let [certificate] = <[Certificate; 1]>::try_from(
        cert::certificates(data)
            .map(Result::unwrap)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(certificate.skipped(), []);
    certificate
}

/// The key a Public Key packet with `body` holds.
fn key_of(body: &[u8]) -> PublicKey {
    let length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let input = [&[0xC6, 0xFF][..], &length, body].concat();
    PublicKey::from_packet(&only_packet(&input)).unwrap()
}

/// The signature a Signature packet with `body` holds.
fn signature_of(body: &[u8]) -> Signature {
    let length = u32::try_from(body.len()).unwrap().to_be_bytes();
    let input = [&[0xC2, 0xFF][..], &length, body].concat();
    Signature::from_packet(&only_packet(&input)).unwrap()
}

/// A multiprecision integer of `value`, whose first octet is not zero.
fn mpi(value: &[u8]) -> Vec<u8> {
    let bits = value.len() * 8 - value[0].leading_zeros() as usize;
    [&u16::try_from(bits).unwrap().to_be_bytes()[..], value].concat()
}

/// Where the hash prefix is in the body of a version 4 signature.
fn v4_prefix_offset(body: &[u8]) -> usize {
    let hashed = usize::from(u16::from_be_bytes([body[4], body[5]]));
    let unhashed_at = 6 + hashed;
    let unhashed = usize::from(u16::from_be_bytes([
        body[unhashed_at],
        body[unhashed_at + 1],
    ]));
    unhashed_at + 2 + unhashed
}

/// The hash `signature` is made over, if it is over `subject`, for a subject
/// that GnuPG does not read otherwise, and so has one.
fn only_digest(signature: &Signature, subject: Subject<'_>) -> Result<Digest, VerifyError> {
    signature.digests(subject).map(|digests| {
        assert_eq!(digests.gnupg, None);
        digests.digest
    })
}

/// The body of a version 4 signature, its hash algorithm made `algorithm`,
/// and its prefix made the one `subject` then hashes to.
fn rehashed(body: &[u8], algorithm: HashAlgorithm, subject: Subject<'_>) -> Vec<u8> {
    let mut body = body.to_vec();
    body[3] = algorithm.number();
    let digest = only_digest(&signature_of(&body), subject).unwrap();
    let at = v4_prefix_offset(&body);
    body[at..at + 2].copy_from_slice(&digest.as_bytes()[..2]);
    body
}

/// RFC 9580 Appendix A: the version 4 binary signature of A.2, the version 6
/// direct-key signature and subkey binding of A.3, and the version 6 text
/// signature of A.6, each hashed as the independent construction hashes it,
/// and verified.
#[test]
fn rfc_9580_samples() {
    let key = PublicKey::from_packet(&only_packet(&dearmor(A1_KEY))).unwrap();
    let a2 = Signature::from_packet(&only_packet(&dearmor(A2_SIGNATURE))).unwrap();
    let document = Subject::Document(b"OpenPGP");
    assert_eq!(
        only_digest(&a2, document),
        Ok(signature_digest(&a2, b"OpenPGP"))
    );
    assert_eq!(a2.verify(&key, document), Ok(()));
    assert_eq!(
        a2.verify(&key, Subject::Document(b"OpenPGP.")),
        Err(VerifyError::HashPrefixMismatch)
    );

    let certificate = only_certificate(&dearmor(A3_CERTIFICATE));
    let primary = certificate.primary();
    let [direct] = certificate.primary_signatures() else {
        panic!("one direct-key signature");
    };
    assert_eq!(
        only_digest(direct, Subject::Key(primary)),
        Ok(signature_digest(direct, &hashed_key(primary.body())))
    );
    assert_eq!(direct.verify(primary, Subject::Key(primary)), Ok(()));
    let [subkey] = certificate.subkeys() else {
        panic!("one subkey");
    };
    let [binding] = subkey.signatures() else {
        panic!("one binding");
    };
    let subject = Subject::Subkey {
        primary,
        subkey: subkey.key(),
    };
    let data = [hashed_key(primary.body()), hashed_key(subkey.key().body())].concat();
    assert_eq!(
        only_digest(binding, subject),
        Ok(signature_digest(binding, &data))
    );
    assert_eq!(binding.verify(primary, subject), Ok(()));

    // The text signature verifies over the text with any line endings that
    // canonicalize to the ones it was made over.
    let a6 = Signature::from_packet(&only_packet(&dearmor(A6_SIGNATURE))).unwrap();
    let lf = A6_TEXT.replace("\r\n", "\n");
    let mixed = A6_TEXT.replacen("\r\n", "\n", 2);
    for text in [A6_TEXT, &lf, &mixed] {
        assert_eq!(
            only_digest(&a6, Subject::Document(text.as_bytes())),
            Ok(signature_digest(&a6, A6_TEXT.as_bytes())),
            "{text:?}"
        );
        assert_eq!(
            a6.verify(primary, Subject::Document(text.as_bytes())),
            Ok(())
        );
    }
    let cr = A6_TEXT.replace("\r\n", "\r");
    assert_eq!(
        a6.verify(primary, Subject::Document(cr.as_bytes())),
        Err(VerifyError::HashPrefixMismatch)
    );
}

/// The certificates GnuPG made, and the detached signatures its signing
/// subkey made: every signature verifies with the key that made it, over the
/// subject its place gives it, and is hashed as the independent construction
/// hashes it.
#[test]
fn gnupg_signatures() {
    let mut checked = 0;
    for name in ["rsa", "ed25519", "ed25519-signing"] {
        let certificate = only_certificate(&vector_bytes(&format!("gnupg/{name}.pgp")));
        let primary = certificate.primary();
        let [user_id] = certificate.user_ids() else {
            panic!("{name}: one user ID");
        };
        let [certification] = user_id.signatures() else {
            panic!("{name}: one certification");
        };
        let subject = Subject::UserId {
            key: primary,
            user_id: user_id.value(),
        };
        let data = [hashed_key(primary.body()), hashed_user_id(user_id.value())].concat();
        assert_eq!(
            only_digest(certification, subject),
            Ok(signature_digest(certification, &data))
        );
        assert_eq!(certification.verify(primary, subject), Ok(()), "{name}");

        let [subkey] = certificate.subkeys() else {
            panic!("{name}: one subkey");
        };
        let [binding] = subkey.signatures() else {
            panic!("{name}: one binding");
        };
        let subject = Subject::Subkey {
            primary,
            subkey: subkey.key(),
        };
        let data = [hashed_key(primary.body()), hashed_key(subkey.key().body())].concat();
        assert_eq!(
            only_digest(binding, subject),
            Ok(signature_digest(binding, &data))
        );
        assert_eq!(binding.verify(primary, subject), Ok(()), "{name}");
        checked += 2;

        if name == "ed25519-signing" {
            let [back] = binding.embedded_signatures() else {
                panic!("one back-signature");
            };
            assert_eq!(back.verify(subkey.key(), subject), Ok(()));
            // The primary did not make it.
            assert_eq!(
                back.verify(primary, subject),
                Err(VerifyError::BadSignature)
            );

            let document = vector_bytes("gnupg/document.txt");
            for file in ["binary", "text"] {
                let data = vector_bytes(&format!("gnupg/{file}.sig"));
                let signature = Signature::from_packet(&only_packet(&data)).unwrap();
                let subject = Subject::Document(&document);
                assert_eq!(signature.verify(subkey.key(), subject), Ok(()), "{file}");
                assert_eq!(
                    signature.verify(primary, subject),
                    Err(VerifyError::BadSignature),
                    "{file}"
                );
            }
            checked += 3;
        }
    }
    assert_eq!(checked, 9);
}

/// The kinds of subject each signature type is made over.
#[test]
fn signature_types_and_their_subjects() {
    for (number, expected) in [
        (0x00, Some(&[SubjectKind::Document][..])),
        (0x01, Some(&[SubjectKind::Document])),
        (0x10, Some(&[SubjectKind::UserId])),
        (0x11, Some(&[SubjectKind::UserId])),
        (0x12, Some(&[SubjectKind::UserId])),
        (0x13, Some(&[SubjectKind::UserId])),
        (0x18, Some(&[SubjectKind::Subkey])),
        (0x19, Some(&[SubjectKind::Subkey])),
        (0x1F, Some(&[SubjectKind::Key])),
        (0x20, Some(&[SubjectKind::Key])),
        (0x28, Some(&[SubjectKind::Subkey])),
        (0x30, Some(&[SubjectKind::UserId, SubjectKind::Key])),
        (0x02, None),
        (0x40, None),
        (0x50, None),
        (0xFF, None),
        (0x03, None),
    ] {
        assert_eq!(kinds(SignatureType(number)), expected, "{number:#04X}");
    }

    // A certificate's own statements are those over a part of it, but for
    // the back-signature, which the subkey makes; and the certifications
    // are the four types over a user ID alone.
    let mut statements = 0;
    for number in 0..=u8::MAX {
        let signature_type = SignatureType(number);
        let expected = match number {
            0x19 => None,
            _ => kinds(signature_type).filter(|kinds| *kinds != [SubjectKind::Document]),
        };
        assert_eq!(statement_kinds(signature_type), expected, "{number:#04X}");
        statements += usize::from(expected.is_some());
        assert_eq!(
            signature_type.is_certification(),
            (0x10..=0x13).contains(&number),
            "{number:#04X}"
        );
    }
    assert_eq!(statements, 9);

    // Through `verify`: the A.2 signature retyped, against each kind of
    // subject.
    let key = PublicKey::from_packet(&only_packet(&dearmor(A1_KEY))).unwrap();
    let body = only_packet(&dearmor(A2_SIGNATURE)).body().to_vec();
    let user_id = Subject::UserId {
        key: &key,
        user_id: b"user",
    };
    let subkey = Subject::Subkey {
        primary: &key,
        subkey: &key,
    };
    for (number, subject, expected) in [
        (0x00, Subject::Key(&key), VerifyError::WrongSubject),
        (0x01, user_id, VerifyError::WrongSubject),
        (
            0x13,
            Subject::Document(b"OpenPGP"),
            VerifyError::WrongSubject,
        ),
        (0x18, user_id, VerifyError::WrongSubject),
        (0x1F, subkey, VerifyError::WrongSubject),
        (0x30, subkey, VerifyError::WrongSubject),
        (0x02, Subject::Document(b""), VerifyError::UnsupportedType),
        (
            0x40,
            Subject::Document(b"OpenPGP"),
            VerifyError::UnsupportedType,
        ),
        (0xFF, Subject::Key(&key), VerifyError::UnsupportedType),
    ] {
        let mut retyped = body.clone();
        retyped[1] = number;
        let signature = signature_of(&retyped);
        assert_eq!(
            signature.verify(&key, subject),
            Err(expected),
            "{number:#04X}"
        );
    }
}

/// A key is framed by the signature's version, not the key's (RFC 9580
/// §5.2.4): a version 4 signature over version 6 keys frames them with
/// `0x99` and two octets of length, and a version 6 signature over version 4
/// keys with `0x9B` and four.
#[test]
fn keys_are_framed_by_the_signatures_version() {
    let v4 = only_certificate(&vector_bytes("gnupg/rsa.pgp"));
    let v6 = only_certificate(&dearmor(A3_CERTIFICATE));
    let frame = |prefix: u8, body: &[u8]| -> Vec<u8> {
        let length = if prefix == 0x99 {
            u16::try_from(body.len()).unwrap().to_be_bytes().to_vec()
        } else {
            u32::try_from(body.len()).unwrap().to_be_bytes().to_vec()
        };
        [&[prefix][..], &length, body].concat()
    };
    for (signer, keys, prefix) in [(&v4, &v6, 0x99), (&v6, &v4, 0x9B)] {
        let binding = &signer.subkeys()[0].signatures()[0];
        let (primary, subkey) = (keys.primary(), keys.subkeys()[0].key());
        let data = [frame(prefix, primary.body()), frame(prefix, subkey.body())].concat();
        assert_eq!(
            only_digest(binding, Subject::Subkey { primary, subkey }),
            Ok(digest(
                binding.hash_algorithm(),
                &signature_input(binding, &data)
            ))
        );
    }

    // A version 4 signature covers no key whose body is longer than 65535
    // octets.
    let mut body = vec![6, 0, 0, 0, 0, 100];
    body.extend_from_slice(&70_000_u32.to_be_bytes());
    body.resize(body.len() + 70_000, 0x44);
    let long = key_of(&body);
    let binding = &v4.subkeys()[0].signatures()[0];
    assert_eq!(
        only_digest(
            binding,
            Subject::Subkey {
                primary: v4.primary(),
                subkey: &long,
            }
        ),
        Err(VerifyError::BadSignature)
    );
}

/// Each reason a signature is refused, reached through `verify`.
#[test]
fn refusals() {
    // A version 4 EdDSALegacy key and its binary signature over "OpenPGP".
    let key = PublicKey::from_packet(&only_packet(&dearmor(A1_KEY))).unwrap();
    let a2_body = only_packet(&dearmor(A2_SIGNATURE)).body().to_vec();
    let a2 = signature_of(&a2_body);
    let document = Subject::Document(b"OpenPGP");
    let point = |key: &PublicKey| match key.material() {
        KeyMaterial::Ed25519(native) => native.to_vec(),
        other => panic!("not an Ed25519 key: {other:?}"),
    };
    let eddsa_legacy = |native: &[u8]| -> PublicKey {
        let oid = [0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
        key_of(
            &[
                &[4, 0x53, 0xF3, 0x5F, 0x0B, 22][..],
                &oid,
                &[0x01, 0x07, 0x40],
                native,
            ]
            .concat(),
        )
    };
    assert_eq!(eddsa_legacy(&point(&key)).body(), key.body());

    // The version 6 key of A.3 made no version 4 signature.
    let v6 = only_certificate(&dearmor(A3_CERTIFICATE));
    assert_eq!(
        a2.verify(v6.primary(), document),
        Err(VerifyError::VersionMismatch)
    );
    // The same point as an Ed25519 key rather than an EdDSALegacy one.
    let ed25519 = key_of(&[&[4, 0x53, 0xF3, 0x5F, 0x0B, 27][..], &point(&key)].concat());
    assert_eq!(
        a2.verify(&ed25519, document),
        Err(VerifyError::AlgorithmMismatch)
    );
    // Another hash: one irongall does not implement, and one too short for
    // Ed25519.
    for number in [1, 3, 4, 13, 15, 100] {
        let mut body = a2_body.clone();
        body[3] = number;
        assert_eq!(
            signature_of(&body).verify(&key, document),
            Err(VerifyError::UnsupportedHash),
            "{number}"
        );
    }
    for algorithm in [HashAlgorithm::SHA1, HashAlgorithm::SHA224] {
        let body = rehashed(&a2_body, algorithm, document);
        assert_eq!(
            signature_of(&body).verify(&key, document),
            Err(VerifyError::HashTooShort),
            "{algorithm}"
        );
    }
    // An identity point, and a point that is not canonically encoded: the
    // y-coordinate p, which is 0.
    let identity = [&[0x01][..], &[0; 31]].concat();
    let mut p = vec![0xFF; 32];
    p[0] = 0xED;
    p[31] = 0x7F;
    for native in [identity, p] {
        assert_eq!(
            a2.verify(&eddsa_legacy(&native), document),
            Err(VerifyError::InvalidKey)
        );
    }
    // Another valid key.
    assert_eq!(
        a2.verify(&eddsa_legacy(&point(v6.primary())), document),
        Err(VerifyError::BadSignature)
    );
    // Integers wider than Ed25519's, as an EdDSALegacy signature over
    // another curve carries them: no signature the key made, though the key
    // is one irongall verifies with.
    let material = v4_prefix_offset(&a2_body) + 2;
    let wide = [&a2_body[..material], &mpi(&[0x5A; 57]), &mpi(&[0x5A; 57])].concat();
    assert_eq!(
        signature_of(&wide).material(),
        crate::signature::SignatureMaterial::Opaque
    );
    assert_eq!(
        signature_of(&wide).verify(&key, document),
        Err(VerifyError::BadSignature)
    );
    // Other data.
    assert_eq!(
        a2.verify(&key, Subject::Document(b"OpenPGP\n")),
        Err(VerifyError::HashPrefixMismatch)
    );

    // An RSA certification, checked against keys of other material, its
    // subject unchanged so that its prefix still matches.
    let rsa = only_certificate(&vector_bytes("gnupg/rsa.pgp"));
    let primary = rsa.primary();
    let user_id = &rsa.user_ids()[0];
    let certification = &user_id.signatures()[0];
    let subject = Subject::UserId {
        key: primary,
        user_id: user_id.value(),
    };
    let rsa_key = |algorithm: u8, modulus: &[u8], exponent: &[u8]| {
        key_of(
            &[
                &[4, 0, 0, 0, 0, algorithm][..],
                &mpi(modulus),
                &mpi(exponent),
            ]
            .concat(),
        )
    };
    let odd = |bits: usize| {
        let mut modulus = vec![0x5A; bits.div_ceil(8)];
        modulus[0] = 0xFF >> ((8 - bits % 8) % 8);
        *modulus.last_mut().unwrap() |= 1;
        modulus
    };
    let f4 = [0x01, 0x00, 0x01];
    for (key, expected) in [
        (rsa_key(1, &odd(2047), &f4), VerifyError::ModulusTooShort),
        (rsa_key(1, &odd(8193), &f4), VerifyError::ModulusTooLong),
        (
            rsa_key(1, &odd(2048), &[0x02, 0x00, 0x00, 0x00, 0x01]),
            VerifyError::ExponentTooLarge,
        ),
        (
            rsa_key(1, &[&odd(2048)[..255], &[0x5A]].concat(), &f4),
            VerifyError::InvalidKey,
        ),
        (rsa_key(1, &odd(2048), &f4), VerifyError::BadSignature),
        (rsa.subkeys()[0].key().clone(), VerifyError::BadSignature),
    ] {
        assert_eq!(certification.verify(&key, subject), Err(expected));
    }
    assert_eq!(certification.verify(primary, subject), Ok(()));

    // RSA's encrypt-only variant signs nothing, though its material is RSA.
    let mut encrypt_only = primary.body().to_vec();
    encrypt_only[5] = 2;
    let mut body = Vec::new();
    for packet in packet::packets(&vector_bytes("gnupg/rsa.pgp")) {
        let packet = packet.unwrap();
        if packet.tag() == packet::Tag::SIGNATURE {
            body = packet.body().to_vec();
            break;
        }
    }
    body[2] = 2;
    assert_eq!(
        signature_of(&body).verify(&key_of(&encrypt_only), subject),
        Err(VerifyError::UnsupportedAlgorithm)
    );

    // A DSA key: its signature reads, and irongall does not verify it.
    let dsa = only_certificate(&vector_bytes("gnupg/dsa.pgp"));
    let user_id = &dsa.user_ids()[0];
    assert_eq!(
        user_id.signatures()[0].verify(
            dsa.primary(),
            Subject::UserId {
                key: dsa.primary(),
                user_id: user_id.value(),
            }
        ),
        Err(VerifyError::UnsupportedAlgorithm)
    );
}

/// The SHA2-256 digests of `pieces`, passed through [`LineEndings`] one
/// after another: the first reading's and GnuPG's, and whether GnuPG's had
/// a context of its own.
///
/// After each piece, at most one CR is held back from a context both
/// readings share, so finishing never hashes more.
fn canonicalized(pieces: &[&[u8]]) -> ((Digest, Digest), bool) {
    let mut context = Context::new(HashAlgorithm::SHA256).unwrap();
    let mut line_endings = LineEndings::default();
    for piece in pieces {
        line_endings.update(&mut context, piece);
        assert!(line_endings.gnupg.is_some() || line_endings.crs <= 1);
    }
    let (context, gnupg) = line_endings.finish(&context);
    let parted = gnupg.is_some();
    let first = context.finalize();
    let gnupg = gnupg.map_or(first, Context::finalize);
    ((first, gnupg), parted)
}

/// The SHA2-256 digests of the canonical texts: `text`, and GnuPG's reading
/// of it.
fn sha256s(text: &[u8], gnupg: &[u8]) -> (Digest, Digest) {
    let digest = |text: &[u8]| Digest::Sha256(Sha256::digest(text));
    (digest(text), digest(gnupg))
}

/// `text` with a CR inserted before every LF that lacks one: the first
/// reading, written directly.
fn canonical(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (at, &octet) in text.iter().enumerate() {
        if octet == b'\n' && (at == 0 || text[at - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(octet);
    }
    out
}

/// `text` as GnuPG reads it, written directly: every run of CRs before an LF,
/// and the run that ends the text, dropped, and then a CR before every LF.
fn gnupg_canonical(text: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for &octet in text {
        if octet == b'\n' {
            while out.last() == Some(&b'\r') {
                out.pop();
            }
            out.extend_from_slice(b"\r\n");
        } else {
            out.push(octet);
        }
    }
    // The CRs of a line ending stay; only those that end the text go.
    while out.last() == Some(&b'\r') {
        out.pop();
    }
    out
}

#[test]
fn line_endings() {
    for (text, expected, gnupg) in [
        (&b""[..], &b""[..], &b""[..]),
        (b"a", b"a", b"a"),
        (b"a\nb\n", b"a\r\nb\r\n", b"a\r\nb\r\n"),
        (b"a\r\nb", b"a\r\nb", b"a\r\nb"),
        (b"\n\n", b"\r\n\r\n", b"\r\n\r\n"),
        (b"a\rb", b"a\rb", b"a\rb"),
        (b"a\rb\r", b"a\rb\r", b"a\rb"),
        (b"\r\r\n", b"\r\r\n", b"\r\n"),
        (b"a\r\r\r\nb\r\r", b"a\r\r\r\nb\r\r", b"a\r\nb"),
        (b"\n\r", b"\r\n\r", b"\r\n"),
        (b"\r", b"\r", b""),
        (b"a \t\n", b"a \t\r\n", b"a \t\r\n"),
        (b"a\r \n", b"a\r \r\n", b"a\r \r\n"),
    ] {
        assert_eq!(gnupg_canonical(text), gnupg, "{text:?}");
        assert_eq!(
            canonicalized(&[text]).0,
            sha256s(expected, gnupg),
            "{text:?}"
        );
    }
    // A line ending split across two pieces, and empty pieces between.
    for (pieces, expected, gnupg) in [
        (&[&b"a\r"[..], b"\nb"][..], &b"a\r\nb"[..], &b"a\r\nb"[..]),
        (&[b"a\r", b"", b"\n"], b"a\r\n", b"a\r\n"),
        (&[b"a\r", b"b"], b"a\rb", b"a\rb"),
        (&[b"a", b"\n"], b"a\r\n", b"a\r\n"),
        (&[b"\r", b"\r", b"\n"], b"\r\r\n", b"\r\n"),
        (&[b"a\r", b"\r"], b"a\r\r", b"a"),
        (&[b"a\r\r", b"b"], b"a\r\rb", b"a\r\rb"),
        (&[b"a\n", b"\n"], b"a\r\n\r\n", b"a\r\n\r\n"),
    ] {
        assert_eq!(
            canonicalized(pieces).0,
            sha256s(expected, gnupg),
            "{pieces:?}"
        );
    }
    // More CRs than one pass of `hash_crs` holds, before an LF and at the
    // end.
    let crs = [b'\r'; 150];
    for (pieces, expected, gnupg) in [
        (
            &[&b"a"[..], &crs, b"\n"][..],
            [&b"a"[..], &crs, b"\n"].concat(),
            b"a\r\n".to_vec(),
        ),
        (&[b"a", &crs], [&b"a"[..], &crs].concat(), b"a".to_vec()),
        (
            &[b"a", &crs, b"b"],
            [&b"a"[..], &crs, b"b"].concat(),
            [&b"a"[..], &crs, b"b"].concat(),
        ),
    ] {
        assert_eq!(canonicalized(pieces).0, sha256s(&expected, &gnupg));
    }
    // Random text cut into random pieces.
    let mut rng = Rng::new(7);
    for _ in 0..2000 {
        let text: Vec<u8> = (0..rng.below(40))
            .map(|_| b"a \r\r\n"[rng.below(5)])
            .collect();
        let mut cuts: Vec<usize> = (0..rng.below(5))
            .map(|_| rng.below(text.len() + 1))
            .collect();
        cuts.sort_unstable();
        let mut pieces = Vec::new();
        let mut start = 0;
        for cut in cuts {
            pieces.push(&text[start..cut]);
            start = cut;
        }
        pieces.push(&text[start..]);
        let (digests, parted) = canonicalized(&pieces);
        assert_eq!(
            digests,
            sha256s(&canonical(&text), &gnupg_canonical(&text)),
            "{text:?} as {pieces:?}"
        );
        // The readings part only at two CRs in a row, or a CR at the end.
        if parted {
            assert!(
                text.windows(2).any(|pair| pair == b"\r\r") || text.ends_with(b"\r"),
                "{text:?} as {pieces:?}"
            );
        }
    }
}

/// A text signature verifies over a document as either reading has it, and
/// the error, when it does not, is the one a matching prefix met.
#[test]
fn a_text_signature_verifies_under_either_reading() {
    const CREATED: u32 = 1_700_000_000;
    let key = forge::Key::ed25519(1, Version::V4, CREATED);
    let text = b"line\r\r\nends in a CR\r";
    let first = forge::read(
        &key.sign(SignatureType::TEXT, CREATED)
            .over(&canonical(text)),
    );
    let gnupg = forge::read(
        &key.sign(SignatureType::TEXT, CREATED)
            .over(&gnupg_canonical(text)),
    );
    for signature in [&first, &gnupg] {
        assert_eq!(
            signature.verify(key.public(), Subject::Document(text)),
            Ok(())
        );
        let mut hash = signature.document_hash().unwrap();
        for octet in text {
            hash.update(&[*octet]);
        }
        assert_eq!(hash.verify(key.public()), Ok(()));
    }
    // A binary signature over either reading is held to the octets.
    let binary = forge::read(
        &key.sign(SignatureType::BINARY, CREATED)
            .over(&gnupg_canonical(text)),
    );
    assert_eq!(
        binary.verify(key.public(), Subject::Document(text)),
        Err(VerifyError::HashPrefixMismatch)
    );
    // The third reading, where a lone CR ends a line, is not followed.
    let lone = forge::read(&key.sign(SignatureType::TEXT, CREATED).over(b"a\r\nb"));
    assert_eq!(
        lone.verify(key.public(), Subject::Document(b"a\rb")),
        Err(VerifyError::HashPrefixMismatch)
    );
    assert_eq!(
        lone.verify(key.public(), Subject::Document(b"a\nb")),
        Ok(())
    );
}

/// A document hashed in pieces verifies exactly as it does whole: cut at
/// every point, checked against every key, for GnuPG's binary and text
/// signatures and RFC 9580's version 6 text signature.
#[test]
fn a_document_hashed_in_pieces() {
    let gnupg = only_certificate(&vector_bytes("gnupg/ed25519-signing.pgp"));
    let a3 = only_certificate(&dearmor(A3_CERTIFICATE));
    let keys = [gnupg.primary(), gnupg.subkeys()[0].key(), a3.primary()];
    let document = vector_bytes("gnupg/document.txt");
    let a6_lf = A6_TEXT.replace("\r\n", "\n");
    let cases = [
        (vector_bytes("gnupg/binary.sig"), &document[..]),
        (vector_bytes("gnupg/text.sig"), &document[..]),
        (dearmor(A6_SIGNATURE), a6_lf.as_bytes()),
        (dearmor(A6_SIGNATURE), b"another text"),
    ];
    let mut verified = 0;
    for (data, document) in &cases {
        let signature = Signature::from_packet(&only_packet(data)).unwrap();
        let whole: Vec<_> = keys
            .iter()
            .map(|key| signature.verify(key, Subject::Document(document)))
            .collect();
        verified += whole.iter().filter(|result| result.is_ok()).count();
        for cut in 0..=document.len() {
            let mut hash = signature.document_hash().unwrap();
            assert_eq!(hash.signature(), &signature);
            hash.update(&document[..cut]);
            hash.update(&document[cut..]);
            for (key, whole) in keys.iter().zip(&whole) {
                assert_eq!(&hash.verify(key), whole, "cut at {cut}");
            }
        }
        // One octet at a time, and verified twice: verifying does not
        // consume the hash, and hashing more changes what it verifies.
        let mut hash = signature.document_hash().unwrap();
        for octet in document.iter() {
            hash.update(&[*octet]);
        }
        for (key, whole) in keys.iter().zip(&whole) {
            assert_eq!(&hash.verify(key), whole);
            assert_eq!(&hash.verify(key), whole);
        }
        hash.update(b"more");
        assert!(keys.iter().all(|key| hash.verify(key).is_err()));
    }
    assert_eq!(verified, 3);

    // The refusals made before any hashing: a signature that is not over a
    // document, and one whose hash irongall does not implement.
    let body = only_packet(&vector_bytes("gnupg/binary.sig"))
        .body()
        .to_vec();
    for (offset, value, expected) in [
        (1, 0x13, VerifyError::WrongSubject),
        (1, 0x02, VerifyError::UnsupportedType),
        (
            3,
            HashAlgorithm::RIPEMD160.number(),
            VerifyError::UnsupportedHash,
        ),
    ] {
        let mut changed = body.clone();
        changed[offset] = value;
        let signature = signature_of(&changed);
        assert_eq!(signature.document_hash().err(), Some(expected));
    }
}

/// An Ed25519 signature over a hash shorter than 256 bits, made by the key:
/// `verify` refuses it, as RFC 9580 §5.2.3.3 and §5.2.3.4 require, whether
/// the document is hashed whole or in pieces, while the check of which key
/// made it attributes it to the key that did, and to no other. GnuPG made
/// the first, over SHA2-224, and the forge the rest.
#[test]
fn a_hash_too_short_for_ed25519_is_attributed_but_does_not_verify() {
    let document = vector_bytes("gnupg/document.txt");
    let gnupg = only_certificate(&vector_bytes("gnupg/short-hash.pgp"));
    let mut cases = vec![(
        Signature::from_packet(&only_packet(&vector_bytes("gnupg/sha224.sig"))).unwrap(),
        gnupg.primary().clone(),
        gnupg.subkeys()[0].key().clone(),
    )];
    let created = 1_700_000_000;
    for version in [Version::V4, Version::V6] {
        let key = forge::Key::ed25519(1, version, created);
        let other = forge::Key::ed25519(2, version, created);
        let hashes = match version {
            Version::V4 => &[
                HashAlgorithm::SHA1,
                HashAlgorithm::SHA224,
                HashAlgorithm::SHA256,
            ][..],
            _ => &[HashAlgorithm::SHA224, HashAlgorithm::SHA256],
        };
        for &hash in hashes {
            let signature = key
                .sign(SignatureType::BINARY, created)
                .hash(hash)
                .over_document(&document);
            cases.push((
                forge::read(&signature),
                key.public().clone(),
                other.public().clone(),
            ));
        }
    }
    let mut short = 0;
    for (signature, key, other) in &cases {
        let algorithm = signature.hash_algorithm();
        let too_short = signature.hash_too_short();
        assert_eq!(
            too_short,
            algorithm.digest_length() < Some(32),
            "{algorithm}"
        );
        let expected = if too_short {
            Err(VerifyError::HashTooShort)
        } else {
            Ok(())
        };
        let subject = Subject::Document(&document);
        assert_eq!(signature.verify(key, subject), expected, "{algorithm}");
        let mut hash = signature.document_hash().unwrap();
        hash.update(&document);
        assert_eq!(hash.verify(key), expected, "{algorithm}");
        assert_eq!(hash.checks().made_by(key), Ok(()), "{algorithm}");
        assert_eq!(
            hash.checks().made_by(other),
            Err(VerifyError::BadSignature),
            "{algorithm}"
        );
        short += usize::from(too_short);
    }
    assert_eq!(short, 4);

    // An RSA signature over SHA-1 rests on a hash its algorithm allows.
    let rsa = forge::Key::rsa(Version::V4, created);
    let signature = forge::read(
        &rsa.sign(SignatureType::BINARY, created)
            .hash(HashAlgorithm::SHA1)
            .over_document(&document),
    );
    assert!(!signature.hash_too_short());
    assert_eq!(
        signature.verify(rsa.public(), Subject::Document(&document)),
        Ok(())
    );
}

/// Checking a primary key's statements one after another answers as
/// `verify` does, over every kind of part a statement may be over and every
/// part of that kind, except that a hash too short for an Ed25519 signature
/// is attributed rather than refused. Its key hashed once for each hash
/// algorithm, a version 4 check hashes what follows the key, and the count
/// it gives of what it hashes is exact. Checked by the equation alone, a
/// statement is found over the same part whatever its hash prefix.
#[test]
fn a_primary_keys_statements_are_checked_as_verify_checks_them() {
    let created = 1_700_000_000;
    let mut primaries = vec![forge::Key::rsa(Version::V4, created)];
    for version in [Version::V4, Version::V6] {
        primaries.push(forge::Key::ed25519(1, version, created));
    }
    let mut cases = 0;
    for primary in &primaries {
        let version = primary.public().version();
        let subkeys = [2, 3].map(|seed| forge::Key::ed25519(seed, version, created));
        let user_ids = ["archive", "other"];
        let mut hashes = vec![HashAlgorithm::SHA256, HashAlgorithm::SHA512];
        hashes.push(match version {
            Version::V4 => HashAlgorithm::SHA1,
            Version::V6 => HashAlgorithm::SHA224,
        });
        let mut statements = Vec::new();
        for &hash in &hashes {
            let sign = |signature_type| primary.sign(signature_type, created).hash(hash);
            // Each with the index of the part it is over, in `parts`.
            statements.extend([
                (sign(SignatureType::DIRECT_KEY).over_key(primary), 0),
                (
                    sign(SignatureType::CERTIFICATION_REVOCATION).over_key(primary),
                    0,
                ),
                (
                    sign(SignatureType::POSITIVE_CERTIFICATION).over_user_id(primary, user_ids[0]),
                    1,
                ),
                (
                    sign(SignatureType::CERTIFICATION_REVOCATION)
                        .over_user_id(primary, user_ids[1]),
                    2,
                ),
                (
                    sign(SignatureType::SUBKEY_BINDING).over_subkey(primary, &subkeys[0]),
                    3,
                ),
                (
                    sign(SignatureType::SUBKEY_REVOCATION).over_subkey(primary, &subkeys[1]),
                    4,
                ),
            ]);
        }
        let key = primary.public();
        let parts = [
            (Over::Key, Subject::Key(key)),
            (
                Over::UserId(user_ids[0].as_bytes()),
                Subject::UserId {
                    key,
                    user_id: user_ids[0].as_bytes(),
                },
            ),
            (
                Over::UserId(user_ids[1].as_bytes()),
                Subject::UserId {
                    key,
                    user_id: user_ids[1].as_bytes(),
                },
            ),
            (
                Over::Subkey(subkeys[0].public()),
                Subject::Subkey {
                    primary: key,
                    subkey: subkeys[0].public(),
                },
            ),
            (
                Over::Subkey(subkeys[1].public()),
                Subject::Subkey {
                    primary: key,
                    subkey: subkeys[1].public(),
                },
            ),
        ];
        let mut shared = PrimaryChecks::new(key);
        let mut hashed_once = Vec::new();
        let mut verified = 0;
        for (statement, over_part) in &statements {
            let signature = forge::read(statement);
            assert!(shared.may_have_made(&signature));
            for (part, (over, subject)) in parts.into_iter().enumerate() {
                // `verify` refuses a hash too short before it hashes the
                // subject, and the check of who made it does not.
                let expected = match signature.verify(key, subject) {
                    Err(VerifyError::HashTooShort) if part == *over_part => Ok(()),
                    Err(VerifyError::HashTooShort) => Err(VerifyError::HashPrefixMismatch),
                    verdict => verdict,
                };
                assert_eq!(expected.is_ok(), part == *over_part);
                assert_eq!(PrimaryChecks::new(key).made_by(&signature, over), expected);
                let (made, work) = work::of(|| shared.made_by(&signature, over));
                assert_eq!(made, expected);
                if expected != Err(VerifyError::WrongSubject) {
                    let mut cost = shared.cost(&signature, over);
                    let algorithm = signature.hash_algorithm();
                    if version == Version::V4 && !hashed_once.contains(&algorithm) {
                        hashed_once.push(algorithm);
                        cost += hashed_key(key.body()).len();
                    }
                    assert_eq!(work.hashed, cost as u64);
                }
                verified += usize::from(made.is_ok());

                // By the equation alone, the statement is found over the
                // same part, and with its hash prefix inverted, which no
                // signature covers, it is still found there, the prefix
                // reported. Every check that hashes performs the equation.
                let inverted = forge::read(&forge::with_prefix_inverted(statement));
                for (signature, prefix) in
                    [(&signature, Prefix::Matches), (&inverted, Prefix::Differs)]
                {
                    let (made, work) =
                        work::of(|| PrimaryChecks::new(key).made_by_equation(signature, over));
                    let expected = match expected {
                        Ok(()) => Ok(prefix),
                        Err(VerifyError::WrongSubject) => Err(VerifyError::WrongSubject),
                        Err(_) => Err(VerifyError::BadSignature),
                    };
                    assert_eq!(made, expected, "{part}");
                    assert_eq!(
                        work.operations,
                        u64::from(expected != Err(VerifyError::WrongSubject))
                    );
                }
                let expected = match expected {
                    Err(VerifyError::WrongSubject) => Err(VerifyError::WrongSubject),
                    _ => Err(VerifyError::HashPrefixMismatch),
                };
                assert_eq!(shared.made_by(&inverted, over), expected);
                cases += 1;
            }
        }
        assert_eq!(verified, statements.len());
        if version == Version::V4 {
            assert_eq!(hashed_once.len(), hashes.len());
        }
        // Another key's signature over the primary key: one of another
        // algorithm is not one the primary key may have made, and one of
        // its algorithm fails by its equation.
        let other = forge::Key::ed25519(9, version, created);
        let foreign = forge::read(
            &other
                .sign(SignatureType::DIRECT_KEY, created)
                .over_key(primary),
        );
        assert_eq!(
            shared.may_have_made(&foreign),
            primary.public().algorithm() == other.public().algorithm()
        );
        assert_eq!(
            shared.made_by(&foreign, Over::Key),
            Err(
                match primary.public().algorithm() == other.public().algorithm() {
                    true => VerifyError::BadSignature,
                    false => VerifyError::AlgorithmMismatch,
                }
            )
        );
    }
    assert_eq!(cases, 3 * 18 * 5);
}
