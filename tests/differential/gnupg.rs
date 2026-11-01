//! The GnuPG vectors (`tests/vectors/gnupg`), read and verified by both.

use std::fs;
use std::path::{Path, PathBuf};

use irongall::packet::PacketErrorKind;
use irongall::{cert, document};
use pgp::composed::CleartextSignedMessage;
use pgp::packet::PacketHeader;
use pgp::types::Tag as RpgpTag;

use super::{Tally, self_signatures, signature_packets};
use crate::compare::{self, Divergence, Over, Packets, Verdict};

/// The GnuPG vectors' directory.
fn gnupg() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/gnupg")
}

/// A GnuPG vector, dearmored if it is armored.
fn vector(name: &str) -> Vec<u8> {
    let data = fs::read(gnupg().join(name)).unwrap();
    if name.ends_with(".asc") {
        irongall::armor::decode(&data).unwrap().into_data()
    } else {
        data
    }
}

#[test]
fn vectors() {
    // Every self-signature of every certificate.
    for (name, expected) in [
        ("rsa", &[(Verdict::Verified, 2)][..]),
        (
            "dsa",
            &[(Verdict::Diverged(Divergence::UnsupportedAlgorithm), 2)],
        ),
        ("ed25519", &[(Verdict::Verified, 2)]),
        (
            "nistp256",
            &[(Verdict::Diverged(Divergence::UnsupportedAlgorithm), 2)],
        ),
        // rPGP does not verify over brainpoolP256r1 either.
        ("brainpoolp256r1", &[(Verdict::Refused, 2)]),
        // A version 5 certificate, which irongall does not assemble.
        ("ed448", &[]),
        ("ed25519-signing", &[(Verdict::Verified, 3)]),
        ("lifecycle", &[(Verdict::Verified, 9)]),
        ("documents", &[(Verdict::Verified, 3)]),
        ("extended", &[(Verdict::Verified, 3)]),
        ("textmode", &[(Verdict::Verified, 1)]),
        // Each revoked over a hash shorter than an Ed25519 signature may
        // rest on, which both refuse.
        (
            "revoked-sha1",
            &[(Verdict::Verified, 1), (Verdict::Refused, 1)],
        ),
        (
            "short-hash",
            &[(Verdict::Verified, 3), (Verdict::Refused, 1)],
        ),
        ("expired", &[(Verdict::Verified, 1)]),
    ] {
        let data = vector(&format!("{name}.pgp"));
        let packets = compare::read(&data).unwrap();
        let mut tally = Tally::default();
        for certificate in cert::certificates(&data).filter_map(Result::ok) {
            self_signatures(&certificate, &packets, &mut tally);
        }
        let expected = Tally {
            verdicts: expected.iter().copied().collect(),
            ..Tally::default()
        };
        assert_eq!(tally, expected, "{name}");
    }

    // Every document signature, verified with every key of the certificate
    // that made it: it verifies with the key it names, and with no other.
    let mut checked = 0;
    let mut check = |packets: &Packets, certificate: &str, document: &[u8]| {
        let keys = compare::read(&vector(&format!("{certificate}.pgp")))
            .unwrap()
            .keys;
        for signature in &packets.signatures {
            for key in &keys {
                let named = signature
                    .irongall
                    .issuer_fingerprints()
                    .any(|fingerprint| fingerprint == key.irongall.fingerprint());
                let verdict = compare::verify(signature, key, Over::Document(document)).unwrap();
                let expected = if named {
                    Verdict::Verified
                } else {
                    Verdict::Refused
                };
                assert_eq!(verdict, Some(expected), "{certificate}");
                checked += 1;
            }
        }
    };
    let document = vector("document.txt");
    for (signatures, certificate) in [
        ("binary.sig", "ed25519-signing"),
        ("text.sig", "ed25519-signing"),
        ("detached.asc", "documents"),
        ("late.sig", "extended"),
        ("revoked-subkey.sig", "short-hash"),
        ("before-expiry.sig", "expired"),
    ] {
        check(
            &compare::read(&vector(signatures)).unwrap(),
            certificate,
            &document,
        );
    }
    for name in ["cleartext.asc", "cleartext-crlf.asc"] {
        let data = fs::read(gnupg().join(name)).unwrap();
        let message = document::cleartext(&data).unwrap();
        let (theirs, _) = CleartextSignedMessage::from_armor(&data[..]).unwrap();
        assert_eq!(message.text(), theirs.signed_text().as_bytes(), "{name}");
        check(
            &compare::read(&signature_packets(&data)).unwrap(),
            "documents",
            message.text(),
        );
    }
    assert_eq!(checked, 20);

    // An Ed25519 signature over SHA2-224, which both refuse with every key.
    let [signature] = &compare::read(&vector("sha224.sig")).unwrap().signatures[..] else {
        panic!("one signature")
    };
    let keys = compare::read(&vector("short-hash.pgp")).unwrap().keys;
    for key in &keys {
        assert_eq!(
            compare::verify(signature, key, Over::Document(&document)).unwrap(),
            Some(Verdict::Refused)
        );
    }

    // A text signature GnuPG made over a text holding the CRs it drops,
    // before a line's CR LF and at the end, which rPGP keeps.
    let text = vector("text-crs.txt");
    let keys = compare::read(&vector("textmode.pgp")).unwrap().keys;
    let [signature] = &compare::read(&vector("text-crs.sig")).unwrap().signatures[..] else {
        panic!("one signature")
    };
    assert_eq!(
        compare::verify(signature, &keys[0], Over::Document(&text)).unwrap(),
        Some(Verdict::Diverged(Divergence::GnuPgLineEndings))
    );

    // A signature carrying a notation marked critical, which irongall does
    // not read: RFC 9580 §5.2.3.7 has an evaluator treat an unknown critical
    // subpacket as an error. rPGP reads it, and verifies it.
    let data = vector("critical-notation.sig");
    assert!(compare::read(&data).unwrap().signatures.is_empty());
    let packet = irongall::packet::packets(&data).next().unwrap().unwrap();
    assert_eq!(
        irongall::signature::Signature::from_packet(&packet)
            .unwrap_err()
            .kind(),
        PacketErrorKind::CriticalSubpacket
    );
    let length = u32::try_from(packet.body().len()).unwrap();
    let theirs = pgp::packet::Signature::try_from_reader(
        PacketHeader::new_fixed(RpgpTag::Signature, length),
        packet.body(),
    )
    .unwrap();
    let keys = compare::read(&vector("ed25519-signing.pgp")).unwrap().keys;
    assert_eq!(
        keys.iter()
            .filter(|key| theirs.verify(&key.rpgp, &document[..]).is_ok())
            .count(),
        1
    );
}
