//! Certificates GnuPG generated, read by irongall and held to GnuPG's own
//! reading of them (`tests/vectors/gnupg`).

use std::fs;
use std::path::Path;

use irongall::key::{KeyMaterial, PublicKey};
use irongall::packet::{self, PacketErrorKind, Tag};

/// A key as `gpg --with-colons` lists it.
#[derive(Debug)]
struct Listed {
    primary: bool,
    algorithm: u8,
    creation_time: u32,
    key_id: String,
    fingerprint: String,
}

/// The keys of a colon listing, in order: each `pub` or `sub` record with
/// the `fpr` record that follows it.
fn listed(colons: &str) -> Vec<Listed> {
    let mut keys = Vec::new();
    let mut pending = None;
    for line in colons.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields[0] {
            "pub" | "sub" => pending = Some(fields),
            "fpr" => {
                if let Some(key) = pending.take() {
                    keys.push(Listed {
                        primary: key[0] == "pub",
                        algorithm: key[3].parse().unwrap(),
                        creation_time: key[5].parse().unwrap(),
                        key_id: key[4].to_string(),
                        fingerprint: fields[9].to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    keys
}

/// The shape each certificate's keys' material takes, primary first.
#[derive(Debug, PartialEq)]
enum Shape {
    /// RSA with e = 65537, and a modulus of this many octets.
    Rsa(usize),
    Ed25519,
    Opaque,
    Unsupported,
}

#[test]
fn keys_read_as_gnupg_reads_them() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/gnupg");
    let mut checked = 0;
    for (name, shapes) in [
        ("rsa", &[Shape::Rsa(256), Shape::Rsa(256)][..]),
        ("dsa", &[Shape::Opaque, Shape::Opaque]),
        ("ed25519", &[Shape::Ed25519, Shape::Opaque]),
        ("nistp256", &[Shape::Opaque, Shape::Opaque]),
        ("brainpoolp256r1", &[Shape::Opaque, Shape::Opaque]),
        // GnuPG makes Ed448 keys version 5 keys, which irongall does not read.
        ("ed448", &[Shape::Unsupported, Shape::Unsupported]),
        ("ed25519-signing", &[Shape::Ed25519, Shape::Ed25519]),
        (
            "lifecycle",
            &[Shape::Ed25519, Shape::Ed25519, Shape::Opaque],
        ),
        ("documents", &[Shape::Ed25519, Shape::Rsa(384)]),
        ("extended", &[Shape::Ed25519]),
        ("textmode", &[Shape::Ed25519]),
        ("revoked-sha1", &[Shape::Ed25519]),
        ("short-hash", &[Shape::Ed25519, Shape::Ed25519]),
        ("expired", &[Shape::Ed25519]),
    ] {
        let data = fs::read(directory.join(format!("{name}.pgp"))).unwrap();
        let colons = fs::read_to_string(directory.join(format!("{name}.colons"))).unwrap();
        let expected = listed(&colons);
        let read: Vec<_> = packet::packets(&data)
            .map(Result::unwrap)
            .filter(|packet| matches!(packet.tag(), Tag::PUBLIC_KEY | Tag::PUBLIC_SUBKEY))
            .map(|packet| {
                (
                    packet.tag() == Tag::PUBLIC_KEY,
                    PublicKey::from_packet(&packet),
                )
            })
            .collect();
        assert_eq!(read.len(), expected.len(), "{name}");
        assert_eq!(read.len(), shapes.len(), "{name}");

        for (((primary, key), listed), shape) in read.into_iter().zip(&expected).zip(shapes) {
            assert_eq!(primary, listed.primary, "{name}: {listed:?}");
            let key = match (key, shape) {
                (Err(error), Shape::Unsupported) => {
                    assert_eq!(error.kind(), PacketErrorKind::UnsupportedVersion);
                    checked += 1;
                    continue;
                }
                (key, _) => key.unwrap(),
            };
            assert_eq!(
                key.algorithm().number(),
                listed.algorithm,
                "{name}: {listed:?}"
            );
            assert_eq!(
                key.creation_time(),
                listed.creation_time,
                "{name}: {listed:?}"
            );
            assert_eq!(key.fingerprint().to_string(), listed.fingerprint, "{name}");
            assert_eq!(key.key_id().to_string(), listed.key_id, "{name}");
            let found = match key.material() {
                KeyMaterial::Rsa { modulus, exponent } => {
                    assert_eq!(exponent, &[0x01, 0x00, 0x01]);
                    Shape::Rsa(modulus.len())
                }
                KeyMaterial::Ed25519(_) => Shape::Ed25519,
                KeyMaterial::Opaque => Shape::Opaque,
                other => panic!("{name}: unexpected material {other:?}"),
            };
            assert_eq!(&found, shape, "{name}: {listed:?}");
            checked += 1;
        }
    }
    assert_eq!(checked, 25, "keys checked");
}
