//! Signatures GnuPG made, read by irongall and held to GnuPG's own reading of
//! them, `gpg --list-packets` (`tests/vectors/gnupg`).

use std::fs;
use std::path::Path;

use irongall::armor;
use irongall::packet::{self, PacketErrorKind, Tag, Version};
use irongall::signature::{Signature, SignatureMaterial, Subpacket};

/// A subpacket as `gpg --list-packets` lists it.
#[derive(Debug, PartialEq)]
struct ListedSubpacket {
    hashed: bool,
    critical: bool,
    number: u8,
    /// The length of the subpacket's data, after its type.
    length: usize,
}

/// A signature as `gpg --list-packets` lists it.
#[derive(Debug, Default)]
struct Listed {
    algorithm: u8,
    /// The issuer's key ID, which GnuPG takes from the signature's issuer
    /// subpackets.
    key_id: String,
    version: u8,
    creation_time: u32,
    signature_type: u8,
    hash_algorithm: u8,
    hash_prefix: [u8; 2],
    subpackets: Vec<ListedSubpacket>,
    /// Each embedded signature's version, type, public-key algorithm, and
    /// hash algorithm.
    embedded: Vec<[u8; 4]>,
    /// The bit length of each of the material's integers.
    integers: Vec<usize>,
}

/// The value after `prefix` in `text`, up to `end`.
fn between<'a>(text: &'a str, prefix: &str, end: &str) -> &'a str {
    let rest = &text[text.find(prefix).unwrap() + prefix.len()..];
    rest.find(end).map_or(rest, |at| &rest[..at])
}

/// The signatures of a packet listing, in order.
fn listed(listing: &str) -> Vec<Listed> {
    let mut signatures = Vec::new();
    let mut current: Option<Listed> = None;
    for line in listing.lines() {
        if let Some(rest) = line.strip_prefix(":signature packet: algo ") {
            signatures.extend(current.take());
            let (algorithm, key_id) = rest.split_once(", keyid ").unwrap();
            current = Some(Listed {
                algorithm: algorithm.parse().unwrap(),
                key_id: key_id.to_string(),
                ..Listed::default()
            });
            continue;
        }
        // Another packet ends the signature.
        if line.starts_with(':') {
            signatures.extend(current.take());
        }
        let Some(signature) = current.as_mut() else {
            continue;
        };
        let line = line.trim();
        if line.starts_with("version ") {
            signature.version = between(line, "version ", ",").parse().unwrap();
            signature.creation_time = between(line, "created ", ",").parse().unwrap();
            signature.signature_type =
                u8::from_str_radix(between(line, "sigclass 0x", ","), 16).unwrap();
        } else if line.starts_with("digest algo ") {
            signature.hash_algorithm = between(line, "digest algo ", ",").parse().unwrap();
            let prefix: Vec<u8> = between(line, "begin of digest ", "\n")
                .split(' ')
                .map(|octet| u8::from_str_radix(octet, 16).unwrap())
                .collect();
            signature.hash_prefix = prefix.try_into().unwrap();
        } else if line.contains("subpkt ") {
            let number = between(line, "subpkt ", " ").parse().unwrap();
            if number == 32 {
                let embedded = between(line, "(signature: ", ")");
                signature.embedded.push([
                    between(embedded, "v", ",").parse().unwrap(),
                    u8::from_str_radix(between(embedded, "class 0x", ","), 16).unwrap(),
                    between(embedded, "algo ", ",").parse().unwrap(),
                    between(embedded, "digest algo ", ",").parse().unwrap(),
                ]);
            }
            signature.subpackets.push(ListedSubpacket {
                hashed: line.contains("hashed subpkt"),
                critical: line.starts_with("critical "),
                number,
                length: between(line, " len ", " ").parse().unwrap(),
            });
        } else if line.starts_with("data: [") {
            let bits = between(line, "data: [", " bits]");
            signature.integers.push(bits.parse().unwrap());
        }
    }
    signatures.extend(current);
    signatures
}

/// The subpackets of an area as GnuPG lists them.
fn as_listed(subpackets: &[Subpacket], hashed: bool) -> impl Iterator<Item = ListedSubpacket> {
    subpackets.iter().map(move |subpacket| ListedSubpacket {
        hashed,
        critical: subpacket.is_critical(),
        number: subpacket.subpacket_type().number(),
        length: subpacket.body().len(),
    })
}

/// The bit length of the big-endian integer `value`.
fn bits(value: &[u8]) -> usize {
    match value.iter().position(|&octet| octet != 0) {
        Some(at) => (value.len() - at - 1) * 8 + (8 - value[at].leading_zeros() as usize),
        None => 0,
    }
}

fn version_number(version: Version) -> u8 {
    match version {
        Version::V4 => 4,
        Version::V6 => 6,
        other => panic!("unexpected version {other:?}"),
    }
}

/// The subpacket types irongall honors when they are marked critical.
const HONORED: [u8; 18] = [
    2, 3, 9, 16, 25, 27, 29, 32, 33, 11, 21, 22, 23, 24, 26, 28, 30, 39,
];

#[test]
fn signatures_read_as_gnupg_reads_them() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/gnupg");
    let (mut read, mut refused, mut unsupported) = (0, 0, 0);
    for file in [
        "rsa.pgp",
        "dsa.pgp",
        "ed25519.pgp",
        "nistp256.pgp",
        "brainpoolp256r1.pgp",
        "ed448.pgp",
        "ed25519-signing.pgp",
        "lifecycle.pgp",
        "documents.pgp",
        "extended.pgp",
        "textmode.pgp",
        "revoked-sha1.pgp",
        "short-hash.pgp",
        "expired.pgp",
        "binary.sig",
        "text.sig",
        "critical-notation.sig",
        "late.sig",
        "text-crs.sig",
        "sha224.sig",
        "revoked-subkey.sig",
        "before-expiry.sig",
        "detached.asc",
    ] {
        let mut data = fs::read(directory.join(file)).unwrap();
        if file.ends_with(".asc") {
            data = armor::decode(&data).unwrap().into_data();
        }
        let stem = file.rsplit_once('.').unwrap().0;
        let listing = fs::read_to_string(directory.join(format!("{stem}.packets"))).unwrap();
        let expected = listed(&listing);
        let signatures: Vec<_> = packet::packets(&data)
            .map(Result::unwrap)
            .filter(|packet| packet.tag() == Tag::SIGNATURE)
            .map(|packet| Signature::from_packet(&packet))
            .collect();
        assert_eq!(signatures.len(), expected.len(), "{file}");

        for (signature, listed) in signatures.into_iter().zip(&expected) {
            // GnuPG makes version 5 signatures with its Ed448 keys.
            if !matches!(listed.version, 4 | 6) {
                let error = signature.unwrap_err();
                assert_eq!(error.kind(), PacketErrorKind::UnsupportedVersion, "{file}");
                unsupported += 1;
                continue;
            }
            let critical = listed.subpackets.iter().any(|subpacket| {
                subpacket.hashed && subpacket.critical && !HONORED.contains(&subpacket.number)
            });
            if critical {
                let error = signature.unwrap_err();
                assert_eq!(error.kind(), PacketErrorKind::CriticalSubpacket, "{file}");
                refused += 1;
                continue;
            }

            let signature = signature.unwrap();
            assert_eq!(
                version_number(signature.version()),
                listed.version,
                "{file}"
            );
            assert_eq!(
                signature.signature_type().number(),
                listed.signature_type,
                "{file}"
            );
            assert_eq!(
                signature.public_key_algorithm().number(),
                listed.algorithm,
                "{file}"
            );
            assert_eq!(
                signature.hash_algorithm().number(),
                listed.hash_algorithm,
                "{file}"
            );
            assert_eq!(signature.creation_time(), listed.creation_time, "{file}");
            assert_eq!(signature.hash_prefix(), listed.hash_prefix, "{file}");

            let subpackets: Vec<_> = as_listed(signature.hashed_subpackets(), true)
                .chain(as_listed(signature.unhashed_subpackets(), false))
                .collect();
            assert_eq!(subpackets, listed.subpackets, "{file}");

            let embedded: Vec<_> = signature
                .embedded_signatures()
                .iter()
                .map(|embedded| {
                    [
                        version_number(embedded.version()),
                        embedded.signature_type().number(),
                        embedded.public_key_algorithm().number(),
                        embedded.hash_algorithm().number(),
                    ]
                })
                .collect();
            assert_eq!(embedded, listed.embedded, "{file}");

            let issuers: Vec<String> = signature
                .issuer_key_ids()
                .chain(
                    signature
                        .issuer_fingerprints()
                        .map(|fingerprint| fingerprint.key_id()),
                )
                .map(|key_id| key_id.to_string())
                .collect();
            assert!(issuers.contains(&listed.key_id), "{file}: {issuers:?}");

            match signature.material() {
                SignatureMaterial::Rsa(value) => {
                    assert_eq!([bits(value)], *listed.integers, "{file}");
                }
                SignatureMaterial::Ed25519(native) => {
                    let (r, s) = native.split_at(32);
                    assert_eq!([bits(r), bits(s)], *listed.integers, "{file}");
                }
                SignatureMaterial::Opaque => {
                    assert!(matches!(listed.algorithm, 17 | 19), "{file}");
                }
                other => panic!("{file}: unexpected material {other:?}"),
            }
            read += 1;
        }
    }
    assert_eq!(
        (read, refused, unsupported),
        (41, 1, 2),
        "signatures read, refused, and unsupported"
    );
}
