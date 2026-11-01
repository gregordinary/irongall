//! Certificates GnuPG generated, assembled by irongall, with every signature
//! verified and the verdicts held to GnuPG's own, `gpg --check-signatures`
//! (`tests/vectors/gnupg`).

use std::fs;
use std::path::Path;

use irongall::cert::{self, Certificate};
use irongall::packet::PacketErrorKind;
use irongall::signature::{Signature, SignatureType, Subject, VerifyError};

/// A signature as `gpg --check-signatures --with-colons` lists it.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Checked {
    signature_type: u8,
    creation_time: u32,
    /// Whether GnuPG found it good.
    good: bool,
}

/// The signatures of a check listing, by what they are over: those over the
/// primary key, then those over each user ID and each subkey, in the order of
/// the certificate.
fn checked(listing: &str) -> Vec<Vec<Checked>> {
    let mut parts = vec![Vec::new()];
    for line in listing.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        match fields[0] {
            "uid" | "sub" => parts.push(Vec::new()),
            "sig" | "rev" => {
                let good = match fields[1] {
                    "!" => true,
                    "-" => false,
                    other => panic!("an unexpected verdict {other:?}: {line}"),
                };
                let class = fields[10].split(',').next().unwrap();
                parts.last_mut().unwrap().push(Checked {
                    signature_type: u8::from_str_radix(&class[..2], 16).unwrap(),
                    creation_time: fields[5].parse().unwrap(),
                    good,
                });
            }
            _ => {}
        }
    }
    parts
}

/// What irongall makes of each signature over each part of the certificate,
/// verified with the primary key, in the shape [`checked`] gives GnuPG's
/// verdicts. A signature irongall has no verdict on is left out and counted.
///
/// An Ed25519 signature over a hash shorter than 256 bits, which RFC 9580
/// forbids a verifier to accept and GnuPG accepts, is left out too, and
/// listed in `short` with its part, in the shape GnuPG lists a good one.
fn verified(
    certificate: &Certificate,
    unsupported: &mut usize,
    short: &mut Vec<(usize, Checked)>,
) -> Vec<Vec<Checked>> {
    let primary = certificate.primary();
    let mut parts = Vec::new();
    let mut part = |signatures: &[Signature], subject: Subject<'_>| {
        let mut verdicts = Vec::new();
        for signature in signatures {
            let checked = |good| Checked {
                signature_type: signature.signature_type().number(),
                creation_time: signature.creation_time(),
                good,
            };
            let good = match signature.verify(primary, subject) {
                Ok(()) => true,
                Err(VerifyError::BadSignature | VerifyError::HashPrefixMismatch) => false,
                Err(VerifyError::UnsupportedAlgorithm) => {
                    *unsupported += 1;
                    continue;
                }
                Err(VerifyError::HashTooShort) => {
                    short.push((parts.len(), checked(true)));
                    continue;
                }
                Err(other) => panic!("an unexpected refusal: {other}"),
            };
            verdicts.push(checked(good));
        }
        parts.push(verdicts);
    };
    part(certificate.primary_signatures(), Subject::Key(primary));
    for user_id in certificate.user_ids() {
        let subject = Subject::UserId {
            key: primary,
            user_id: user_id.value(),
        };
        part(user_id.signatures(), subject);
    }
    for subkey in certificate.subkeys() {
        let subject = Subject::Subkey {
            primary,
            subkey: subkey.key(),
        };
        part(subkey.signatures(), subject);
    }
    parts
}

#[test]
fn verdicts_agree_with_gnupg() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/gnupg");
    let (mut agreed, mut unsupported, mut short, mut refused) = (0, 0, 0, 0);
    for name in [
        "rsa",
        "dsa",
        "ed25519",
        "nistp256",
        "brainpoolp256r1",
        "ed448",
        "ed25519-signing",
        "lifecycle",
        "documents",
        "extended",
        "textmode",
        "revoked-sha1",
        "short-hash",
        "expired",
    ] {
        let data = fs::read(directory.join(format!("{name}.pgp"))).unwrap();
        let listing = fs::read_to_string(directory.join(format!("{name}.checks"))).unwrap();
        let [certificate] = <[_; 1]>::try_from(cert::certificates(&data).collect::<Vec<_>>())
            .unwrap_or_else(|all| panic!("{name}: {} certificates", all.len()));
        let certificate = match certificate {
            Ok(certificate) => certificate,
            // GnuPG's Ed448 keys are version 5, which irongall does not read.
            Err(error) => {
                assert_eq!(name, "ed448");
                assert_eq!(error.kind(), PacketErrorKind::UnsupportedVersion);
                refused += 1;
                continue;
            }
        };
        assert!(certificate.skipped().is_empty(), "{name}");

        let before = unsupported;
        let mut too_short = Vec::new();
        let ours = verified(&certificate, &mut unsupported, &mut too_short);
        let mut theirs = checked(&listing);
        assert_eq!(ours.len(), theirs.len(), "{name}");
        // GnuPG found good each signature irongall refuses for its short
        // hash.
        for (part, signature) in &too_short {
            let listed = &mut theirs[*part];
            let at = listed.iter().position(|checked| checked == signature);
            listed.remove(at.unwrap_or_else(|| panic!("{name}: {signature:?}")));
        }
        short += too_short.len();
        for (mut ours, mut theirs) in ours.into_iter().zip(theirs) {
            if unsupported > before {
                // irongall verifies none of the certificate's signatures.
                assert!(ours.is_empty(), "{name}");
                continue;
            }
            ours.sort();
            theirs.sort();
            agreed += theirs.len();
            assert_eq!(ours, theirs, "{name}");
        }
    }
    assert_eq!(
        (agreed, unsupported, short, refused),
        (24, 6, 2, 1),
        "verdicts agreed, signatures irongall does not verify, signatures over a hash too short \
         for their algorithm, certificates refused"
    );
}

/// The certificate whose life GnuPG recorded: a revoked user ID, a revoked
/// subkey, a designated revoker, and the key's revocation, each placed where
/// it belongs, and the signing subkey's back-signature verified with the
/// subkey.
#[test]
fn a_revoked_certificate() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/gnupg");
    let data = fs::read(directory.join("lifecycle.pgp")).unwrap();
    let certificate = cert::certificates(&data).next().unwrap().unwrap();
    let types = |signatures: &[Signature]| -> Vec<SignatureType> {
        signatures.iter().map(Signature::signature_type).collect()
    };
    assert_eq!(
        types(certificate.primary_signatures()),
        [SignatureType::KEY_REVOCATION, SignatureType::DIRECT_KEY]
    );
    let [first, second] = certificate.user_ids() else {
        panic!("two user IDs");
    };
    assert_eq!(
        types(first.signatures()),
        [SignatureType::POSITIVE_CERTIFICATION]
    );
    assert_eq!(
        types(second.signatures()),
        [
            SignatureType::CERTIFICATION_REVOCATION,
            SignatureType::POSITIVE_CERTIFICATION
        ]
    );
    let [signing, encryption] = certificate.subkeys() else {
        panic!("two subkeys");
    };
    assert_eq!(
        types(encryption.signatures()),
        [
            SignatureType::SUBKEY_REVOCATION,
            SignatureType::SUBKEY_BINDING
        ]
    );

    let primary = certificate.primary();
    let [binding] = signing.signatures() else {
        panic!("one binding");
    };
    let subject = Subject::Subkey {
        primary,
        subkey: signing.key(),
    };
    let [back] = binding.embedded_signatures() else {
        panic!("one back-signature");
    };
    assert_eq!(back.signature_type(), SignatureType::PRIMARY_KEY_BINDING);
    assert_eq!(back.verify(signing.key(), subject), Ok(()));
    assert_eq!(
        back.verify(primary, subject),
        Err(VerifyError::BadSignature)
    );
    // Each revocation is over its own part only.
    let revocation = &second.signatures()[0];
    let other = Subject::UserId {
        key: primary,
        user_id: first.value(),
    };
    assert_eq!(
        revocation.verify(primary, other),
        Err(VerifyError::HashPrefixMismatch)
    );
}
