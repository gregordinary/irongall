//! Certificates, detached signatures and cleartext signed messages rPGP
//! makes, of every shape irongall verifies, read and verified by both, and
//! judged by irongall's keyring under its default policy.

use std::collections::BTreeMap;

use irongall::document;
use irongall::keyring::Keyring;
use irongall::policy::{Authority, Policy, Reason};
use pgp::composed::{CleartextSignedMessage, Deserializable as _, KeyType, SignedPublicKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::{KeyDetails as _, KeyVersion};

use super::{DOCUMENTS, Tally, made, self_signatures, signature_packets};
use crate::compare::{self, Over, Packets, Verdict};
use crate::make;

/// A time after every signature in `packets` was made, to judge them at.
///
/// rPGP stamps what it signs with its clock, so the time to judge at comes
/// from what it made rather than from a constant.
fn after(packets: &[&Packets]) -> u64 {
    let latest = packets
        .iter()
        .flat_map(|packets| &packets.signatures)
        .map(|signature| signature.irongall.creation_time())
        .max()
        .unwrap();
    u64::from(latest) + 1
}

/// Every hash algorithm rPGP signs with.
const HASHES: &[HashAlgorithm] = &[
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha224,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha3_256,
    HashAlgorithm::Sha3_512,
];

#[test]
fn certificates() {
    for made in made() {
        let name = made.shape.name;
        let certificate = &made.certificate;

        // Assembled alike.
        let theirs = SignedPublicKey::from_bytes(&made.data[..]).unwrap();
        assert_eq!(
            certificate.primary_signatures().len(),
            theirs.details.direct_signatures.len() + theirs.details.revocation_signatures.len(),
            "{name}"
        );
        assert_eq!(certificate.user_ids().len(), theirs.details.users.len());
        for (ours, theirs) in certificate.user_ids().iter().zip(&theirs.details.users) {
            assert_eq!(ours.value(), theirs.id.id());
            assert_eq!(ours.signatures().len(), theirs.signatures.len());
        }
        assert_eq!(certificate.subkeys().len(), theirs.public_subkeys.len());
        for (ours, theirs) in certificate.subkeys().iter().zip(&theirs.public_subkeys) {
            assert_eq!(
                ours.key().fingerprint().as_bytes(),
                theirs.key.fingerprint().as_bytes()
            );
            assert_eq!(ours.signatures().len(), theirs.signatures.len());
        }

        // rPGP encodes what it made as it made it.
        assert!(made.packets.keys.iter().all(|key| !key.reencoded), "{name}");
        assert!(
            made.packets
                .signatures
                .iter()
                .all(|signature| !signature.reencoded),
            "{name}"
        );

        // Every self-signature verifies under both: two certifications, two
        // bindings and a back-signature, and a direct-key signature in v6.
        let mut tally = Tally::default();
        self_signatures(certificate, &made.packets, &mut tally);
        let expected = match made.shape.version {
            KeyVersion::V6 => 6,
            _ => 5,
        };
        assert_eq!(
            tally,
            Tally {
                verdicts: BTreeMap::from([(Verdict::Verified, expected)]),
                ..Tally::default()
            },
            "{name}"
        );

        // And the policy grants what rPGP meant: the primary key and the
        // signing subkey may sign, the encryption subkey may not.
        let now = after(&[&made.packets]);
        let authority = Authority::new(certificate, &Policy::new(), now);
        let standings: Vec<_> = authority
            .signers()
            .map(|(_, standing)| standing.map(|window| window.created()))
            .collect();
        let encryption = match made.shape.encryption {
            // Encryption keys of algorithms irongall does not read are
            // refused before their bindings are.
            KeyType::Rsa(_) => Reason::SubkeyMayNotSign,
            _ => Reason::WeakSubkey,
        };
        assert_eq!(
            standings,
            [Ok(make::CREATED), Ok(make::CREATED), Err(encryption)],
            "{name}"
        );
    }
}

/// Whether rPGP's text signer hashes `document` other than as RFC 9580
/// §5.2.1.2 says: it ends the text with CR LF where the document ends in a
/// lone CR. rPGP's verifier then refuses what its signer made, as irongall
/// does.
fn final_cr_becomes_line_ending(document: &str) -> bool {
    document.ends_with('\r')
}

#[test]
fn detached_signatures() {
    let policy = Policy::new();
    let mut seed = 1000;
    for made in made() {
        let name = made.shape.name;
        let keyring = Keyring::new([made.certificate.clone()]);
        let mut tally = Tally::default();
        for (signer, secret) in made.signers() {
            for &hash in HASHES {
                for text in [false, true] {
                    for document in DOCUMENTS {
                        seed += 1;
                        let case = format!("{name}, {hash:?}, text {text}, {document:?}");
                        let Some(data) =
                            make::detached(secret, hash, text, document.as_bytes(), seed)
                        else {
                            // rPGP makes no Ed25519 signature over a hash
                            // shorter than 256 bits (RFC 9580 §5.2.3.4), and no
                            // version 6 signature over SHA-1, which has no
                            // salt size (Table 23).
                            let ed25519 = matches!(
                                made.shape.signing,
                                KeyType::Ed25519 | KeyType::Ed25519Legacy
                            );
                            let refused = match hash {
                                HashAlgorithm::Sha1 => {
                                    ed25519 || made.shape.version == KeyVersion::V6
                                }
                                HashAlgorithm::Sha224 => ed25519,
                                _ => false,
                            };
                            assert!(refused, "{case}: rPGP refused to sign");
                            continue;
                        };
                        let packets = compare::read(&data).unwrap();
                        let [signature] = &packets.signatures[..] else {
                            panic!("{case}: one signature")
                        };
                        let over = Over::Document(document.as_bytes());
                        let verdict = compare::verify(signature, signer, over).unwrap();
                        tally.add(verdict);
                        let expected = if text && final_cr_becomes_line_ending(document) {
                            // Made over the document as if it ended in a
                            // line ending.
                            let with_lf = format!("{document}\n");
                            let over = Over::Document(with_lf.as_bytes());
                            let verdict = compare::verify(signature, signer, over).unwrap();
                            assert_eq!(verdict, Some(Verdict::Verified), "{case}");
                            Verdict::Refused
                        } else {
                            Verdict::Verified
                        };
                        assert_eq!(verdict, Some(expected), "{case}");

                        // Through the keyring, under the default policy.
                        let detached = document::detached(&data).unwrap();
                        let now = after(&[&made.packets, &packets]);
                        let verdict = keyring
                            .verify(&policy, now, detached.signatures(), document.as_bytes())
                            .map(|verified| verified.key().fingerprint())
                            .map_err(|refusal| refusal.reason());
                        let expected = if expected != Verdict::Verified {
                            Err(Reason::Unverified)
                        } else if hash == HashAlgorithm::Sha1 {
                            Err(Reason::WeakHash)
                        } else {
                            Ok(signer.irongall.fingerprint())
                        };
                        assert_eq!(verdict, expected, "{case}");
                    }
                }
            }
        }
        assert!(tally.verdicts.contains_key(&Verdict::Verified), "{name}");
    }
}

/// Whether rPGP's cleartext signer hashes `text` with what the cleartext
/// form cannot carry: a line ending in a space or a tab, which RFC 9580 §7.2
/// removes before hashing, or a final CR, which joins the line ending before
/// the signature. rPGP's own reader then refuses what its signer made, as
/// irongall does.
fn signer_keeps_whitespace(text: &str) -> bool {
    text.ends_with('\r')
        || text.split('\n').any(|line| {
            line.strip_suffix('\r')
                .unwrap_or(line)
                .ends_with([' ', '\t'])
        })
}

/// Whether a line of `text` ends in a CR before its CR LF. irongall's
/// cleartext reader removes it, as GnuPG's does; rPGP keeps it.
fn cr_before_line_ending(text: &str) -> bool {
    text.split('\n').any(|line| {
        line.strip_suffix('\r')
            .is_some_and(|line| line.ends_with('\r'))
    })
}

#[test]
fn cleartext_messages() {
    let policy = Policy::new();
    let mut seed = 2000;
    for made in made() {
        let name = made.shape.name;
        let keyring = Keyring::new([made.certificate.clone()]);
        for (signer, secret) in made.signers() {
            for document in DOCUMENTS {
                seed += 1;
                let case = format!("{name}, {document:?}");
                let data = make::cleartext(secret, document, seed);
                let message = document::cleartext(&data).unwrap();
                let (theirs, _) = CleartextSignedMessage::from_armor(&data[..]).unwrap();
                let packets = compare::read(&signature_packets(&data)).unwrap();
                let [signature] = &packets.signatures[..] else {
                    panic!("{case}: one signature")
                };
                assert_eq!(
                    message.signatures(),
                    std::slice::from_ref(&signature.irongall)
                );

                // The text the signatures are over, as each reads it.
                let text = String::from_utf8(message.text().to_vec()).unwrap();
                if cr_before_line_ending(document) {
                    assert_eq!(
                        text,
                        theirs.signed_text().replace("\r\r\n", "\r\n"),
                        "{case}"
                    );
                } else {
                    assert_eq!(text, theirs.signed_text(), "{case}");
                }

                let verdict = compare::verify(signature, signer, Over::Document(text.as_bytes()));
                let now = after(&[&made.packets, &packets]);
                let accepted = keyring
                    .verify(&policy, now, message.signatures(), message.text())
                    .map(|verified| verified.key().fingerprint())
                    .map_err(|refusal| refusal.reason());
                let rpgp_accepts_its_own = theirs.verify(&signer.rpgp).is_ok();
                if signer_keeps_whitespace(document) {
                    assert_eq!(verdict.unwrap(), Some(Verdict::Refused), "{case}");
                    assert_eq!(accepted, Err(Reason::Unverified), "{case}");
                    assert!(!rpgp_accepts_its_own, "{case}");
                } else if cr_before_line_ending(document) {
                    assert_eq!(verdict.unwrap(), Some(Verdict::Refused), "{case}");
                    assert_eq!(accepted, Err(Reason::Unverified), "{case}");
                    assert!(rpgp_accepts_its_own, "{case}");
                } else {
                    assert_eq!(verdict.unwrap(), Some(Verdict::Verified), "{case}");
                    assert_eq!(accepted, Ok(signer.irongall.fingerprint()), "{case}");
                    assert!(rpgp_accepts_its_own, "{case}");
                }
            }
        }
    }
}
