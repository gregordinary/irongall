//! Certificate assembly and signature verification over arbitrary input: no
//! panic, every signature placed where its type belongs, every user ID within
//! its bound and held once, every subkey of its primary key's version and
//! held once, and every signature verified, against the subject its place
//! gives it and against the input as a document, without panicking.

#![no_main]

use irongall::cert;
use irongall::signature::{Signature, SignatureType, Subject};
use libfuzzer_sys::fuzz_target;

/// Checks that every signature is of one of `types`, and verifies each with
/// `key` over `subject` and over `document`, along with the signatures it
/// embeds, by `embedded_key`.
fn check(
    signatures: &[Signature],
    types: &[SignatureType],
    key: &irongall::key::PublicKey,
    embedded_key: &irongall::key::PublicKey,
    subject: Subject<'_>,
    document: &[u8],
) {
    for signature in signatures {
        assert!(types.contains(&signature.signature_type()));
        let _ = signature.verify(key, subject);
        let _ = signature.verify(key, Subject::Document(document));
        for embedded in signature.embedded_signatures() {
            let _ = embedded.verify(embedded_key, subject);
        }
    }
}

fuzz_target!(|input: &[u8]| {
    for certificate in cert::certificates(input) {
        let certificate = match certificate {
            Ok(certificate) => certificate,
            Err(error) => {
                assert!(error.offset() <= input.len());
                continue;
            }
        };
        for skipped in certificate.skipped() {
            assert!(skipped.offset() <= input.len());
        }
        let primary = certificate.primary();
        check(
            certificate.primary_signatures(),
            &[
                SignatureType::DIRECT_KEY,
                SignatureType::KEY_REVOCATION,
                SignatureType::CERTIFICATION_REVOCATION,
            ],
            primary,
            primary,
            Subject::Key(primary),
            input,
        );
        let user_ids = certificate.user_ids();
        let subkeys = certificate.subkeys();
        for (at, user_id) in user_ids.iter().enumerate() {
            assert!(
                user_ids[..at]
                    .iter()
                    .all(|held| held.value() != user_id.value())
            );
        }
        for (at, subkey) in subkeys.iter().enumerate() {
            assert!(subkeys[..at].iter().all(|held| held.key() != subkey.key()));
        }
        for user_id in user_ids {
            assert!(user_id.value().len() <= 2048);
            check(
                user_id.signatures(),
                &[
                    SignatureType::GENERIC_CERTIFICATION,
                    SignatureType::PERSONA_CERTIFICATION,
                    SignatureType::CASUAL_CERTIFICATION,
                    SignatureType::POSITIVE_CERTIFICATION,
                    SignatureType::CERTIFICATION_REVOCATION,
                ],
                primary,
                primary,
                Subject::UserId {
                    key: primary,
                    user_id: user_id.value(),
                },
                input,
            );
        }
        for subkey in certificate.subkeys() {
            assert_eq!(subkey.key().version(), primary.version());
            check(
                subkey.signatures(),
                &[SignatureType::SUBKEY_BINDING, SignatureType::SUBKEY_REVOCATION],
                primary,
                subkey.key(),
                Subject::Subkey {
                    primary,
                    subkey: subkey.key(),
                },
                input,
            );
        }
    }
});
