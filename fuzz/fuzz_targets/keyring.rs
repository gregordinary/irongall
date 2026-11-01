//! Verification against a keyring over arbitrary input: no panic, every
//! certificate judged, and every verdict consistent with the judgement and
//! the cryptography under it. A keyring that holds every certificate twice
//! judges as the keyring does, since the copies combine into one.
//!
//! The input is a two-octet big-endian length, that many octets of keyring,
//! and a signed document: a cleartext signed message, or else detached
//! signatures over the keyring's octets.

#![no_main]

use irongall::cert::{self, Certificate};
use irongall::document;
use irongall::key::Fingerprint;
use irongall::keyring::{Keyring, Refusal};
use irongall::policy::{Authority, Policy};
use irongall::signature::{Signature, Subject};
use libfuzzer_sys::fuzz_target;

/// The time judged at: 2026-03-01 00:00:00 UTC, after the seeds were made.
const NOW: u64 = 1_772_323_200;

/// Checks a keyring's verdict on `signatures` over `document`, and returns
/// it: the fingerprints of the certificate and key that made the signature
/// accepted, or the refusal.
fn check(
    keyring: &Keyring,
    policy: &Policy,
    signatures: &[Signature],
    document: &[u8],
) -> Result<(Fingerprint, Fingerprint), Refusal> {
    let verdict = keyring.verify(policy, NOW, signatures, document);
    match &verdict {
        Ok(verified) => {
            let certificate = verified.certificate();
            assert!(keyring.certificates().contains(certificate));
            assert!(signatures.contains(verified.signature()));
            let authority = Authority::new(certificate, policy, NOW);
            let (_, standing) = authority
                .signers()
                .find(|(key, _)| *key == verified.key())
                .expect("the key is the certificate's");
            let window = standing.expect("the key may sign");
            let made = u64::from(verified.signature().creation_time());
            assert!(window.contains(made));
            assert!(window.expires().is_none_or(|expires| NOW < expires));
            assert!(made <= NOW + policy.clock_skew());
            assert!(policy.accepts_hash(verified.signature().hash_algorithm()));
            assert_eq!(
                verified
                    .signature()
                    .verify(verified.key(), Subject::Document(document)),
                Ok(())
            );
        }
        Err(refusal) => {
            if let Some(key) = refusal.key() {
                let certificate = refusal.certificate().expect("named with its key");
                assert!(keyring.certificates().iter().any(|held| {
                    held.primary().fingerprint() == certificate
                        && (held.primary().fingerprint() == key
                            || held.subkeys().iter().any(|subkey| subkey.key().fingerprint() == key))
                }));
            }
        }
    }
    verdict.map(|verified| {
        (
            verified.certificate().primary().fingerprint(),
            verified.key().fingerprint(),
        )
    })
}

fuzz_target!(|input: &[u8]| {
    let Some((length, rest)) = input.split_first_chunk::<2>() else {
        return;
    };
    let length = usize::from(u16::from_be_bytes(*length)).min(rest.len());
    let (keyring_data, document_data) = rest.split_at(length);

    let certificates: Vec<Certificate> = cert::certificates(keyring_data)
        .filter_map(Result::ok)
        .collect();
    let policy = Policy::new();
    for certificate in &certificates {
        let authority = Authority::new(certificate, &policy, NOW);
        assert_eq!(authority.signers().count(), 1 + certificate.subkeys().len());
        for (key, standing) in authority.signers() {
            if let Ok(window) = standing {
                let primary = certificate.primary().creation_time();
                assert_eq!(window.created(), key.creation_time().max(primary));
                assert!(policy.accepts_key(key));
            }
        }
    }
    let doubled = Keyring::new(certificates.iter().chain(&certificates).cloned());
    let keyring = Keyring::new(certificates);
    assert_eq!(doubled.certificates().len(), keyring.certificates().len());
    for (once, twice) in keyring.certificates().iter().zip(doubled.certificates()) {
        let standings = |certificate| {
            Authority::new(certificate, &policy, NOW)
                .signers()
                .map(|(key, standing)| (key.fingerprint(), standing))
                .collect::<Vec<_>>()
        };
        assert_eq!(standings(once), standings(twice));
    }

    let mut verdicts = Vec::new();
    for keyring in [&keyring, &doubled] {
        if let Ok(message) = document::cleartext(document_data) {
            verdicts.push(check(
                keyring,
                &policy,
                message.signatures(),
                message.text(),
            ));
        } else if let Ok(detached) = document::detached(document_data) {
            verdicts.push(check(keyring, &policy, detached.signatures(), keyring_data));
        }
    }
    if let [once, twice] = &verdicts[..] {
        assert_eq!(once, twice);
    }
});
