//! Cleartext signed messages and detached signature files over arbitrary
//! input: no panic, a message's text in the form its signatures are made
//! over it, only signatures over a document kept, and every signature given
//! the same verdict over its document whole and hashed in two pieces.

#![no_main]

use std::sync::LazyLock;

use irongall::document;
use irongall::key::PublicKey;
use irongall::signature::{Signature, SignatureType, Subject};
use irongall::{armor, cert};
use libfuzzer_sys::fuzz_target;

/// Keys of every algorithm irongall verifies with: the version 4 EdDSALegacy
/// primary key and RSA subkey GnuPG made the document vectors with, and the
/// version 6 Ed25519 primary key of RFC 9580 Appendix A.3.
static KEYS: LazyLock<Vec<PublicKey>> = LazyLock::new(|| {
    let a3 = armor::decode(A3_CERTIFICATE.as_bytes()).unwrap().into_data();
    let gnupg = include_bytes!("../../tests/vectors/gnupg/documents.pgp");
    let mut keys = Vec::new();
    for data in [&gnupg[..], &a3] {
        let certificate = cert::certificates(data).next().unwrap().unwrap();
        keys.push(certificate.primary().clone());
        keys.extend(certificate.subkeys().iter().map(|subkey| subkey.key().clone()));
    }
    keys
});

/// The version 6 certificate of RFC 9580 Appendix A.3.
const A3_CERTIFICATE: &str = "\
-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----
";

/// Verifies each signature over `document` with every key, whole and in two
/// pieces cut where `cut` says, and checks the verdicts agree.
fn check(signatures: &[Signature], types: &[SignatureType], document: &[u8], cut: usize) {
    let (head, tail) = document.split_at(cut % (document.len() + 1));
    for signature in signatures {
        assert!(types.contains(&signature.signature_type()));
        let mut hash = signature.document_hash().ok();
        if let Some(hash) = &mut hash {
            hash.update(head);
            hash.update(tail);
        }
        for key in KEYS.iter() {
            let whole = signature.verify(key, Subject::Document(document));
            if let Some(hash) = &hash {
                assert_eq!(hash.verify(key), whole);
            }
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let cut = input.len() / 3;
    if let Ok(message) = document::cleartext(input) {
        // The text is lines joined by CR LF, none holding an LF or ending in
        // a space, a tab, or a CR.
        let text = message.text();
        let mut rest = text;
        loop {
            let (line, next) = match rest.windows(2).position(|pair| pair == b"\r\n") {
                Some(at) => (&rest[..at], Some(&rest[at + 2..])),
                None => (rest, None),
            };
            assert!(!line.contains(&b'\n'));
            assert!(!matches!(line.last(), Some(b' ' | b'\t' | b'\r')));
            match next {
                Some(next) => rest = next,
                None => break,
            }
        }
        check(message.signatures(), &[SignatureType::TEXT], text, cut);
    }
    if let Ok(signatures) = document::detached(input) {
        check(
            signatures.signatures(),
            &[SignatureType::BINARY, SignatureType::TEXT],
            input,
            cut,
        );
    }
});
