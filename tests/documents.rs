//! Cleartext signed messages and detached signatures GnuPG made, read by
//! irongall, with every signature verified and the verdicts held to GnuPG's
//! own, `gpg --status-fd 1 --verify` (`tests/vectors/gnupg`).

use std::fs;
use std::path::{Path, PathBuf};

use irongall::cert;
use irongall::document::{self, Cleartext};
use irongall::key::PublicKey;
use irongall::signature::{Signature, Subject};

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/gnupg")
}

/// A signature as GnuPG's `VALIDSIG` status line describes it.
#[derive(Debug, PartialEq, Eq)]
struct Valid {
    /// The fingerprint of the key that made it.
    signer: String,
    creation_time: u32,
    version: u8,
    public_key_algorithm: u8,
    hash_algorithm: u8,
    signature_type: u8,
    /// The fingerprint of the certificate's primary key.
    primary: String,
}

/// The `VALIDSIG` lines of a verification's status output, in order.
fn valid(status: &str) -> Vec<Valid> {
    status
        .lines()
        .filter_map(|line| line.strip_prefix("[GNUPG:] VALIDSIG "))
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            Valid {
                signer: fields[0].to_string(),
                creation_time: fields[2].parse().unwrap(),
                version: fields[4].parse().unwrap(),
                public_key_algorithm: fields[6].parse().unwrap(),
                hash_algorithm: fields[7].parse().unwrap(),
                signature_type: u8::from_str_radix(fields[8], 16).unwrap(),
                primary: fields[9].to_string(),
            }
        })
        .collect()
}

/// The keys of the certificate `name`, which made the documents, primary
/// first.
fn keys(name: &str) -> Vec<PublicKey> {
    let data = fs::read(directory().join(format!("{name}.pgp"))).unwrap();
    let certificate = cert::certificates(&data).next().unwrap().unwrap();
    assert!(certificate.skipped().is_empty());
    let mut keys = vec![certificate.primary().clone()];
    keys.extend(
        certificate
            .subkeys()
            .iter()
            .map(|subkey| subkey.key().clone()),
    );
    keys
}

/// What irongall makes of each signature over `document`: the key of
/// `keys` it verifies with, as GnuPG would describe it. Every signature must
/// verify with exactly one key, by its whole document and in pieces.
fn verified(signatures: &[Signature], keys: &[PublicKey], document: &[u8]) -> Vec<Valid> {
    signatures
        .iter()
        .map(|signature| {
            let mut verifying = keys
                .iter()
                .filter(|key| signature.verify(key, Subject::Document(document)).is_ok());
            let key = verifying.next().expect("a key that verifies the signature");
            assert!(verifying.next().is_none());

            let mut hash = signature.document_hash().unwrap();
            for piece in document.chunks(7) {
                hash.update(piece);
            }
            assert_eq!(hash.verify(key), Ok(()));

            Valid {
                signer: key.fingerprint().to_string(),
                creation_time: signature.creation_time(),
                version: 4,
                public_key_algorithm: signature.public_key_algorithm().number(),
                hash_algorithm: signature.hash_algorithm().number(),
                signature_type: signature.signature_type().number(),
                primary: keys[0].fingerprint().to_string(),
            }
        })
        .collect()
}

/// The text GnuPG signed: `cleartext.txt`, read as the signatures are made
/// over it.
const SIGNED_TEXT: &[u8] = b"irongall test, cleartext\r\n\
    - a line that begins with a dash\r\n\
    From the start of a line\r\n\
    trailing spaces\r\n\
    trailing tab\r\n\
    -----BEGIN PGP SIGNATURE----- inside the text\r\n\
    \r\n\
    the last line before an empty one\r\n";

#[test]
fn cleartext_verdicts_agree_with_gnupg() {
    let keys = keys("documents");
    let mut agreed = 0;
    for name in ["cleartext", "cleartext-crlf"] {
        let input = fs::read(directory().join(format!("{name}.asc"))).unwrap();
        let status = fs::read_to_string(directory().join(format!("{name}.verify"))).unwrap();
        let message: Cleartext = document::cleartext(&input).unwrap();
        assert_eq!(message.text(), SIGNED_TEXT, "{name}");
        assert!(message.skipped().is_empty(), "{name}");
        let theirs = valid(&status);
        assert_eq!(
            verified(message.signatures(), &keys, message.text()),
            theirs
        );
        agreed += theirs.len();
    }
    assert_eq!(agreed, 4, "signatures agreed");
}

#[test]
fn detached_verdicts_agree_with_gnupg() {
    let keys = keys("documents");
    let input = fs::read(directory().join("detached.asc")).unwrap();
    let status = fs::read_to_string(directory().join("detached.verify")).unwrap();
    let document = fs::read(directory().join("document.txt")).unwrap();
    let signatures = document::detached(&input).unwrap();
    assert!(signatures.skipped().is_empty());
    let theirs = valid(&status);
    assert_eq!(theirs.len(), 2, "signatures listed");
    assert_eq!(verified(signatures.signatures(), &keys, &document), theirs);
}

/// A text signature GnuPG made over a text holding the carriage returns it
/// reads otherwise than RFC 9580's line endings alone would say: before a
/// line's CR LF, and at the end, which it drops, and in the middle of a line
/// and before a space, which it keeps.
#[test]
fn text_mode_verdicts_agree_with_gnupg() {
    let keys = keys("textmode");
    let input = fs::read(directory().join("text-crs.sig")).unwrap();
    let status = fs::read_to_string(directory().join("text-crs.verify")).unwrap();
    let document = fs::read(directory().join("text-crs.txt")).unwrap();
    assert!(document.windows(3).any(|window| window == b"\r\r\n"));
    assert!(document.ends_with(b"\r"));
    let signatures = document::detached(&input).unwrap();
    assert!(signatures.skipped().is_empty());
    let theirs = valid(&status);
    assert_eq!(theirs.len(), 1, "signatures listed");
    assert_eq!(verified(signatures.signatures(), &keys, &document), theirs);
}
