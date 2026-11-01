//! irongall held to rPGP, an independent implementation of RFC 9580:
//! certificates and signatures rPGP makes, the GnuPG vectors, and those
//! octets altered, each read and verified by both. What both read, they must
//! read alike, and every difference in their verdicts must be one
//! `compare::Divergence` lists.

mod compare;
mod forge;
mod make;

mod altered;
mod divergences;
mod generated;
mod gnupg;

use std::collections::BTreeMap;
use std::sync::OnceLock;

use compare::{Key, Over, Packets, Verdict};
use irongall::cert::{self, Certificate};
use make::Shape;
use pgp::composed::{KeyType, SignedSecretKey};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::types::{KeyVersion, SigningKey};

/// Every shape of certificate irongall verifies with, as rPGP makes them: each
/// algorithm at each version it exists in, with a signing subkey.
fn shapes() -> Vec<Shape> {
    let shape = |name, version, primary, signing, encryption| Shape {
        name,
        version,
        primary,
        signing,
        encryption,
    };
    vec![
        shape(
            "v4 RSA",
            KeyVersion::V4,
            KeyType::Rsa(3072),
            KeyType::Rsa(2048),
            KeyType::Rsa(2048),
        ),
        shape(
            "v4 EdDSALegacy",
            KeyVersion::V4,
            KeyType::Ed25519Legacy,
            KeyType::Ed25519Legacy,
            KeyType::ECDH(ECCCurve::Curve25519Legacy),
        ),
        shape(
            "v4 Ed25519",
            KeyVersion::V4,
            KeyType::Ed25519,
            KeyType::Ed25519,
            KeyType::X25519,
        ),
        shape(
            "v6 Ed25519",
            KeyVersion::V6,
            KeyType::Ed25519,
            KeyType::Ed25519,
            KeyType::X25519,
        ),
        shape(
            "v6 RSA",
            KeyVersion::V6,
            KeyType::Rsa(4096),
            KeyType::Rsa(3072),
            KeyType::X25519,
        ),
    ]
}

/// A certificate rPGP made, with its secret keys and its packets as both
/// read them.
struct Made {
    shape: Shape,
    secret: SignedSecretKey,
    data: Vec<u8>,
    packets: Packets,
    certificate: Certificate,
}

impl Made {
    /// The primary key and the signing subkey, each with its secret.
    fn signers(&self) -> [(&Key, &dyn SigningKey); 2] {
        let subkey = &self.certificate.subkeys()[0];
        [
            (
                paired_key(&self.packets, self.certificate.primary()),
                &*self.secret,
            ),
            (
                paired_key(&self.packets, subkey.key()),
                &*self.secret.secret_subkeys[0],
            ),
        ]
    }
}

/// A certificate of every shape, made once for every test: RSA key
/// generation takes a second or two.
fn made() -> &'static [Made] {
    static MADE: OnceLock<Vec<Made>> = OnceLock::new();
    MADE.get_or_init(|| {
        shapes()
            .into_iter()
            .zip(0..)
            .map(|(shape, seed)| {
                let secret = make::certificate(&shape, seed);
                let data = make::public(&secret);
                let packets = compare::read(&data).unwrap();
                let mut certificates = cert::certificates(&data);
                let certificate = certificates.next().unwrap().unwrap();
                assert!(certificates.next().is_none());
                Made {
                    shape,
                    secret,
                    data,
                    packets,
                    certificate,
                }
            })
            .collect()
    })
}

/// Documents whose line endings and whitespace a text signature, or the
/// cleartext framework, treats differently from a binary signature.
const DOCUMENTS: &[&str] = &[
    "",
    "one line",
    "one line\n",
    "lines\nending\nin LF\n",
    "lines\r\nending\r\nin CR LF\r\n",
    "a lone\rCR",
    "a CR at the end\r",
    "CR CR LF\r\r\n",
    "trailing spaces  \nand tabs\t\t\n",
    "- dash-led\n-\n--\n",
    "\n\n\r\n\n",
];

/// The pair `read` made of `signature`, if both read it.
fn pair<'a>(
    packets: &'a Packets,
    signature: &irongall::signature::Signature,
) -> Option<&'a compare::Signature> {
    packets
        .signatures
        .iter()
        .find(|pair| pair.irongall == *signature)
}

/// The pair `read` made of `key`.
fn paired_key<'a>(packets: &'a Packets, key: &irongall::key::PublicKey) -> &'a Key {
    packets
        .keys
        .iter()
        .find(|pair| pair.irongall == *key)
        .expect("both read every key of a certificate irongall assembles")
}

/// Counts each verdict, the signatures only one of the two read, and those
/// the two cannot be compared on; and, among packets read apart from a
/// certificate, those only one of the two read, by the divergence that
/// explains each.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tally {
    verdicts: BTreeMap<Verdict, usize>,
    unread: usize,
    incomparable: usize,
    one_sided: BTreeMap<compare::Divergence, usize>,
}

impl Tally {
    /// Counts the packets only one of the two read in `packets`.
    fn read(&mut self, packets: &Packets) {
        for &divergence in &packets.one_sided {
            *self.one_sided.entry(divergence).or_insert(0) += 1;
        }
    }

    fn add(&mut self, verdict: Option<Verdict>) {
        match verdict {
            Some(verdict) => *self.verdicts.entry(verdict).or_insert(0) += 1,
            None => self.incomparable += 1,
        }
    }

    /// Verifies `signature` with `signer` over `over` with both, where both
    /// read it.
    fn verify(&mut self, signature: Option<&compare::Signature>, signer: &Key, over: Over<'_>) {
        match signature {
            Some(signature) => self.add(compare::verify(signature, signer, over).unwrap()),
            None => self.unread += 1,
        }
    }
}

/// Verifies every signature `certificate` holds over the part it is placed
/// on, with its primary key (and each back-signature with its subkey).
fn self_signatures(certificate: &Certificate, packets: &Packets, tally: &mut Tally) {
    let primary = paired_key(packets, certificate.primary());
    for signature in certificate.primary_signatures() {
        tally.verify(pair(packets, signature), primary, Over::Key(primary));
    }
    for part in certificate.user_ids() {
        let user_id = packets
            .user_ids
            .iter()
            .find(|pair| pair.value == part.value())
            .expect("both read every user ID");
        for signature in part.signatures() {
            let over = Over::UserId {
                key: primary,
                user_id,
            };
            tally.verify(pair(packets, signature), primary, over);
        }
    }
    for subkey in certificate.subkeys() {
        let subkey_pair = paired_key(packets, subkey.key());
        let over = Over::Subkey {
            primary,
            subkey: subkey_pair,
        };
        for signature in subkey.signatures() {
            let signature = pair(packets, signature);
            tally.verify(signature, primary, over);
            if let Some(back) = signature.and_then(|signature| signature.embedded.as_deref()) {
                tally.verify(Some(back), subkey_pair, over);
            }
        }
    }
}

/// Each packet of `data` with its header, as irongall frames it.
fn framed(data: &[u8]) -> Vec<&[u8]> {
    let offsets: Vec<usize> = irongall::packet::packets(data)
        .map(|packet| packet.unwrap().offset())
        .chain([data.len()])
        .collect();
    offsets
        .windows(2)
        .map(|bounds| &data[bounds[0]..bounds[1]])
        .collect()
}

/// The signature packets of an armored cleartext message, dearmored.
fn signature_packets(data: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(data).unwrap();
    let start = text.rfind("-----BEGIN PGP SIGNATURE-----").unwrap();
    irongall::armor::decode(&text.as_bytes()[start..])
        .unwrap()
        .into_data()
}
