//! Holds what reading input allocates to the factors SECURITY.md states, on
//! a 64-bit target: a document is held in at most [`DOCUMENT`] times its
//! size, and a keyring in at most [`KEYRING`] times its size once it is a
//! `Keyring`, and [`KEYRING_WHILE_COMBINED`] times while its certificates
//! are combined into one. Judging a certificate read, as
//! `Keyring::verify` does with the certificate of a key that made a
//! signature, allocates at most [`JUDGEMENT`] times the certificate's size
//! besides.
//!
//! Each case packs its input with the smallest of one thing a document or a
//! keyring can hold many of: signatures, subpackets, embedded signatures,
//! armor headers, certificates, user IDs, subkeys, and the signatures over
//! each part of a certificate. Each runs at a power of two and one past it,
//! since a list that grows by doubling holds the most room it does not use
//! just past one. What is counted is the octets requested of the allocator
//! (see [`Counting`]), and each case checks that the input read as it was
//! made to, so that a case cannot pass by reading nothing.

use std::process::ExitCode;

use irongall::keyring::Keyring;
use irongall::policy::{Authority, Policy};
use irongall::{cert, document};
use irongall_memory::{Counting, Measured};

#[global_allocator]
static ALLOCATOR: Counting = Counting::new();

/// The most a document, binary or armored, is held in while it is read and
/// once it is, as a multiple of its size.
const DOCUMENT: usize = 9;

/// The most a keyring is held in once its certificates are a `Keyring`, as
/// a multiple of its size.
const KEYRING: usize = 22;

/// The most a keyring is held in while its certificates are combined into a
/// `Keyring`, as a multiple of its size: the list that gathers them grows by
/// doubling, before it is held at its length.
const KEYRING_WHILE_COMBINED: usize = 44;

/// The most judging a certificate allocates, while it judges and once it
/// has, as a multiple of the certificate's size.
const JUDGEMENT: usize = 6;

/// The power of two each case packs its input with that many of, or one
/// more.
const COUNT: usize = 1 << 15;

/// What a case reads, or judges.
#[derive(Clone, Copy)]
enum Kind {
    Document,
    Keyring,
    Judgement,
}

impl Kind {
    /// The most held once read, and while being read, as multiples of the
    /// input's size.
    fn bounds(self) -> (usize, usize) {
        match self {
            Kind::Document => (DOCUMENT, DOCUMENT),
            Kind::Keyring => (KEYRING, KEYRING_WHILE_COMBINED),
            Kind::Judgement => (JUDGEMENT, JUDGEMENT),
        }
    }
}

/// A case: what it packs its input with, what reads it, and the case
/// itself, which makes the input of `count` items, reads it, checks what it
/// read, and returns the input's length and what reading it allocated.
type Case = (&'static str, Kind, fn(usize) -> (usize, Measured));

const CASES: &[Case] = &[
    (
        "one signature, its unhashed area the smallest subpackets",
        Kind::Document,
        subpackets,
    ),
    (
        "the smallest signatures",
        Kind::Document,
        smallest_signatures,
    ),
    (
        "signatures each embedding the smallest signature",
        Kind::Document,
        each_embedding_one,
    ),
    (
        "one signature, its unhashed area the smallest embedded signatures",
        Kind::Document,
        embedded_signatures,
    ),
    ("armor headers of no value", Kind::Document, armor_headers),
    (
        "a cleartext message's lines of one character",
        Kind::Document,
        cleartext_lines,
    ),
    (
        "Signature packets that do not read",
        Kind::Document,
        unread_signatures,
    ),
    ("the smallest certificates", Kind::Keyring, certificates),
    (
        "certificates each with an empty user ID",
        Kind::Keyring,
        certificates_with_user_ids,
    ),
    (
        "certificates each with the smallest subkey",
        Kind::Keyring,
        certificates_with_subkeys,
    ),
    (
        "copies of one certificate, each with a user ID of its own",
        Kind::Keyring,
        copies,
    ),
    ("one certificate's smallest subkeys", Kind::Keyring, subkeys),
    ("one certificate's user IDs", Kind::Keyring, user_ids),
    (
        "the smallest direct-key signatures",
        Kind::Keyring,
        direct_key_signatures,
    ),
    (
        "the smallest certifications of one user ID",
        Kind::Keyring,
        certifications,
    ),
    (
        "the smallest certifications, after a user attribute",
        Kind::Keyring,
        unplaced_certifications,
    ),
    (
        "a certificate's Signature packets that do not read",
        Kind::Keyring,
        unread_certificate_signatures,
    ),
    (
        "one certificate's user IDs, judged",
        Kind::Judgement,
        judged_user_ids,
    ),
    (
        "one certificate's smallest subkeys, judged",
        Kind::Judgement,
        judged_subkeys,
    ),
    (
        "one certificate's smallest subkeys it may verify with, judged",
        Kind::Judgement,
        judged_verifiable_subkeys,
    ),
    (
        "the smallest certifications of one user ID, judged",
        Kind::Judgement,
        judged_certifications,
    ),
    (
        "the smallest certifications, after a user attribute, judged",
        Kind::Judgement,
        judged_unplaced_certifications,
    ),
];

fn main() -> ExitCode {
    let mut failed = false;
    println!(
        "{:<76} {:>8} {:>6} {:>6}",
        "input packed with", "octets", "held", "peak"
    );
    for &(name, kind, case) in CASES {
        let (held_bound, peak_bound) = kind.bounds();
        for count in [COUNT, COUNT + 1] {
            let (length, measured) = case(count);
            let factor = |octets: usize| octets as f64 / length as f64;
            let within =
                measured.held <= held_bound * length && measured.peak <= peak_bound * length;
            println!(
                "{:<76} {:>8} {:>6.1} {:>6.1}{}",
                format!("{name} ({count})"),
                length,
                factor(measured.held),
                factor(measured.peak),
                if within { "" } else { "  over" },
            );
            failed |= !within;
        }
    }
    if failed {
        eprintln!(
            "reading or judging held more than SECURITY.md states: a document {DOCUMENT} times \
             its size, a keyring {KEYRING} times, and {KEYRING_WHILE_COMBINED} while it is \
             combined, and judging a certificate {JUDGEMENT} times"
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// The smallest body of a version 4 signature of `signature_type`: an
/// algorithm irongall does not read, whose material is of no length, a
/// creation time alone in its hashed area, and an empty unhashed area.
fn smallest_signature(signature_type: u8) -> [u8; 16] {
    [
        4,
        signature_type,
        100,
        8,
        0x00,
        0x06,
        0x05,
        0x02,
        0x60,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xAB,
        0xCD,
    ]
}

/// The packet of `tag` with `body`, its header in the current format (RFC
/// 9580 §4.2.1).
fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![0xC0 | tag];
    match u8::try_from(body.len()) {
        Ok(length) if length < 192 => packet.push(length),
        _ => {
            packet.push(0xFF);
            packet.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        }
    }
    packet.extend_from_slice(body);
    packet
}

/// A version 6 binary signature whose unhashed area is `unhashed`, with a
/// four-octet length, so the area may be longer than a version 4 one.
fn version_6_signature(unhashed: &[u8]) -> Vec<u8> {
    let hashed = [0x05, 0x02, 0x60, 0x00, 0x00, 0x00];
    let mut body = vec![6, 0x00, 27, 8];
    body.extend_from_slice(&u32::try_from(hashed.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&hashed);
    body.extend_from_slice(&u32::try_from(unhashed.len()).unwrap().to_be_bytes());
    body.extend_from_slice(unhashed);
    // The hash prefix, the salt SHA2-256 calls for, and Ed25519 material.
    body.extend_from_slice(&[0xAB, 0xCD, 16]);
    body.extend_from_slice(&[0x5A; 16]);
    body.extend_from_slice(&[0x11; 64]);
    packet(2, &body)
}

/// The smallest Embedded Signature subpacket.
fn embedded_subpacket() -> Vec<u8> {
    let signature = smallest_signature(0x00);
    let mut subpacket = vec![u8::try_from(signature.len() + 1).unwrap(), 32];
    subpacket.extend_from_slice(&signature);
    subpacket
}

/// The smallest key packet of `tag`, a Public Key or a Public Subkey: version
/// 4, created at `created`, of an algorithm irongall does not read, whose
/// material is of no length.
fn key(tag: u8, created: u32) -> Vec<u8> {
    let mut body = vec![4];
    body.extend_from_slice(&created.to_be_bytes());
    body.push(100);
    packet(tag, &body)
}

/// A user ID of three octets for each `index`, distinct for each.
fn user_id(index: usize) -> Vec<u8> {
    let index = u32::try_from(index).unwrap().to_be_bytes();
    packet(13, &index[1..])
}

/// A primary key's creation time the cases' subkeys do not share.
const PRIMARY_CREATED: u32 = 0x6000_0000;

fn read_document(input: &[u8]) -> (document::Detached, Measured) {
    let (detached, measured) = ALLOCATOR.measure(|| document::detached(input));
    (detached.unwrap(), measured)
}

fn read_keyring(input: &[u8]) -> (Keyring, Measured) {
    let (keyring, measured) =
        ALLOCATOR.measure(|| cert::certificates(input).collect::<Result<Keyring, _>>());
    (keyring.unwrap(), measured)
}

/// Reads `input` as a keyring that should hold one certificate, and returns
/// it with what reading it allocated.
fn read_certificate(input: &[u8]) -> (cert::Certificate, Measured) {
    let (keyring, measured) = read_keyring(input);
    let [certificate] = keyring.certificates() else {
        panic!("one certificate");
    };
    (certificate.clone(), measured)
}

fn subpackets(count: usize) -> (usize, Measured) {
    let unhashed: Vec<u8> = std::iter::repeat_n([0x01, 0x64], count).flatten().collect();
    let input = version_6_signature(&unhashed);
    let (detached, measured) = read_document(&input);
    let [signature] = detached.signatures() else {
        panic!("one signature");
    };
    assert_eq!(signature.unhashed_subpackets().count(), count);
    (input.len(), measured)
}

fn smallest_signatures(count: usize) -> (usize, Measured) {
    let input = packet(2, &smallest_signature(0x00)).repeat(count);
    let (detached, measured) = read_document(&input);
    assert_eq!(detached.signatures().len(), count);
    (input.len(), measured)
}

fn each_embedding_one(count: usize) -> (usize, Measured) {
    let embedded = embedded_subpacket();
    let mut body = smallest_signature(0x00)[..12].to_vec();
    body.extend_from_slice(&u16::try_from(embedded.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&embedded);
    body.extend_from_slice(&[0xAB, 0xCD]);
    let input = packet(2, &body).repeat(count);
    let (detached, measured) = read_document(&input);
    assert_eq!(detached.signatures().len(), count);
    assert!(
        detached
            .signatures()
            .iter()
            .all(|signature| signature.embedded_signatures().len() == 1)
    );
    (input.len(), measured)
}

fn embedded_signatures(count: usize) -> (usize, Measured) {
    let input = version_6_signature(&embedded_subpacket().repeat(count));
    let (detached, measured) = read_document(&input);
    let [signature] = detached.signatures() else {
        panic!("one signature");
    };
    assert_eq!(signature.embedded_signatures().len(), count);
    (input.len(), measured)
}

fn armor_headers(count: usize) -> (usize, Measured) {
    // The smallest signature's packet, in base64.
    let data = "whAEAGQIAAYFAmAAAAAAAKvN";
    let mut input = b"-----BEGIN PGP SIGNATURE-----\n".to_vec();
    input.extend_from_slice(&b"a:\n".repeat(count));
    input.extend_from_slice(format!("\n{data}\n-----END PGP SIGNATURE-----\n").as_bytes());
    let headers = irongall::armor::decode(&input).unwrap().headers().count();
    assert_eq!(headers, count);
    let (detached, measured) = read_document(&input);
    assert_eq!(detached.signatures().len(), 1);
    (input.len(), measured)
}

/// A cleartext message's text is held with its line endings made CR LF, so
/// a text of the shortest lines is held in half as much again as it takes.
fn cleartext_lines(count: usize) -> (usize, Measured) {
    // The smallest text signature's packet, in base64.
    let data = "whAEAWQIAAYFAmAAAAAAAKvN";
    let mut input = b"-----BEGIN PGP SIGNED MESSAGE-----\n\n".to_vec();
    input.extend_from_slice(&b"a\n".repeat(count));
    input.extend_from_slice(
        format!("-----BEGIN PGP SIGNATURE-----\n\n{data}\n-----END PGP SIGNATURE-----\n")
            .as_bytes(),
    );
    let (cleartext, measured) = ALLOCATOR.measure(|| document::cleartext(&input));
    let cleartext = cleartext.unwrap();
    assert_eq!(cleartext.signatures().len(), 1);
    assert_eq!(cleartext.text().len(), count * 3 - 2);
    (input.len(), measured)
}

fn unread_signatures(count: usize) -> (usize, Measured) {
    let input = packet(2, &[]).repeat(count);
    let (detached, measured) = read_document(&input);
    assert_eq!(
        (detached.signatures().len(), detached.skipped().len()),
        (0, count)
    );
    (input.len(), measured)
}

fn certificates(count: usize) -> (usize, Measured) {
    let input: Vec<u8> = (0..count)
        .flat_map(|index| key(6, u32::try_from(index).unwrap()))
        .collect();
    let (keyring, measured) = read_keyring(&input);
    assert_eq!(keyring.certificates().len(), count);
    (input.len(), measured)
}

fn certificates_with_user_ids(count: usize) -> (usize, Measured) {
    let input: Vec<u8> = (0..count)
        .flat_map(|index| [key(6, u32::try_from(index).unwrap()), packet(13, &[])].concat())
        .collect();
    let (keyring, measured) = read_keyring(&input);
    assert_eq!(keyring.certificates().len(), count);
    assert!(
        keyring
            .certificates()
            .iter()
            .all(|certificate| certificate.user_ids().len() == 1)
    );
    (input.len(), measured)
}

fn certificates_with_subkeys(count: usize) -> (usize, Measured) {
    let input: Vec<u8> = (0..count)
        .flat_map(|index| {
            let created = u32::try_from(index).unwrap();
            [key(6, created), key(14, created)].concat()
        })
        .collect();
    let (keyring, measured) = read_keyring(&input);
    assert_eq!(keyring.certificates().len(), count);
    assert!(
        keyring
            .certificates()
            .iter()
            .all(|certificate| certificate.subkeys().len() == 1)
    );
    (input.len(), measured)
}

fn copies(count: usize) -> (usize, Measured) {
    let input: Vec<u8> = (0..count)
        .flat_map(|index| [key(6, PRIMARY_CREATED), user_id(index)].concat())
        .collect();
    let (certificate, measured) = read_certificate(&input);
    assert_eq!(certificate.user_ids().len(), count);
    (input.len(), measured)
}

fn subkeys(count: usize) -> (usize, Measured) {
    let mut input = key(6, PRIMARY_CREATED);
    for index in 0..count {
        input.extend(key(14, u32::try_from(index).unwrap()));
    }
    let (certificate, measured) = read_certificate(&input);
    assert_eq!(certificate.subkeys().len(), count);
    (input.len(), measured)
}

fn user_ids(count: usize) -> (usize, Measured) {
    let mut input = key(6, PRIMARY_CREATED);
    for index in 0..count {
        input.extend(user_id(index));
    }
    let (certificate, measured) = read_certificate(&input);
    assert_eq!(certificate.user_ids().len(), count);
    (input.len(), measured)
}

fn direct_key_signatures(count: usize) -> (usize, Measured) {
    let mut input = key(6, PRIMARY_CREATED);
    input.extend(packet(2, &smallest_signature(0x1F)).repeat(count));
    let (certificate, measured) = read_certificate(&input);
    assert_eq!(certificate.primary_signatures().len(), count);
    (input.len(), measured)
}

fn certifications(count: usize) -> (usize, Measured) {
    let mut input = key(6, PRIMARY_CREATED);
    input.extend(packet(13, b"a"));
    input.extend(packet(2, &smallest_signature(0x10)).repeat(count));
    let (certificate, measured) = read_certificate(&input);
    let [user_id] = certificate.user_ids() else {
        panic!("one user ID");
    };
    assert_eq!(user_id.signatures().len(), count);
    (input.len(), measured)
}

/// Certifications after a user attribute, which irongall does not read, are
/// kept with the certificate, though no part lists them; the public API
/// cannot count them, so the case checks that nothing else holds them.
fn unplaced_certifications(count: usize) -> (usize, Measured) {
    let mut input = key(6, PRIMARY_CREATED);
    input.extend(packet(17, b"a"));
    input.extend(packet(2, &smallest_signature(0x10)).repeat(count));
    let (certificate, measured) = read_certificate(&input);
    assert!(certificate.user_ids().is_empty() && certificate.skipped().is_empty());
    (input.len(), measured)
}

fn unread_certificate_signatures(count: usize) -> (usize, Measured) {
    let mut input = key(6, PRIMARY_CREATED);
    input.extend(packet(2, &[]).repeat(count));
    let (certificate, measured) = read_certificate(&input);
    assert_eq!(certificate.skipped().len(), count);
    (input.len(), measured)
}

/// A version 6 Ed25519 key packet of `tag`, created at `created`, which
/// irongall verifies with: the public key of RFC 8032 §7.1's first test.
fn ed25519_key(tag: u8, created: u32) -> Vec<u8> {
    let mut body = vec![6];
    body.extend_from_slice(&created.to_be_bytes());
    body.extend_from_slice(&[27, 0, 0, 0, 32]);
    body.extend_from_slice(&[
        0xD7, 0x5A, 0x98, 0x01, 0x82, 0xB1, 0x0A, 0xB7, 0xD5, 0x4B, 0xFE, 0xD3, 0xC9, 0x64, 0x07,
        0x3A, 0x0E, 0xE1, 0x72, 0xF3, 0xDA, 0xA6, 0x23, 0x25, 0xAF, 0x02, 0x1A, 0x68, 0xF7, 0x07,
        0x51, 0x1A,
    ]);
    packet(tag, &body)
}

/// Judges the one certificate `input` holds, under a primary key irongall
/// verifies with, and returns what judging it allocated: the certificate is
/// read before the measure begins.
fn judge(input: &[u8]) -> Measured {
    let (certificate, _) = read_certificate(input);
    let policy = Policy::new();
    assert!(policy.accepts_key(certificate.primary()));
    let (authority, measured) =
        ALLOCATOR.measure(|| Authority::new(&certificate, &policy, u64::from(PRIMARY_CREATED)));
    assert_eq!(authority.signers().count(), certificate.subkeys().len() + 1);
    measured
}

fn judged_user_ids(count: usize) -> (usize, Measured) {
    let mut input = ed25519_key(6, PRIMARY_CREATED);
    for index in 0..count {
        input.extend(user_id(index));
    }
    (input.len(), judge(&input))
}

/// The smallest subkeys of the primary key's version, 6, of an algorithm
/// irongall does not read.
fn judged_subkeys(count: usize) -> (usize, Measured) {
    let mut input = ed25519_key(6, PRIMARY_CREATED);
    for index in 0..count {
        let mut body = vec![6];
        body.extend_from_slice(&u32::try_from(index).unwrap().to_be_bytes());
        body.extend_from_slice(&[100, 0, 0, 0, 0]);
        input.extend(packet(14, &body));
    }
    (input.len(), judge(&input))
}

fn judged_verifiable_subkeys(count: usize) -> (usize, Measured) {
    let mut input = ed25519_key(6, PRIMARY_CREATED);
    for index in 0..count {
        input.extend(ed25519_key(14, u32::try_from(index).unwrap()));
    }
    (input.len(), judge(&input))
}

fn judged_certifications(count: usize) -> (usize, Measured) {
    let mut input = ed25519_key(6, PRIMARY_CREATED);
    input.extend(packet(13, b"a"));
    input.extend(packet(2, &smallest_signature(0x10)).repeat(count));
    (input.len(), judge(&input))
}

fn judged_unplaced_certifications(count: usize) -> (usize, Measured) {
    let mut input = ed25519_key(6, PRIMARY_CREATED);
    input.extend(packet(17, b"a"));
    input.extend(packet(2, &smallest_signature(0x10)).repeat(count));
    (input.len(), judge(&input))
}
