//! Tests for verifying against a keyring: which keys a signature is tried
//! with, which refusal is reported, a document hashed in pieces, and the
//! documents and certificates GnuPG made, judged under the default policy.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::{Keyring, Refusal};
use crate::cert::{self, Certificate};
use crate::document;
use crate::key::Fingerprint;
use crate::packet::{self, Tag, Version};
use crate::policy::{Authority, Policy, Reason};
use crate::signature::{Signature, SignatureType, SubpacketType};
use crate::test_support::forge::{self, Key};
use crate::test_support::work::{self, Work};
use crate::test_support::{vector, vector_bytes};

const CREATED: u32 = 1_544_987_117;
const SIGNED: u32 = 1_790_000_000;
const NOW: u64 = 1_790_086_400;
const DOCUMENT: &[u8] = b"Suite: test\nComponents: main\n";

/// A certificate of `primary`, certified to certify and sign, made at
/// [`CREATED`].
fn signing(primary: &Key) -> Certificate {
    forge::certificate(&[
        &primary.primary(),
        &forge::user_id("archive"),
        &primary
            .sign(SignatureType::POSITIVE_CERTIFICATION, CREATED)
            .key_flags(0x03)
            .over_user_id(primary, "archive"),
    ])
}

/// The key that made the accepted signature among `signatures`, or the
/// refusal.
fn verify(keyring: &Keyring, signatures: &[Signature]) -> Result<Fingerprint, Refusal> {
    keyring
        .verify(&Policy::new(), NOW, signatures, DOCUMENT)
        .map(|verified| verified.key().fingerprint())
}

/// Copies of one certificate obtained at different times are combined into
/// one, so a stale copy, without the revocation a later one holds, revives
/// nothing, in whichever order the keyring is given them. A certificate of
/// another key between them is kept apart, in its place.
#[test]
fn copies_of_a_certificate_are_combined() {
    for version in [Version::V4, Version::V6] {
        let primary = Key::ed25519(1, version, CREATED);
        let parts = [
            primary.primary(),
            primary
                .sign(SignatureType::DIRECT_KEY, CREATED)
                .key_flags(0x03)
                .over_key(&primary),
        ];
        let revocation = primary
            .sign(SignatureType::KEY_REVOCATION, SIGNED + 1)
            .over_key(&primary);
        let stale = forge::certificate(&[&parts[0], &parts[1]]);
        let revoked = forge::certificate(&[&parts[0], &parts[1], &revocation]);
        let signatures = [forge::read(
            &primary
                .sign(SignatureType::BINARY, SIGNED)
                .over_document(DOCUMENT),
        )];
        let reason =
            |keyring: &Keyring| verify(keyring, &signatures).map_err(|refusal| refusal.reason());
        assert_eq!(
            reason(&Keyring::new([stale.clone()])),
            Ok(primary.public().fingerprint())
        );
        for keyring in [
            Keyring::new([revoked.clone()]),
            Keyring::new([revoked.clone(), stale.clone()]),
            Keyring::new([stale.clone(), revoked.clone()]),
        ] {
            assert_eq!(keyring.certificates().len(), 1);
            assert_eq!(
                reason(&keyring),
                Err(Reason::CertificateRevoked),
                "{version:?}"
            );
        }
        let other = signing(&Key::ed25519(3, Version::V4, CREATED));
        let keyring = Keyring::new([stale.clone(), other.clone(), revoked]);
        assert_eq!(keyring.certificates().len(), 2);
        assert_eq!(keyring.certificates()[1], other);
        assert_eq!(reason(&keyring), Err(Reason::CertificateRevoked));
    }
}

/// A signature is tried with the keys its issuers name, or with every key if
/// it names none. A wrong name loses only what the signature would have
/// verified.
#[test]
fn issuers_choose_the_keys_tried() {
    let (one, two) = (
        Key::ed25519(1, Version::V4, CREATED),
        Key::ed25519(2, Version::V4, CREATED),
    );
    let keyring = Keyring::new([signing(&one), signing(&two)]);
    let creation = SIGNED.to_be_bytes();
    let bare = || {
        two.sign(SignatureType::TEXT, SIGNED)
            .bare()
            .hashed(SubpacketType::SIGNATURE_CREATION_TIME, &creation)
    };
    let fingerprint = |key: &Key| [&[4][..], key.public().fingerprint().as_bytes()].concat();

    let unnamed = forge::read(&bare().over_document(DOCUMENT));
    let by_key_id = forge::read(
        &bare()
            .unhashed(
                SubpacketType::ISSUER_KEY_ID,
                two.public().key_id().as_bytes(),
            )
            .over_document(DOCUMENT),
    );
    let misnamed = forge::read(
        &bare()
            .hashed(SubpacketType::ISSUER_FINGERPRINT, &fingerprint(&one))
            .over_document(DOCUMENT),
    );
    let one_of_two = forge::read(
        &bare()
            .unhashed(
                SubpacketType::ISSUER_KEY_ID,
                one.public().key_id().as_bytes(),
            )
            .unhashed(
                SubpacketType::ISSUER_KEY_ID,
                two.public().key_id().as_bytes(),
            )
            .over_document(DOCUMENT),
    );
    let expected = Ok(two.public().fingerprint());
    assert_eq!(verify(&keyring, &[unnamed]), expected);
    assert_eq!(verify(&keyring, &[by_key_id]), expected);
    assert_eq!(verify(&keyring, &[one_of_two]), expected);
    assert_eq!(
        verify(&keyring, &[misnamed]).unwrap_err().reason(),
        Reason::Unverified
    );
}

/// When nothing is accepted, the refusal reported is the first refusal of a
/// signature a key in the keyring made, in the order of the signatures and
/// then of the keyring; and an accepted signature anywhere is the answer.
#[test]
fn the_first_refusal_is_reported() {
    let (one, two) = (
        Key::ed25519(1, Version::V4, CREATED),
        Key::ed25519(2, Version::V4, CREATED),
    );
    let keyring = Keyring::new([signing(&one), signing(&two)]);
    let early = |key: &Key| {
        forge::read(
            &key.sign(SignatureType::TEXT, CREATED - 1)
                .over_document(DOCUMENT),
        )
    };
    let expiring = |key: &Key| {
        forge::read(
            &key.sign(SignatureType::TEXT, SIGNED)
                .expiration(1)
                .over_document(DOCUMENT),
        )
    };
    let good = |key: &Key| {
        forge::read(
            &key.sign(SignatureType::TEXT, SIGNED)
                .over_document(DOCUMENT),
        )
    };

    let refusal = verify(&keyring, &[early(&two), expiring(&one)]).unwrap_err();
    assert_eq!(refusal.reason(), Reason::BeforeKeyCreation);
    assert_eq!(refusal.key(), Some(two.public().fingerprint()));
    assert_eq!(refusal.certificate(), refusal.key());
    let refusal = verify(&keyring, &[expiring(&one), early(&two)]).unwrap_err();
    assert_eq!(refusal.reason(), Reason::SignatureExpired);
    assert_eq!(refusal.key(), Some(one.public().fingerprint()));

    for signatures in [[early(&one), good(&two)], [good(&two), early(&one)]] {
        assert_eq!(
            verify(&keyring, &signatures),
            Ok(two.public().fingerprint())
        );
    }

    let refusal = verify(&Keyring::default(), &[good(&one)]).unwrap_err();
    assert_eq!(
        (refusal.reason(), refusal.key()),
        (Reason::Unverified, None)
    );
    assert_eq!(
        alloc::string::ToString::to_string(&refusal),
        "no signature verifies with a key in the keyring"
    );
}

/// A signature that names as its issuer a key irongall does not verify with
/// is refused as such, with the key it names, unless a key in the keyring
/// made a signature the policy refused. One that names no issuer says
/// nothing of the keys it was tried with.
#[test]
fn a_signature_naming_a_key_irongall_does_not_verify_with() {
    let (one, two) = (
        Key::ed25519(1, Version::V4, CREATED),
        Key::ed25519(2, Version::V4, CREATED),
    );
    let rsa = Key::rsa(Version::V4, CREATED);
    // A DSA key, and an RSA key of 1024 bits, each signing as a key the tests
    // hold does, so that only the key stands in the way.
    let dsa = [
        &[4][..],
        &CREATED.to_be_bytes(),
        &[17],
        &[0, 8, 0xFF],
        &[0, 8, 0xFF],
        &[0, 8, 0xFF],
        &[0, 8, 0xFF],
    ]
    .concat();
    let mut modulus = alloc::vec![0x5A; 128];
    modulus[0] = 0x80;
    modulus[127] |= 1;
    let narrow = [
        &[4][..],
        &CREATED.to_be_bytes(),
        &[1],
        &[4, 0],
        &modulus,
        &[0, 17, 1, 0, 1],
    ]
    .concat();
    let good = |key: &Key| {
        forge::read(
            &key.sign(SignatureType::TEXT, SIGNED)
                .over_document(DOCUMENT),
        )
    };
    let early = forge::read(
        &two.sign(SignatureType::TEXT, CREATED - 1)
            .over_document(DOCUMENT),
    );

    for (like, body) in [(&one, &dsa), (&rsa, &narrow)] {
        let unsupported = Key::with_body(like, body);
        let keyring = Keyring::new([signing(&unsupported), signing(&two)]);
        let named = good(&unsupported);
        let refusal = verify(&keyring, core::slice::from_ref(&named)).unwrap_err();
        assert_eq!(refusal.reason(), Reason::UnsupportedKey);
        assert_eq!(refusal.key(), Some(unsupported.public().fingerprint()));
        assert_eq!(refusal.certificate(), refusal.key());
        assert_eq!(
            alloc::string::ToString::to_string(&refusal),
            alloc::format!(
                "the signature names as its issuer a key irongall does not verify with (key {})",
                unsupported.public().fingerprint()
            )
        );

        // A refusal of a signature a key made outranks it, and an accepted
        // signature is the answer, in either order.
        for signatures in [
            [named.clone(), early.clone()],
            [early.clone(), named.clone()],
        ] {
            assert_eq!(
                verify(&keyring, &signatures).unwrap_err().reason(),
                Reason::BeforeKeyCreation
            );
        }
        for signatures in [[named.clone(), good(&two)], [good(&two), named.clone()]] {
            assert_eq!(
                verify(&keyring, &signatures),
                Ok(two.public().fingerprint())
            );
        }

        // Without the issuer subpackets, the signature names no key.
        let unnamed = forge::read(
            &unsupported
                .sign(SignatureType::TEXT, SIGNED)
                .bare()
                .hashed(
                    SubpacketType::SIGNATURE_CREATION_TIME,
                    &SIGNED.to_be_bytes(),
                )
                .over_document(DOCUMENT),
        );
        assert_eq!(
            verify(&keyring, &[unnamed]).unwrap_err().reason(),
            Reason::Unverified
        );
    }
    // The same shape with a key irongall verifies with.
    let keyring = Keyring::new([signing(&one)]);
    assert_eq!(
        verify(&keyring, &[good(&one)]),
        Ok(one.public().fingerprint())
    );
}

/// A document hashed in pieces for each signature is judged as it is whole.
#[test]
fn a_document_hashed_in_pieces() {
    let (one, two) = (
        Key::ed25519(1, Version::V4, CREATED),
        Key::ed25519(2, Version::V4, CREATED),
    );
    let keyring: Keyring = [signing(&one), signing(&two)].into_iter().collect();
    let signatures = [
        forge::read(
            &one.sign(SignatureType::TEXT, CREATED - 1)
                .over_document(DOCUMENT),
        ),
        forge::read(
            &two.sign(SignatureType::BINARY, SIGNED)
                .over_document(DOCUMENT),
        ),
    ];
    for cut in 0..=DOCUMENT.len() {
        let mut hashes: Vec<_> = signatures
            .iter()
            .map(|signature| signature.document_hash().unwrap())
            .collect();
        for hash in &mut hashes {
            hash.update(&DOCUMENT[..cut]);
            hash.update(&DOCUMENT[cut..]);
        }
        let verified = keyring.verify_hashed(&Policy::new(), NOW, &hashes).unwrap();
        assert_eq!(verified.key(), two.public());
        assert_eq!(verified.signature(), &signatures[1]);
    }
    let too_many = Policy::new().with_max_signatures(1);
    let hashes: Vec<_> = signatures
        .iter()
        .map(|signature| signature.document_hash().unwrap())
        .collect();
    assert_eq!(
        keyring
            .verify_hashed(&too_many, NOW, &hashes)
            .unwrap_err()
            .reason(),
        Reason::TooManySignatures
    );
}

/// Trying a signature with many keys costs its hash once: a version 6
/// signature's hashed area may be as long as its packet, and a keyring may
/// hold any number of keys of its algorithm, such as subkeys appended to a
/// certificate without a binding, so finishing the hash for each key would
/// cost the two multiplied. The work grows with neither multiplied by the
/// other, whichever key verifies, and a signature that names only keys the
/// keyring does not hold is never finished at all.
#[test]
fn the_work_of_trying_a_signature_does_not_multiply() {
    let primary = Key::ed25519(1, Version::V6, CREATED);
    let direct = primary
        .sign(SignatureType::DIRECT_KEY, CREATED)
        .key_flags(0x03)
        .over_key(&primary);
    let keyring = |subkeys: u32| {
        let mut packets = vec![primary.primary(), direct.clone()];
        for at in 0..subkeys {
            packets.push(Key::ed25519(2, Version::V6, CREATED + at).subkey());
        }
        let parts: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
        Keyring::new([forge::certificate(&parts)])
    };
    let padding = vec![0x5A; 64 * 1024];
    let creation = SIGNED.to_be_bytes();
    let signature = |over: &[u8]| {
        forge::read(
            &primary
                .sign(SignatureType::BINARY, SIGNED)
                .bare()
                .hashed(SubpacketType::SIGNATURE_CREATION_TIME, &creation)
                .hashed(SubpacketType(101), &padding)
                .over_document(over),
        )
    };
    let good = signature(DOCUMENT);
    let other = signature(b"another document");
    let hashed_fields = u64::try_from(good.hashed_fields().len()).unwrap();
    let mut each = Vec::new();
    for subkeys in [1, 64] {
        let keyring = keyring(subkeys);
        assert_eq!(keyring.certificates()[0].subkeys().len(), subkeys as usize);
        let (verdict, unverified) = work::of(|| verify(&keyring, core::slice::from_ref(&other)));
        assert_eq!(verdict.unwrap_err().reason(), Reason::Unverified);
        assert_eq!(unverified.operations, 0);
        // The salt, the document, and the hashed fields and trailer once.
        assert!(unverified.hashed < hashed_fields + 64, "{unverified:?}");
        let (verdict, verified) = work::of(|| verify(&keyring, core::slice::from_ref(&good)));
        assert_eq!(verdict, Ok(primary.public().fingerprint()));
        each.push((unverified.hashed, verified.operations));
    }
    // Nothing the subkeys add is hashed. Two equations are checked: the
    // document's signature with the primary key, tried first, and the
    // direct-key signature that grants it the right to sign.
    assert_eq!(each[0], each[1]);
    assert_eq!(each[0].1, 2);

    // Among many issuers, the one that names a key in the keyring is found,
    // and a signature that names none of its keys is passed over unhashed.
    let named = |names: &[Fingerprint]| {
        let mut signing = primary
            .sign(SignatureType::BINARY, SIGNED)
            .bare()
            .hashed(SubpacketType::SIGNATURE_CREATION_TIME, &creation);
        for name in names {
            signing = signing.unhashed(
                SubpacketType::ISSUER_FINGERPRINT,
                &[&[6][..], name.as_bytes()].concat(),
            );
        }
        forge::read(&signing.over_document(DOCUMENT))
    };
    let strangers: Vec<Fingerprint> = (0..200)
        .map(|seed| {
            Key::ed25519(seed, Version::V6, SIGNED)
                .public()
                .fingerprint()
        })
        .filter(|fingerprint| *fingerprint != primary.public().fingerprint())
        .collect();
    let keyring = keyring(64);
    let mut names = strangers.clone();
    names.insert(100, primary.public().fingerprint());
    assert_eq!(
        verify(&keyring, &[named(&names)]),
        Ok(primary.public().fingerprint())
    );
    let unnamed = named(&strangers);
    let (verdict, work) = work::of(|| verify(&keyring, core::slice::from_ref(&unnamed)));
    assert_eq!(verdict.unwrap_err().reason(), Reason::Unverified);
    // The salt and the document, which hashing begins with, and no more.
    assert_eq!(
        work,
        Work {
            hashed: (unnamed.salt().len() + DOCUMENT.len()) as u64,
            operations: 0,
            prepared: 0,
        }
    );
}

/// The one certificate in a GnuPG vector.
fn gnupg(name: &str) -> Certificate {
    let data = vector_bytes(&alloc::format!("gnupg/{name}.pgp"));
    cert::certificates(&data).next().unwrap().unwrap()
}

/// 2026-03-01 00:00:00 UTC: after GnuPG made every vector.
const MARCH_2026: u64 = 1_772_323_200;

/// GnuPG's certificates, judged under the default policy: each grants what
/// GnuPG made it to grant.
#[test]
fn gnupg_certificates() {
    let standings = |name: &str| -> Vec<_> {
        let certificate = gnupg(name);
        Authority::new(&certificate, &Policy::new(), MARCH_2026)
            .signers()
            .map(|(_, standing)| standing.map(|window| (window.created(), window.expires())))
            .collect()
    };
    let january = 1_767_225_600;
    let february = 1_769_904_000;
    assert_eq!(
        standings("rsa"),
        [Ok((january, None)), Err(Reason::SubkeyMayNotSign)]
    );
    // An encryption subkey's binding grants it no signing; an ECDH one is of
    // an algorithm irongall does not verify with, which is judged first.
    assert_eq!(
        standings("ed25519"),
        [Ok((january, None)), Err(Reason::WeakSubkey)]
    );
    assert_eq!(
        standings("ed25519-signing"),
        [Err(Reason::PrimaryMayNotSign), Ok((january, None))]
    );
    // DSA and ECDSA, which irongall does not verify with.
    for name in ["dsa", "nistp256", "brainpoolp256r1"] {
        assert_eq!(standings(name)[0], Err(Reason::WeakPrimaryKey), "{name}");
    }
    assert_eq!(
        standings("documents"),
        [Ok((february, None)), Ok((february, None))]
    );
    // Revoked on its eighth day, after a subkey and a user ID were revoked
    // and the key's expiration set.
    assert!(
        standings("lifecycle")
            .iter()
            .all(|standing| *standing == Err(Reason::CertificateRevoked))
    );
    let lifecycle = gnupg("lifecycle");
    let authority = Authority::new(&lifecycle, &Policy::new(), MARCH_2026);
    assert_eq!(
        authority.primary_user_id().map(|user_id| user_id.value()),
        Some(&b"irongall test, lifecycle <lifecycle@example.invalid>"[..])
    );
    // Made to expire in a year, and extended to five once its second user ID
    // was revoked, which GnuPG does not re-sign: the extension holds, and the
    // revoked user ID's stale certification restricts nothing.
    let extended = gnupg("extended");
    assert_eq!(standings("extended"), [Ok((january, Some(1_925_164_800)))]);
    let authority = Authority::new(&extended, &Policy::new(), MARCH_2026);
    assert_eq!(
        authority.primary_user_id().map(|user_id| user_id.value()),
        Some(&b"irongall test, extended <extended@example.invalid>"[..])
    );
    // Revoked by their own Ed25519 keys over hashes shorter than 256 bits,
    // on which an Ed25519 signature never verifies: the certificate over
    // SHA-1, and the signing subkey over SHA2-224. Each revocation still
    // revokes, as GnuPG lists it.
    assert!(
        standings("revoked-sha1")
            .iter()
            .all(|standing| *standing == Err(Reason::CertificateRevoked))
    );
    assert!(vector("gnupg/revoked-sha1.colons").starts_with("pub:r:"));
    let february_tenth = 1_770_681_600;
    assert_eq!(
        standings("short-hash"),
        [Ok((february_tenth, None)), Err(Reason::SubkeyRevoked)]
    );
    assert!(vector("gnupg/short-hash.colons").contains("\nsub:r:"));
    // Made to expire a day after it was made, as GnuPG lists it.
    assert_eq!(
        standings("expired"),
        [Ok((
            february_tenth,
            Some(u64::from(february_tenth) + 86_400)
        ))]
    );

    // Each certificate irongall judges lapses when GnuPG lists its primary
    // key as expiring, whether or not the primary key may sign.
    let listed = |name: &str| -> Option<u64> {
        let colons = vector(&alloc::format!("gnupg/{name}.colons"));
        let primary = colons
            .lines()
            .find(|line| line.starts_with("pub:"))
            .unwrap();
        let expires = primary.split(':').nth(6).unwrap();
        (!expires.is_empty()).then(|| expires.parse().unwrap())
    };
    let lapse = |name: &str| Authority::new(&gnupg(name), &Policy::new(), MARCH_2026).lapse();
    let judged = [
        "rsa",
        "ed25519",
        "ed25519-signing",
        "documents",
        "extended",
        "short-hash",
        "expired",
    ];
    for name in judged {
        assert_eq!(lapse(name), Ok(listed(name)), "{name}");
    }
    assert_eq!(listed("extended"), Some(1_925_164_800));
    for name in ["lifecycle", "revoked-sha1"] {
        assert_eq!(lapse(name), Err(Reason::CertificateRevoked), "{name}");
    }
    for name in ["dsa", "nistp256", "brainpoolp256r1"] {
        assert_eq!(lapse(name), Err(Reason::WeakPrimaryKey), "{name}");
    }
}

/// GnuPG's signed documents verify against a keyring holding every GnuPG
/// certificate, each by the key that made it.
#[test]
fn gnupg_documents() {
    let keyring = Keyring::new(
        [
            "rsa",
            "dsa",
            "ed25519",
            "nistp256",
            "brainpoolp256r1",
            "ed25519-signing",
            "lifecycle",
            "documents",
            "extended",
            "revoked-sha1",
            "short-hash",
            "expired",
        ]
        .map(gnupg),
    );
    let policy = Policy::new();
    let documents = gnupg("documents");

    for name in ["cleartext", "cleartext-crlf"] {
        let message =
            document::cleartext(&vector_bytes(&alloc::format!("gnupg/{name}.asc"))).unwrap();
        let verified = keyring
            .verify(&policy, MARCH_2026, message.signatures(), message.text())
            .unwrap();
        assert_eq!(verified.certificate(), &documents);
        assert_eq!(verified.key(), documents.primary());
        // With the primary key's signature removed, the subkey's verifies.
        let verified = keyring
            .verify(
                &policy,
                MARCH_2026,
                &message.signatures()[1..],
                message.text(),
            )
            .unwrap();
        assert_eq!(verified.key(), documents.subkeys()[0].key());
    }

    let document = vector_bytes("gnupg/document.txt");
    let detached = document::detached(&vector_bytes("gnupg/detached.asc")).unwrap();
    let verified = keyring
        .verify(&policy, MARCH_2026, detached.signatures(), &document)
        .unwrap();
    assert_eq!(verified.key(), documents.primary());

    // The certifying primary key's signing subkey made these; the binary
    // signature expires two years after 2026-01-01.
    let signing = gnupg("ed25519-signing");
    for file in ["binary", "text"] {
        let detached =
            document::detached(&vector_bytes(&alloc::format!("gnupg/{file}.sig"))).unwrap();
        let verified = keyring
            .verify(&policy, MARCH_2026, detached.signatures(), &document)
            .unwrap();
        assert_eq!(verified.key(), signing.subkeys()[0].key(), "{file}");
    }
    let binary = document::detached(&vector_bytes("gnupg/binary.sig")).unwrap();
    let later = 1_767_225_600 + 2 * 365 * 86_400;
    assert_eq!(
        keyring
            .verify(&policy, later, binary.signatures(), &document)
            .unwrap_err()
            .reason(),
        Reason::SignatureExpired
    );

    // Made on 2028-01-01 by `extended`'s primary key, after the expiration it
    // was first given and within the one it was extended to. GnuPG verifies
    // it the next day, and so does irongall. Judged before it was made, it
    // claims a time not yet reached.
    let extended = gnupg("extended");
    let late = document::detached(&vector_bytes("gnupg/late.sig")).unwrap();
    let status = vector("gnupg/late.verify");
    assert!(status.contains(&alloc::format!(
        "VALIDSIG {}",
        extended.primary().fingerprint()
    )));
    let next_day = 1_830_384_000;
    let verified = keyring
        .verify(&policy, next_day, late.signatures(), &document)
        .unwrap();
    assert_eq!(verified.key(), extended.primary());
    assert_eq!(
        keyring
            .verify(&policy, MARCH_2026, late.signatures(), &document)
            .unwrap_err()
            .reason(),
        Reason::Postdated
    );

    // By `short-hash`'s primary key over SHA2-224, which GnuPG verifies and
    // RFC 9580 forbids an Ed25519 signature to rest on: the key made it, and
    // it is refused for its hash, though the policy accepts SHA2-224.
    let short = gnupg("short-hash");
    let sha224 = document::detached(&vector_bytes("gnupg/sha224.sig")).unwrap();
    let status = vector("gnupg/sha224.verify");
    assert!(status.contains(&alloc::format!(
        "VALIDSIG {}",
        short.primary().fingerprint()
    )));
    assert!(policy.accepts_hash(sha224.signatures()[0].hash_algorithm()));
    let refusal = keyring
        .verify(&policy, MARCH_2026, sha224.signatures(), &document)
        .unwrap_err();
    assert_eq!(refusal.reason(), Reason::WeakHash);
    assert_eq!(refusal.key(), Some(short.primary().fingerprint()));
    // By its subkey, a day before the primary key revoked the subkey over
    // SHA2-224. GnuPG reports the signature good and its key revoked.
    let by_subkey = document::detached(&vector_bytes("gnupg/revoked-subkey.sig")).unwrap();
    let status = vector("gnupg/revoked-subkey.verify");
    let subkey = short.subkeys()[0].key();
    assert!(status.contains(&alloc::format!("VALIDSIG {}", subkey.fingerprint())));
    assert!(status.contains(&alloc::format!("REVKEYSIG {}", subkey.key_id())));
    let refusal = keyring
        .verify(&policy, MARCH_2026, by_subkey.signatures(), &document)
        .unwrap_err();
    assert_eq!(refusal.reason(), Reason::SubkeyRevoked);
    assert_eq!(refusal.key(), Some(subkey.fingerprint()));

    // Made by `expired` within its one day of life. Judged once the key has
    // expired, GnuPG reports it made by an expired key, and irongall refuses
    // it; judged within the day, it is accepted.
    let expired = gnupg("expired");
    let before_expiry = document::detached(&vector_bytes("gnupg/before-expiry.sig")).unwrap();
    let status = vector("gnupg/before-expiry.verify");
    assert!(status.contains(&alloc::format!("EXPKEYSIG {}", expired.primary().key_id())));
    assert!(!status.contains("GOODSIG"));
    let refusal = keyring
        .verify(&policy, MARCH_2026, before_expiry.signatures(), &document)
        .unwrap_err();
    assert_eq!(refusal.reason(), Reason::KeyExpired);
    assert_eq!(refusal.key(), Some(expired.primary().fingerprint()));
    let within = u64::from(before_expiry.signatures()[0].creation_time()) + 3600;
    let verified = keyring
        .verify(&policy, within, before_expiry.signatures(), &document)
        .unwrap();
    assert_eq!(verified.key(), expired.primary());
}

/// `name`'s certificate with each Signature packet of `signature_type`
/// changed by `change`, and every packet framed as the test forge frames
/// one, or `None` if `change` changes none.
fn gnupg_changed(
    name: &str,
    signature_type: SignatureType,
    change: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Option<Certificate> {
    let data = vector_bytes(&alloc::format!("gnupg/{name}.pgp"));
    let mut changed = 0;
    let mut framed = Vec::new();
    for packet in packet::packets(&data) {
        let packet = packet.unwrap();
        let mut reframed = forge::packet(packet.tag(), packet.body());
        if packet.tag() == Tag::SIGNATURE
            && forge::read(&reframed).signature_type() == signature_type
        {
            reframed = change(&reframed)?;
            changed += 1;
        }
        framed.extend(reframed);
    }
    assert_eq!(changed, 1, "{name}");
    Some(cert::certificates(&framed).next().unwrap().unwrap())
}

/// GnuPG's revocations still revoke when changed where no signature covers
/// them, as anyone who handles a certificate can change them: with the
/// hash prefix inverted, with an octet after the material, or with the
/// integers of the material written another way. GnuPG 2.4.4 lists each
/// certificate with the first two changes as revoked (`pub:r`, `sub:r`),
/// and the signature its revoked subkey made is still refused.
#[test]
fn gnupg_revocations_changed_where_nothing_covers_them_still_revoke() {
    type Change = Box<dyn Fn(&[u8]) -> Option<Vec<u8>>>;
    let mut changes: Vec<(String, Change)> = vec![
        (
            "prefix".into(),
            Box::new(|packet: &[u8]| Some(forge::with_prefix_inverted(packet))),
        ),
        (
            "appended".into(),
            Box::new(|packet: &[u8]| Some(forge::with_appended(packet, &[0x00]))),
        ),
    ];
    for encoding in forge::Encoding::ALL {
        changes.push((
            alloc::format!("{encoding:?}"),
            Box::new(move |packet: &[u8]| forge::with_integers(packet, encoding)),
        ));
    }
    let standings = |certificate: &Certificate| -> Vec<_> {
        Authority::new(certificate, &Policy::new(), MARCH_2026)
            .signers()
            .map(|(_, standing)| standing.map(|window| (window.created(), window.expires())))
            .collect()
    };
    let document = vector_bytes("gnupg/document.txt");
    let by_subkey = document::detached(&vector_bytes("gnupg/revoked-subkey.sig")).unwrap();
    let mut tried = 0;
    for (how, change) in &changes {
        if let Some(revoked) = gnupg_changed(
            "revoked-sha1",
            SignatureType::KEY_REVOCATION,
            change.as_ref(),
        ) {
            assert!(
                standings(&revoked)
                    .iter()
                    .all(|standing| *standing == Err(Reason::CertificateRevoked)),
                "{how}"
            );
            tried += 1;
        }
        if let Some(short) = gnupg_changed(
            "short-hash",
            SignatureType::SUBKEY_REVOCATION,
            change.as_ref(),
        ) {
            assert_eq!(
                standings(&short),
                [Ok((1_770_681_600, None)), Err(Reason::SubkeyRevoked)],
                "{how}"
            );
            let refusal = Keyring::new([short])
                .verify(
                    &Policy::new(),
                    MARCH_2026,
                    by_subkey.signatures(),
                    &document,
                )
                .unwrap_err();
            assert_eq!(refusal.reason(), Reason::SubkeyRevoked, "{how}");
            tried += 1;
        }
    }
    // Every change, to both revocations, but for a length one bit longer
    // than an integer within its octets: the high bit of the first octet of
    // both of the subkey revocation's integers is set.
    assert_eq!(tried, 9);
}
