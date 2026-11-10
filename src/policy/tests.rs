//! Tests for the policy: each rule a certificate's authority and a
//! document's signature are judged by, on certificates and signatures made
//! for the purpose, each refusal checked to be the policy's by the same
//! shape with the defect removed.

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use alloc::{format, vec};

use super::statements::Statements;
use super::{Authority, Policy, Reason, Window};
use crate::cert::{Certificate, UserId};
use crate::hash::HashAlgorithm;
use crate::key::{Fingerprint, KeyMaterial};
use crate::keyring::Keyring;
use crate::packet::{self, Tag, Version};
use crate::signature::{Signature, SignatureType, Subject, SubpacketType};
use crate::test_support::forge::{self, Key};
use crate::test_support::work;

/// When the keys of most tests were made: 2018-12-16.
const CREATED: u32 = 1_544_987_117;
/// Two years, a key lifetime short enough to lapse long before [`SIGNED`].
const TWO_YEARS: u32 = 63_072_000;
const DAY: u32 = 86_400;
/// When the documents of most tests were signed: 2026-09-21.
const SIGNED: u32 = 1_790_000_000;
/// The time the tests judge at: a day after [`SIGNED`].
const NOW: u64 = 1_790_086_400;

/// Key flags: certifying (0x01) and signing (0x02).
const CERTIFY: u8 = 0x01;
const SIGN: u8 = 0x02;
/// Key flags: encrypting communications and storage (0x04, 0x08).
const ENCRYPT: u8 = 0x0C;

/// The document the tests sign.
const DOCUMENT: &[u8] = b"Suite: test\nComponents: main\nSHA256:\n abc 10 main/Packages\n";

const USER_ID: &str = "archive <archive@example.invalid>";

/// A version 4 Ed25519 key from `seed`, made at [`CREATED`].
fn ed25519(seed: u8) -> Key {
    Key::ed25519(seed, Version::V4, CREATED)
}

/// The packets of a certification of [`USER_ID`] by `primary`, made at
/// `created`, stating `flags` if any and a key expiration if any.
fn certification(primary: &Key, created: u32, flags: Option<u8>, expires: Option<u32>) -> Vec<u8> {
    certification_of(primary, USER_ID, created, flags, expires)
}

/// [`certification`], of `user_id`.
fn certification_of(
    primary: &Key,
    user_id: &str,
    created: u32,
    flags: Option<u8>,
    expires: Option<u32>,
) -> Vec<u8> {
    let mut signing = primary.sign(SignatureType::POSITIVE_CERTIFICATION, created);
    if let Some(flags) = flags {
        signing = signing.key_flags(flags);
    }
    if let Some(expires) = expires {
        signing = signing.key_expiration(expires);
    }
    signing.over_user_id(primary, user_id)
}

/// `subkey`'s back-signature over its binding to `primary`, made at
/// `created`.
fn back_signature(primary: &Key, subkey: &Key, created: u32) -> Vec<u8> {
    subkey
        .sign(SignatureType::PRIMARY_KEY_BINDING, created)
        .over_subkey(primary, subkey)
}

/// A binding of `subkey` by `primary`, made at `created`, granting `flags`
/// and embedding a back-signature made at the same time.
fn binding(primary: &Key, subkey: &Key, created: u32, flags: u8) -> Vec<u8> {
    primary
        .sign(SignatureType::SUBKEY_BINDING, created)
        .key_flags(flags)
        .embed(&back_signature(primary, subkey, created))
        .over_subkey(primary, subkey)
}

/// The usual certificate: `primary`, certified to certify and sign, with
/// `subkey` bound to sign, everything made at [`CREATED`].
fn archive(primary: &Key, subkey: &Key) -> Certificate {
    forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(primary, CREATED, Some(CERTIFY | SIGN), None),
        &subkey.subkey(),
        &binding(primary, subkey, CREATED, SIGN),
    ])
}

/// A text signature by `key` over [`DOCUMENT`], made at `created`.
fn signed(key: &Key, created: u32) -> Vec<u8> {
    key.sign(SignatureType::TEXT, created)
        .over_document(DOCUMENT)
}

/// The fingerprint of the key in `certificate` that a signature among
/// `signatures` over [`DOCUMENT`] is accepted from, under `policy` at `now`,
/// or the reason none is.
fn judge(
    certificate: &Certificate,
    signatures: &[&[u8]],
    policy: &Policy,
    now: u64,
) -> Result<Fingerprint, Reason> {
    let signatures: Vec<_> = signatures.iter().map(|data| forge::read(data)).collect();
    Keyring::new([certificate.clone()])
        .verify(policy, now, &signatures, DOCUMENT)
        .map(|verified| verified.key().fingerprint())
        .map_err(|refusal| refusal.reason())
}

/// [`judge`] under the default policy at [`NOW`].
fn verdict(certificate: &Certificate, signatures: &[&[u8]]) -> Result<Fingerprint, Reason> {
    judge(certificate, signatures, &Policy::new(), NOW)
}

/// Each key's window, or the reason it has none, primary first.
fn standings(certificate: &Certificate, now: u64) -> Vec<Result<Window, Reason>> {
    Authority::new(certificate, &Policy::new(), now)
        .signers()
        .map(|(_, standing)| standing)
        .collect()
}

/// A window from `created` until `expires`.
fn window(created: u32, expires: Option<u64>) -> Window {
    Window { created, expires }
}

/// The signatures made here verify, by every kind of key, over every kind of
/// subject, so a refusal in the tests below is the policy's.
#[test]
fn forged_signatures_verify() {
    let keys = [
        ed25519(1),
        Key::ed25519(2, Version::V6, CREATED),
        Key::rsa(Version::V4, CREATED),
    ];
    for key in &keys {
        let other = Key::ed25519(9, key.public().version(), CREATED);
        for hash in [HashAlgorithm::SHA256, HashAlgorithm::SHA512] {
            let document = forge::read(
                &key.sign(SignatureType::BINARY, SIGNED)
                    .hash(hash)
                    .over_document(DOCUMENT),
            );
            assert_eq!(
                document.verify(key.public(), Subject::Document(DOCUMENT)),
                Ok(())
            );
        }
        let text = forge::read(&signed(key, SIGNED));
        let crlf = DOCUMENT
            .iter()
            .flat_map(|&octet| {
                if octet == b'\n' {
                    vec![b'\r', b'\n']
                } else {
                    vec![octet]
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(text.verify(key.public(), Subject::Document(&crlf)), Ok(()));
        let user_id = forge::read(&certification(key, CREATED, None, None));
        let subject = Subject::UserId {
            key: key.public(),
            user_id: USER_ID.as_bytes(),
        };
        assert_eq!(user_id.verify(key.public(), subject), Ok(()));
        let bound = forge::read(&binding(key, &other, CREATED, SIGN));
        let subject = Subject::Subkey {
            primary: key.public(),
            subkey: other.public(),
        };
        assert_eq!(bound.verify(key.public(), subject), Ok(()));
        assert_eq!(
            bound.embedded_signatures()[0].verify(other.public(), subject),
            Ok(())
        );
        let direct = forge::read(&key.sign(SignatureType::DIRECT_KEY, CREATED).over_key(key));
        assert_eq!(
            direct.verify(key.public(), Subject::Key(key.public())),
            Ok(())
        );
    }
    // SHA-1, which only RSA verifies over.
    let rsa = &keys[2];
    let sha1 = forge::read(
        &rsa.sign(SignatureType::TEXT, SIGNED)
            .hash(HashAlgorithm::SHA1)
            .over_document(DOCUMENT),
    );
    assert_eq!(
        sha1.verify(rsa.public(), Subject::Document(DOCUMENT)),
        Ok(())
    );
}

#[test]
fn a_good_signature_verifies_and_a_tampered_or_foreign_one_does_not() {
    let primary = ed25519(1);
    let certificate = archive(&primary, &ed25519(2));
    let good = signed(&primary, SIGNED);
    assert_eq!(
        verdict(&certificate, &[&good]),
        Ok(primary.public().fingerprint())
    );

    let foreign = signed(&ed25519(3), SIGNED);
    assert_eq!(verdict(&certificate, &[&foreign]), Err(Reason::Unverified));

    let signature = forge::read(&good);
    let keyring = Keyring::new([certificate]);
    let tampered = keyring.verify(
        &Policy::new(),
        NOW,
        core::slice::from_ref(&signature),
        b"Suite: evil\n",
    );
    assert_eq!(tampered.unwrap_err().reason(), Reason::Unverified);
}

/// A document signed with a signing subkey verifies, and names both the
/// subkey that made the signature and the certificate it belongs to.
#[test]
fn a_subkey_signature_verifies() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let keyring = Keyring::new([archive(&primary, &subkey)]);
    let signature = forge::read(&signed(&subkey, SIGNED));
    let signatures = [signature];
    let verified = keyring
        .verify(&Policy::new(), NOW, &signatures, DOCUMENT)
        .unwrap();
    assert_eq!(verified.key(), subkey.public());
    assert_eq!(verified.certificate().primary(), primary.public());
    assert_eq!(verified.signature(), &signatures[0]);
}

#[test]
fn only_signing_subkeys_may_sign() {
    let (primary, signing, encrypting) = (ed25519(1), ed25519(2), ed25519(3));
    let certificate = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
        &signing.subkey(),
        &binding(&primary, &signing, CREATED, SIGN),
        &encrypting.subkey(),
        &primary
            .sign(SignatureType::SUBKEY_BINDING, CREATED)
            .key_flags(ENCRYPT)
            .over_subkey(&primary, &encrypting),
    ]);
    assert_eq!(
        standings(&certificate, NOW),
        [
            Ok(window(CREATED, None)),
            Ok(window(CREATED, None)),
            Err(Reason::SubkeyMayNotSign),
        ]
    );
    // The refusal says which key made the signature.
    let signature = forge::read(&signed(&encrypting, SIGNED));
    let keyring = Keyring::new([certificate]);
    let refusal = keyring
        .verify(
            &Policy::new(),
            NOW,
            core::slice::from_ref(&signature),
            DOCUMENT,
        )
        .unwrap_err();
    assert_eq!(refusal.reason(), Reason::SubkeyMayNotSign);
    assert_eq!(refusal.key(), Some(encrypting.public().fingerprint()));
    assert_eq!(refusal.certificate(), Some(primary.public().fingerprint()));
    assert_eq!(
        refusal.to_string(),
        format!(
            "the subkey that made the signature is not certified for signing (key {}, certificate {})",
            encrypting.public().fingerprint(),
            primary.public().fingerprint()
        )
    );
}

#[test]
fn a_revoked_subkey_is_refused() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let document = signed(&subkey, SIGNED);
    let certificate = archive(&primary, &subkey);
    assert!(verdict(&certificate, &[&document]).is_ok());

    let revocation = primary
        .sign(SignatureType::SUBKEY_REVOCATION, SIGNED)
        .over_subkey(&primary, &subkey);
    let revoked = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
        &subkey.subkey(),
        &revocation,
        &binding(&primary, &subkey, CREATED, SIGN),
    ]);
    assert_eq!(verdict(&revoked, &[&document]), Err(Reason::SubkeyRevoked));
}

/// A subkey whose binding gave it a day's life is refused for a signature
/// made years later: the expiration is read from the binding, relative to
/// the subkey's creation.
#[test]
fn a_signature_after_the_subkey_expired_is_refused() {
    // Made a hundred days after its primary key, which the expiration is
    // not relative to.
    let made = CREATED + 100 * DAY;
    let (primary, subkey) = (ed25519(1), Key::ed25519(2, Version::V4, made));
    let expiring = primary
        .sign(SignatureType::SUBKEY_BINDING, made)
        .key_flags(SIGN)
        .key_expiration(DAY)
        .embed(&back_signature(&primary, &subkey, made))
        .over_subkey(&primary, &subkey);
    let certificate = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
        &subkey.subkey(),
        &expiring,
    ]);
    let lapse = u64::from(made + DAY);
    assert_eq!(
        standings(&certificate, NOW)[1],
        Ok(window(made, Some(lapse)))
    );
    assert_eq!(
        verdict(&certificate, &[&signed(&subkey, SIGNED)]),
        Err(Reason::AfterKeyExpiration)
    );
    // Within the day, and at its last second, the subkey signed with
    // authority; at the lapse itself it no longer had any. Each is judged as
    // of when it was made, since judged later, the authority has lapsed.
    for (at, accepted) in [(made + DAY - 1, true), (made + DAY, false)] {
        let signature = signed(&subkey, at);
        assert_eq!(
            judge(&certificate, &[&signature], &Policy::new(), u64::from(at)).is_ok(),
            accepted,
            "{at}"
        );
    }
    assert_eq!(
        judge(
            &certificate,
            &[&signed(&subkey, made + DAY - 1)],
            &Policy::new(),
            lapse
        ),
        Err(Reason::KeyExpired)
    );
}

/// A key that has expired verifies nothing, not even a signature dated
/// within its life: a signature's date is its signer's claim, so the key's
/// holder could otherwise make new ones dated before the expiration. The
/// expiration counts the same wherever it is stated: as a key expiration or
/// a signature expiration, on the self-signature, the subkey binding, or the
/// back-signature.
#[test]
fn an_expired_key_verifies_nothing_however_its_expiration_is_stated() {
    let primary = ed25519(1);
    let subkey = ed25519(2);
    let lapse = CREATED + 10 * DAY;
    let user_id = forge::user_id(USER_ID);
    let by_primary = signed(&primary, CREATED + 5 * DAY);
    let by_subkey = signed(&subkey, CREATED + 5 * DAY);
    let back = back_signature(&primary, &subkey, CREATED);
    let certifying = certification(&primary, CREATED, Some(CERTIFY), None);
    let binding = || {
        primary
            .sign(SignatureType::SUBKEY_BINDING, CREATED)
            .key_flags(SIGN)
    };
    let cases = [
        (
            "key expiration on the self-signature",
            forge::certificate(&[
                &primary.primary(),
                &user_id,
                &certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(10 * DAY)),
            ]),
            &by_primary,
            Reason::KeyExpired,
        ),
        (
            "signature expiration on the self-signature",
            forge::certificate(&[
                &primary.primary(),
                &user_id,
                &primary
                    .sign(SignatureType::POSITIVE_CERTIFICATION, CREATED)
                    .key_flags(CERTIFY | SIGN)
                    .expiration(10 * DAY)
                    .over_user_id(&primary, USER_ID),
            ]),
            &by_primary,
            // Expired, the self-signature no longer binds the key.
            Reason::MissingSelfSignature,
        ),
        (
            "key expiration on the binding",
            forge::certificate(&[
                &primary.primary(),
                &user_id,
                &certifying,
                &subkey.subkey(),
                &binding()
                    .key_expiration(10 * DAY)
                    .embed(&back)
                    .over_subkey(&primary, &subkey),
            ]),
            &by_subkey,
            Reason::KeyExpired,
        ),
        (
            "signature expiration on the binding",
            forge::certificate(&[
                &primary.primary(),
                &user_id,
                &certifying,
                &subkey.subkey(),
                &binding()
                    .expiration(10 * DAY)
                    .embed(&back)
                    .over_subkey(&primary, &subkey),
            ]),
            &by_subkey,
            Reason::KeyExpired,
        ),
        (
            "signature expiration on the back-signature",
            forge::certificate(&[
                &primary.primary(),
                &user_id,
                &certifying,
                &subkey.subkey(),
                &binding()
                    .embed_hashed(
                        &subkey
                            .sign(SignatureType::PRIMARY_KEY_BINDING, CREATED)
                            .expiration(10 * DAY)
                            .over_subkey(&primary, &subkey),
                    )
                    .over_subkey(&primary, &subkey),
            ]),
            &by_subkey,
            Reason::KeyExpired,
        ),
    ];
    for (name, certificate, signature, refused) in &cases {
        let judged = |now: u32| judge(certificate, &[signature], &Policy::new(), u64::from(now));
        // Judged before the lapse, the signature is accepted, and at the
        // lapse and after, it is not.
        assert!(judged(CREATED + 5 * DAY).is_ok(), "{name}");
        assert!(judged(lapse - 1).is_ok(), "{name}");
        assert_eq!(judged(lapse), Err(*refused), "{name}");
        assert_eq!(judged(CREATED + 20 * DAY), Err(*refused), "{name}");
    }
}

/// A key made with a finite lifetime and later made not to expire: the
/// later self-signature, stating no expiration, governs, and lifts the
/// expiration the earlier one set.
#[test]
fn an_expiration_a_later_self_signature_drops_is_lifted() {
    let primary = ed25519(1);
    let expiring = certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(TWO_YEARS));
    let lifting = certification(&primary, 1_606_071_634, Some(CERTIFY | SIGN), None);
    let document = signed(&primary, SIGNED);
    let base = [primary.primary(), forge::user_id(USER_ID)];

    let only = forge::certificate(&[&base[0], &base[1], &expiring]);
    let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
    assert_eq!(standings(&only, NOW)[0], Ok(window(CREATED, Some(lapse))));
    assert_eq!(
        verdict(&only, &[&document]),
        Err(Reason::AfterKeyExpiration)
    );

    let lifted = forge::certificate(&[&base[0], &base[1], &expiring, &lifting]);
    assert_eq!(standings(&lifted, NOW)[0], Ok(window(CREATED, None)));
    assert!(verdict(&lifted, &[&document]).is_ok());
}

#[test]
fn a_later_self_signature_that_shortens_the_expiration_governs() {
    let primary = ed25519(1);
    let certificate = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(
            &primary,
            CREATED,
            Some(CERTIFY | SIGN),
            Some(10 * TWO_YEARS),
        ),
        &certification(
            &primary,
            1_606_071_634,
            Some(CERTIFY | SIGN),
            Some(TWO_YEARS),
        ),
    ]);
    let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
    assert_eq!(
        standings(&certificate, NOW)[0],
        Ok(window(CREATED, Some(lapse)))
    );
}

/// Recency is compared within one user ID. A user ID added later says
/// nothing of the expiration another's certification set, and its silence
/// does not lift it.
#[test]
fn an_expiration_is_not_lifted_by_a_certification_of_another_user_id() {
    let primary = ed25519(1);
    let second = "archive <second@example.invalid>";
    let certificate = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(TWO_YEARS)),
        &forge::user_id(second),
        &certification_of(&primary, second, 1_606_071_634, Some(CERTIFY | SIGN), None),
    ]);
    let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
    assert_eq!(
        standings(&certificate, NOW)[0],
        Ok(window(CREATED, Some(lapse)))
    );
}

/// A certification counts only once it verifies as the primary key's, so a
/// newer one another key made, whether it names that key as its issuer or
/// claims the primary key, lifts nothing.
#[test]
fn a_certification_the_primary_did_not_make_lifts_nothing() {
    let (primary, foreign) = (ed25519(1), ed25519(3));
    let expiring = certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(TWO_YEARS));
    let named = foreign
        .sign(SignatureType::POSITIVE_CERTIFICATION, 1_606_071_634)
        .key_flags(CERTIFY | SIGN)
        .over_user_id(&primary, USER_ID);
    let claiming = foreign
        .sign(SignatureType::POSITIVE_CERTIFICATION, 1_606_071_634)
        .bare()
        .hashed(
            crate::signature::SubpacketType::SIGNATURE_CREATION_TIME,
            &1_606_071_634_u32.to_be_bytes(),
        )
        .hashed(
            crate::signature::SubpacketType::ISSUER_FINGERPRINT,
            &[&[4][..], primary.public().fingerprint().as_bytes()].concat(),
        )
        .key_flags(CERTIFY | SIGN)
        .over_user_id(&primary, USER_ID);
    let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
    for forged in [named, claiming] {
        let certificate = forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &expiring,
            &forged,
        ]);
        assert_eq!(
            standings(&certificate, NOW)[0],
            Ok(window(CREATED, Some(lapse)))
        );
    }
}

/// Begins a signature by `key` of `signature_type`, made at `created`, that
/// names its issuer in its unhashed area alone, as GnuPG did before it
/// hashed the issuer's fingerprint: `key` if `truly`, and otherwise a key
/// that is not there. A version 4 signature names it by key ID, and a
/// version 6 one by fingerprint.
fn unhashed_issuer(
    key: &Key,
    signature_type: SignatureType,
    created: u32,
    truly: bool,
) -> forge::Signing<'_> {
    let signing = key.sign(signature_type, created).bare().hashed(
        SubpacketType::SIGNATURE_CREATION_TIME,
        &created.to_be_bytes(),
    );
    match key.public().version() {
        Version::V4 => {
            let key_id = if truly {
                *key.public().key_id().as_bytes()
            } else {
                [0x99; 8]
            };
            signing.unhashed(SubpacketType::ISSUER_KEY_ID, &key_id)
        }
        Version::V6 => {
            let fingerprint = if truly {
                key.public().fingerprint().as_bytes().to_vec()
            } else {
                vec![0x99; 32]
            };
            signing.unhashed(
                SubpacketType::ISSUER_FINGERPRINT,
                &[&[6][..], &fingerprint].concat(),
            )
        }
    }
}

/// Which key made a certificate's signature is established by verifying it,
/// not by the issuer it names, so a restriction that names its issuer in the
/// unhashed area alone restricts whatever that area says: anyone handling
/// the certificate can change it.
#[test]
fn an_issuer_hides_no_restriction() {
    for version in [Version::V4, Version::V6] {
        let primary = Key::ed25519(1, version, CREATED);
        let subkey = Key::ed25519(2, version, CREATED);
        let documents = [signed(&primary, SIGNED), signed(&subkey, SIGNED)];
        let direct = primary
            .sign(SignatureType::DIRECT_KEY, CREATED)
            .key_flags(CERTIFY | SIGN)
            .over_key(&primary);
        let with = |on_key: &[u8], on_user_id: &[u8], on_subkey: &[u8]| {
            forge::certificate(&[
                &primary.primary(),
                &direct,
                on_key,
                &forge::user_id(USER_ID),
                &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
                on_user_id,
                &subkey.subkey(),
                &binding(&primary, &subkey, CREATED, SIGN),
                on_subkey,
            ])
        };
        for document in &documents {
            assert!(verdict(&with(&[], &[], &[]), &[document]).is_ok());
        }
        let later = CREATED + DAY;
        for truly in [true, false] {
            let by = |signature_type| unhashed_issuer(&primary, signature_type, later, truly);
            let revocation = by(SignatureType::KEY_REVOCATION).over_key(&primary);
            let certifying = by(SignatureType::DIRECT_KEY)
                .key_flags(CERTIFY)
                .over_key(&primary);
            let withdrawn = by(SignatureType::CERTIFICATION_REVOCATION).over_key(&primary);
            let certifying_user_id = by(SignatureType::POSITIVE_CERTIFICATION)
                .key_flags(CERTIFY)
                .over_user_id(&primary, USER_ID);
            let subkey_revocation =
                by(SignatureType::SUBKEY_REVOCATION).over_subkey(&primary, &subkey);
            let encrypting = by(SignatureType::SUBKEY_BINDING)
                .key_flags(ENCRYPT)
                .over_subkey(&primary, &subkey);
            for (certificate, document, reason) in [
                (with(&revocation, &[], &[]), 0, Reason::CertificateRevoked),
                (with(&certifying, &[], &[]), 0, Reason::PrimaryMayNotSign),
                (
                    with(&[], &certifying_user_id, &[]),
                    0,
                    Reason::PrimaryMayNotSign,
                ),
                (with(&[], &[], &subkey_revocation), 1, Reason::SubkeyRevoked),
                (with(&[], &[], &encrypting), 1, Reason::SubkeyMayNotSign),
            ] {
                assert_eq!(
                    verdict(&certificate, &[&documents[document]]),
                    Err(reason),
                    "{version:?} {truly} {reason:?}"
                );
            }
            // The withdrawn direct-key signature no longer binds a version 6
            // key, and a version 4 key falls back on its user ID's.
            let expected = match version {
                Version::V4 => Ok(()),
                Version::V6 => Err(Reason::MissingDirectKeySignature),
            };
            assert_eq!(
                standings(&with(&withdrawn, &[], &[]), NOW)[0].map(|_| ()),
                expected,
                "{version:?} {truly}"
            );
        }

        // A back-signature's issuer neither withholds its consent nor lifts
        // the bound its expiration sets.
        let lapse = u64::from(CREATED) + u64::from(DAY);
        for truly in [true, false] {
            let expiring =
                unhashed_issuer(&subkey, SignatureType::PRIMARY_KEY_BINDING, CREATED, truly)
                    .expiration(DAY)
                    .over_subkey(&primary, &subkey);
            for embedded in [
                &[&expiring][..],
                &[&expiring, &back_signature(&primary, &subkey, CREATED)],
            ] {
                let mut signing = primary
                    .sign(SignatureType::SUBKEY_BINDING, CREATED)
                    .key_flags(SIGN);
                for back in embedded {
                    signing = signing.embed_hashed(back);
                }
                let certificate = forge::certificate(&[
                    &primary.primary(),
                    &direct,
                    &subkey.subkey(),
                    &signing.over_subkey(&primary, &subkey),
                ]);
                assert_eq!(
                    standings(&certificate, NOW)[1],
                    Ok(window(CREATED, Some(lapse))),
                    "{version:?} {truly}"
                );
            }
        }
    }
}

/// A subkey's authority is the primary key's to give, so it lapses when the
/// primary key's does, whatever its own binding says.
#[test]
fn an_expired_primary_cannot_sign_through_its_subkey() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let certificate = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(TWO_YEARS)),
        &subkey.subkey(),
        &binding(&primary, &subkey, CREATED, SIGN),
    ]);
    let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
    assert_eq!(
        standings(&certificate, NOW),
        [
            Ok(window(CREATED, Some(lapse))),
            Ok(window(CREATED, Some(lapse)))
        ]
    );
    assert_eq!(
        verdict(&certificate, &[&signed(&subkey, SIGNED)]),
        Err(Reason::AfterKeyExpiration)
    );
}

/// Every judgement is relative to a signature's creation time, which its
/// maker chooses; a signature without one does not read at all.
#[test]
fn a_signature_without_a_creation_time_is_not_read() {
    let primary = ed25519(1);
    let undated = primary
        .sign(SignatureType::BINARY, SIGNED)
        .bare()
        .over_document(DOCUMENT);
    let detached = crate::document::detached(&undated).unwrap();
    assert!(detached.signatures().is_empty());
    assert_eq!(
        detached.skipped()[0].kind(),
        crate::packet::PacketErrorKind::MissingCreationTime
    );
}

#[test]
fn a_signature_over_a_hash_the_policy_refuses_is_refused() {
    let rsa = Key::rsa(Version::V4, CREATED);
    let certificate = archive(&rsa, &ed25519(2));
    let sha1 = rsa
        .sign(SignatureType::TEXT, SIGNED)
        .hash(HashAlgorithm::SHA1)
        .over_document(DOCUMENT);
    assert_eq!(verdict(&certificate, &[&sha1]), Err(Reason::WeakHash));
    let accepting = Policy::new().with_hash(HashAlgorithm::SHA1, true);
    assert!(judge(&certificate, &[&sha1], &accepting, NOW).is_ok());
    // And a policy may refuse what the default accepts.
    let sha256 = signed(&rsa, SIGNED);
    let refusing = Policy::new().with_hash(HashAlgorithm::SHA256, false);
    assert_eq!(
        judge(&certificate, &[&sha256], &refusing, NOW),
        Err(Reason::WeakHash)
    );
}

/// A policy that holds a document to its exact octets refuses a text
/// signature, which verifies over the document with other line endings too,
/// and accepts a binary one; the refusal does not mask a binary signature
/// beside it. The default accepts both.
#[test]
fn a_policy_may_refuse_text_signatures() {
    let primary = ed25519(1);
    let certificate = archive(&primary, &ed25519(2));
    let text = signed(&primary, SIGNED);
    let binary = primary
        .sign(SignatureType::BINARY, SIGNED)
        .over_document(DOCUMENT);
    let fingerprint = primary.public().fingerprint();
    assert!(Policy::new().accepts_text_signatures());
    assert_eq!(verdict(&certificate, &[&text]), Ok(fingerprint));
    assert_eq!(verdict(&certificate, &[&binary]), Ok(fingerprint));

    let exact = Policy::new().with_text_signatures(false);
    assert!(!exact.accepts_text_signatures());
    assert_eq!(
        judge(&certificate, &[&text], &exact, NOW),
        Err(Reason::TextSignature)
    );
    assert_eq!(
        judge(&certificate, &[&binary], &exact, NOW),
        Ok(fingerprint)
    );
    assert_eq!(
        judge(&certificate, &[&text, &binary], &exact, NOW),
        Ok(fingerprint)
    );

    // The text signature verifies over the document with CR LF line endings
    // too; the binary one does not.
    let crlf: Vec<u8> = DOCUMENT
        .split(|&octet| octet == b'\n')
        .collect::<Vec<_>>()
        .join(&b"\r\n"[..]);
    for (signature, verifies) in [(&text, true), (&binary, false)] {
        let signatures = [forge::read(signature)];
        let accepted = Keyring::new([certificate.clone()])
            .verify(&Policy::new(), NOW, &signatures, &crlf)
            .is_ok();
        assert_eq!(accepted, verifies);
    }
}

/// A key that re-signs a document can leave the signature it replaced
/// beside the new one. The refused one, first, does not mask the accepted
/// one.
#[test]
fn a_refused_signature_does_not_mask_an_accepted_one_from_the_same_key() {
    let rsa = Key::rsa(Version::V4, CREATED);
    let certificate = archive(&rsa, &ed25519(2));
    let sha1 = rsa
        .sign(SignatureType::TEXT, SIGNED)
        .hash(HashAlgorithm::SHA1)
        .over_document(DOCUMENT);
    let sha256 = signed(&rsa, SIGNED);
    assert_eq!(
        verdict(&certificate, &[&sha1, &sha256]),
        Ok(rsa.public().fingerprint())
    );
}

/// The newest binding is the primary key's latest word on a subkey, so a
/// defect in it refuses the subkey rather than handing authority back to the
/// binding it superseded: one carrying a critical subpacket irongall does
/// not implement, and one over a hash the policy refuses.
#[test]
fn a_defective_newest_binding_refuses_rather_than_reviving_a_superseded_one() {
    let subkey = ed25519(2);
    for primary in [ed25519(1), Key::rsa(Version::V4, CREATED)] {
        let rsa = primary.public().algorithm() == crate::key::PublicKeyAlgorithm::RSA;
        let broad = binding(&primary, &subkey, CREATED, SIGN);
        let later = |flags: u8| {
            primary
                .sign(SignatureType::SUBKEY_BINDING, CREATED + DAY)
                .key_flags(flags)
                .embed(&back_signature(&primary, &subkey, CREATED + DAY))
        };
        // Withdrawing the grant, and renewing it, each with a defect.
        let mut defects = vec![
            (later(0).critical_notation(), Reason::UnhonoredBinding),
            (later(SIGN).critical_notation(), Reason::UnhonoredBinding),
        ];
        // Ed25519 verifies over no hash narrower than 256 bits.
        if rsa {
            defects.push((later(0).hash(HashAlgorithm::SHA1), Reason::SubkeyMayNotSign));
            defects.push((later(SIGN).hash(HashAlgorithm::SHA1), Reason::WeakBinding));
        }
        for (newest, reason) in defects {
            let certificate = forge::certificate(&[
                &primary.primary(),
                &forge::user_id(USER_ID),
                &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
                &subkey.subkey(),
                &broad,
                &newest.over_subkey(&primary, &subkey),
            ]);
            assert_eq!(standings(&certificate, NOW)[1], Err(reason), "{reason}");
            assert_eq!(
                verdict(&certificate, &[&signed(&subkey, SIGNED)]),
                Err(reason)
            );
        }
    }
}

/// Two bindings made in the same second, one of which irongall does not
/// honor: neither is newer, and the tie fails closed, whichever comes first.
#[test]
fn a_tie_between_bindings_fails_closed() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let honored = binding(&primary, &subkey, CREATED, SIGN);
    let unhonored = primary
        .sign(SignatureType::SUBKEY_BINDING, CREATED)
        .key_flags(SIGN)
        .embed(&back_signature(&primary, &subkey, CREATED))
        .critical_notation()
        .over_subkey(&primary, &subkey);
    for bindings in [[&honored, &unhonored], [&unhonored, &honored]] {
        let certificate = forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            &subkey.subkey(),
            bindings[0],
            bindings[1],
        ]);
        assert_eq!(
            standings(&certificate, NOW)[1],
            Err(Reason::UnhonoredBinding)
        );
    }
}

/// The binding alone is the primary key's claim over the subkey, which any
/// primary key can make about any key it has seen. The back-signature is the
/// subkey holder's own, and without one, or with one that does not count,
/// the subkey does not sign.
#[test]
fn a_signing_subkey_without_a_back_signature_is_refused() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let rsa = Key::rsa(Version::V4, CREATED);
    let unbacked = |back: Option<Vec<u8>>| {
        let mut signing = primary
            .sign(SignatureType::SUBKEY_BINDING, CREATED)
            .key_flags(SIGN);
        if let Some(back) = back {
            signing = signing.embed(&back);
        }
        forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            &subkey.subkey(),
            &signing.over_subkey(&primary, &subkey),
        ])
    };
    let refused = Err(Reason::MissingBackSignature);
    assert!(
        standings(
            &unbacked(Some(back_signature(&primary, &subkey, CREATED))),
            NOW
        )[1]
        .is_ok()
    );
    assert_eq!(standings(&unbacked(None), NOW)[1], refused);
    // Dated a day before the keys it speaks of existed.
    let early = back_signature(&primary, &subkey, CREATED - DAY);
    assert_eq!(standings(&unbacked(Some(early)), NOW)[1], refused);
    // Made by another key, or of another type.
    let foreign = back_signature(&primary, &ed25519(3), CREATED);
    assert_eq!(standings(&unbacked(Some(foreign)), NOW)[1], refused);
    let retyped = subkey
        .sign(SignatureType::SUBKEY_BINDING, CREATED)
        .over_subkey(&primary, &subkey);
    assert_eq!(standings(&unbacked(Some(retyped)), NOW)[1], refused);

    // Over a hash the policy refuses: an RSA subkey's SHA-1 back-signature.
    let certificate = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
        &rsa.subkey(),
        &primary
            .sign(SignatureType::SUBKEY_BINDING, CREATED)
            .key_flags(SIGN)
            .embed(
                &rsa.sign(SignatureType::PRIMARY_KEY_BINDING, CREATED)
                    .hash(HashAlgorithm::SHA1)
                    .over_subkey(&primary, &rsa),
            )
            .over_subkey(&primary, &rsa),
    ]);
    assert_eq!(standings(&certificate, NOW)[1], refused);

    // An undated back-signature does not read, and neither does the binding
    // that embeds it, which irongall then does not honor.
    let undated = subkey
        .sign(SignatureType::PRIMARY_KEY_BINDING, CREATED)
        .bare()
        .over_subkey(&primary, &subkey);
    assert_eq!(
        standings(&unbacked(Some(undated)), NOW)[1],
        Err(Reason::UnhonoredBinding)
    );
}

/// A back-signature's expiration bounds the consent it gives, and with it
/// the subkey's authority, where the binding covers it. Where a binding
/// carries several, the earliest expiration governs.
#[test]
fn an_expiring_back_signature_bounds_the_subkeys_authority() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let expiring = subkey
        .sign(SignatureType::PRIMARY_KEY_BINDING, CREATED)
        .expiration(DAY)
        .over_subkey(&primary, &subkey);
    let lasting = back_signature(&primary, &subkey, CREATED);
    for backs in [
        vec![&expiring],
        vec![&lasting, &expiring],
        vec![&expiring, &lasting],
    ] {
        let mut signing = primary
            .sign(SignatureType::SUBKEY_BINDING, CREATED)
            .key_flags(SIGN);
        for back in backs {
            signing = signing.embed_hashed(back);
        }
        let certificate = forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            &subkey.subkey(),
            &signing.over_subkey(&primary, &subkey),
        ]);
        let lapse = u64::from(CREATED + DAY);
        assert_eq!(
            standings(&certificate, NOW)[1],
            Ok(window(CREATED, Some(lapse)))
        );
        assert_eq!(
            verdict(&certificate, &[&signed(&subkey, SIGNED)]),
            Err(Reason::AfterKeyExpiration)
        );
    }
}

/// A back-signature's expiration holds only where the binding covers it. In
/// the hashed area, no change to the unhashed area lifts it. In the unhashed
/// area, it refuses the subkey: replacing it with an older back-signature
/// the subkey made over the same keys makes, octet for octet, the binding
/// GnuPG itself makes when it re-makes one, carrying the first
/// back-signature forward, and that binding is accepted as GnuPG's is. A
/// back-signature in the unhashed area that states no expiration gives its
/// consent, and an embedded signature that is not the subkey's consent
/// refuses nothing, wherever it is.
#[test]
fn a_back_signatures_expiration_holds_only_where_the_binding_covers_it() {
    for version in [Version::V4, Version::V6] {
        let primary = Key::ed25519(1, version, CREATED);
        let subkey = Key::ed25519(2, version, CREATED);
        let other = Key::ed25519(3, version, CREATED);
        let document = signed(&subkey, SIGNED);
        let later = CREATED + DAY;
        let direct = primary
            .sign(SignatureType::DIRECT_KEY, CREATED)
            .key_flags(CERTIFY | SIGN)
            .over_key(&primary);
        let older = binding(&primary, &subkey, CREATED, SIGN);
        let lasting = back_signature(&primary, &subkey, CREATED);
        let expiring_by = |key: &Key| {
            key.sign(SignatureType::PRIMARY_KEY_BINDING, later)
                .expiration(TWO_YEARS)
                .over_subkey(&primary, &subkey)
        };
        let expiring = expiring_by(&subkey);
        let newer = |hashed: &[&[u8]], unhashed: &[&[u8]]| {
            let mut signing = primary
                .sign(SignatureType::SUBKEY_BINDING, later)
                .key_flags(SIGN);
            for back in hashed {
                signing = signing.embed_hashed(back);
            }
            for back in unhashed {
                signing = signing.embed(back);
            }
            signing.over_subkey(&primary, &subkey)
        };
        let with = |newer: &[u8]| {
            forge::certificate(&[&primary.primary(), &direct, &subkey.subkey(), &older, newer])
        };
        let standing = |newer: &[u8]| standings(&with(newer), NOW)[1];
        let mut carried = Vec::new();
        forge::with_unhashed(&older, |area| {
            carried = area.to_vec();
            area.to_vec()
        });
        let bounded = Ok(window(
            CREATED,
            Some(u64::from(later) + u64::from(TWO_YEARS)),
        ));
        let unbounded = Ok(window(CREATED, None));

        let covered = newer(&[&expiring], &[]);
        assert_eq!(standing(&covered), bounded, "{version:?}");
        assert_eq!(
            verdict(&with(&covered), &[&document]),
            Err(Reason::AfterKeyExpiration)
        );
        for changed in [
            forge::with_unhashed(&covered, |_| carried.clone()),
            forge::with_unhashed(&covered, |area| [area, &carried].concat()),
            forge::with_unhashed(&covered, |_| Vec::new()),
        ] {
            assert_eq!(standing(&changed), bounded, "{version:?}");
        }

        let uncovered = newer(&[], &[&expiring]);
        assert_eq!(
            standing(&uncovered),
            Err(Reason::UnhonoredBinding),
            "{version:?}"
        );
        let added = forge::with_unhashed(&uncovered, |area| [area, &carried].concat());
        assert_eq!(standing(&added), Err(Reason::UnhonoredBinding));
        let emptied = forge::with_unhashed(&uncovered, |_| Vec::new());
        assert_eq!(standing(&emptied), Err(Reason::MissingBackSignature));
        let replaced = forge::with_unhashed(&uncovered, |_| carried.clone());
        assert_eq!(replaced, newer(&[], &[&lasting]), "{version:?}");
        assert_eq!(standing(&replaced), unbounded, "{version:?}");

        // Beside a covered back-signature, an uncovered one that states an
        // expiration still refuses; one that is not the subkey's does not.
        assert_eq!(
            standing(&newer(&[&lasting], &[&expiring])),
            Err(Reason::UnhonoredBinding),
            "{version:?}"
        );
        let foreign = expiring_by(&other);
        assert_eq!(
            standing(&newer(&[], &[&lasting, &foreign])),
            unbounded,
            "{version:?}"
        );
        assert_eq!(
            standing(&newer(&[], &[&foreign])),
            Err(Reason::MissingBackSignature),
            "{version:?}"
        );
    }
}

/// A binding's or a self-signature's own expiration ends what it grants. A
/// subkey's binding bounds the subkey's window. A user ID's certification
/// bounds the key's while it is in force; once it has expired, it no longer
/// binds the user ID, and says nothing about the key.
#[test]
fn an_expiring_self_signature_bounds_the_authority_it_grants() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let second = "archive <second@example.invalid>";
    let with = |others: &[u8]| {
        forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &primary
                .sign(SignatureType::POSITIVE_CERTIFICATION, CREATED)
                .key_flags(CERTIFY | SIGN)
                .expiration(TWO_YEARS)
                .over_user_id(&primary, USER_ID),
            others,
            &subkey.subkey(),
            &primary
                .sign(SignatureType::SUBKEY_BINDING, CREATED)
                .key_flags(SIGN)
                .expiration(DAY)
                .embed(&back_signature(&primary, &subkey, CREATED))
                .over_subkey(&primary, &subkey),
        ])
    };
    let (day, two_years) = (
        u64::from(CREATED + DAY),
        u64::from(CREATED) + u64::from(TWO_YEARS),
    );
    let alone = with(&[]);
    assert_eq!(
        standings(&alone, u64::from(CREATED + DAY / 2)),
        [
            Ok(window(CREATED, Some(two_years))),
            Ok(window(CREATED, Some(day)))
        ]
    );
    assert_eq!(
        standings(&alone, NOW),
        [Err(Reason::MissingSelfSignature); 2]
    );
    // Beside a user ID whose certification has not expired.
    let other = [
        forge::user_id(second),
        certification_of(&primary, second, CREATED, Some(CERTIFY | SIGN), None),
    ]
    .concat();
    assert_eq!(
        standings(&with(&other), NOW),
        [Ok(window(CREATED, None)), Ok(window(CREATED, Some(day)))]
    );
}

/// The newest self-signature governs only once it is in effect: one dated
/// after the time judged at, here silent about expiration, does not lift
/// the expiration in force.
#[test]
fn a_future_dated_self_signature_does_not_govern() {
    let primary = ed25519(1);
    let ahead = u32::try_from(NOW).unwrap() + 10 * TWO_YEARS / 2;
    let certificate = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(TWO_YEARS)),
        &certification(&primary, ahead, Some(CERTIFY | SIGN), None),
    ]);
    let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
    assert_eq!(
        standings(&certificate, NOW)[0],
        Ok(window(CREATED, Some(lapse)))
    );
    // Judged once it is in effect, it governs.
    assert_eq!(
        standings(&certificate, u64::from(ahead))[0],
        Ok(window(CREATED, None))
    );
}

/// The policy's RSA floor reads the modulus's width exactly.
#[test]
fn the_rsa_floor_reads_the_modulus() {
    let rsa = Key::rsa(Version::V4, CREATED);
    for bits in [1024_usize, 2047, 2048, 3072, 4096, 8192, 8193] {
        // The top bit set, so the modulus is exactly `bits` wide, and odd.
        let mut modulus = vec![0u8; bits.div_ceil(8)];
        modulus[0] = 1 << ((bits - 1) % 8);
        *modulus.last_mut().unwrap() |= 1;
        let integer = [&u16::try_from(bits).unwrap().to_be_bytes()[..], &modulus].concat();
        let body = [
            &[4][..],
            &CREATED.to_be_bytes(),
            &[1],
            &integer,
            &[0, 17, 1, 0, 1],
        ]
        .concat();
        let key = Key::with_body(&rsa, &body);
        let KeyMaterial::Rsa { modulus, .. } = key.public().material() else {
            panic!("an RSA key");
        };
        assert_eq!(crate::bignum::bit_length(modulus), bits);
        for floor in [2048, 3072] {
            assert_eq!(
                Policy::new()
                    .with_rsa_minimum_bits(floor)
                    .accepts_key(key.public()),
                (floor..=8192).contains(&bits),
                "{bits} against {floor}"
            );
        }
    }
    // A key of an algorithm irongall does not verify with is never
    // accepted.
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
    assert!(!Policy::new().accepts_key(Key::with_body(&rsa, &dsa).public()));
}

/// A key irongall refuses to verify with, whatever the signature, is not one
/// the policy accepts: a certificate resting on it is refused for its key,
/// and not for the signatures over it, none of which can verify.
#[test]
fn a_key_irongall_does_not_verify_with_is_refused_for_itself() {
    let rsa = Key::rsa(Version::V4, CREATED);
    let body = rsa.public().body();
    // [4, created, algorithm, n, e], each integer a two-octet bit count and
    // its octets.
    let n_end = 8 + usize::from(u16::from_be_bytes([body[6], body[7]])).div_ceil(8);
    let rsa_with = |algorithm: u8, low: u8, exponent: &[u8]| {
        let bits = exponent.len() * 8 - exponent[0].leading_zeros() as usize;
        let mut body = [
            &body[..n_end],
            &u16::try_from(bits).unwrap().to_be_bytes(),
            exponent,
        ]
        .concat();
        body[5] = algorithm;
        body[n_end - 1] = low;
        Key::with_body(&rsa, &body)
    };
    let low = body[n_end - 1];
    let f4 = [0x01, 0x00, 0x01];
    let ed = ed25519(1);
    let ed_with = |point: &[u8]| {
        let body = ed.public().body();
        Key::with_body(&ed, &[&body[..body.len() - 32], point].concat())
    };
    let identity = [&[1][..], &[0; 31]].concat();
    // The y-coordinate p, which encodes 0 non-canonically.
    let p = [&[0xED][..], &[0xFF; 30], &[0x7F]].concat();
    // Whether irongall verifies with each key, and if it does, whether the
    // forge's signatures verify with it: they do only where its material is
    // the forge's own.
    for (name, key, verifies) in [
        ("RSA", rsa_with(1, low, &f4), Some(true)),
        ("RSA sign-only", rsa_with(3, low, &f4), Some(true)),
        ("RSA encrypt-only", rsa_with(2, low, &f4), None),
        ("even modulus", rsa_with(1, low & 0xFE, &f4), None),
        ("e = 2^34 + 1", rsa_with(1, low, &[4, 0, 0, 0, 1]), None),
        (
            "e = 2^33 - 1",
            rsa_with(1, low, &[1, 0xFF, 0xFF, 0xFF, 0xFF]),
            Some(false),
        ),
        ("e = 65536", rsa_with(1, low, &[1, 0, 0]), None),
        ("e = 1", rsa_with(1, low, &[1]), None),
        ("e = 3", rsa_with(1, low, &[3]), Some(false)),
        ("Ed25519", ed.clone(), Some(true)),
        ("identity point", ed_with(&identity), None),
        ("non-canonical point", ed_with(&p), None),
    ] {
        assert_eq!(
            Policy::new().accepts_key(key.public()),
            verifies.is_some(),
            "{name}"
        );
        let certificate = forge::certificate(&[
            &key.primary(),
            &forge::user_id(USER_ID),
            &certification(&key, CREATED, Some(CERTIFY | SIGN), None),
        ]);
        let lapse = Authority::new(&certificate, &Policy::new(), NOW).lapse();
        let standing = standings(&archive(&ed25519(2), &key), NOW)[1];
        match verifies {
            None => {
                assert_eq!(lapse, Err(Reason::WeakPrimaryKey), "{name}");
                assert_eq!(standing, Err(Reason::WeakSubkey), "{name}");
            }
            Some(true) => {
                assert_eq!(lapse, Ok(None), "{name}");
                assert_eq!(standing, Ok(window(CREATED, None)), "{name}");
            }
            Some(false) => {
                assert_eq!(lapse, Err(Reason::MissingSelfSignature), "{name}");
                assert_eq!(standing, Err(Reason::MissingBackSignature), "{name}");
            }
        }
    }
}

/// A key the policy refuses grants nothing: as a primary key, its
/// certificate, and as a subkey, itself. A subkey it refuses is refused
/// before any signature over the subkey is verified.
#[test]
fn a_key_the_policy_refuses_cannot_sign() {
    let rsa = Key::rsa(Version::V4, CREATED);
    let strict = Policy::new().with_rsa_minimum_bits(3072);

    let certificate = archive(&rsa, &ed25519(2));
    let by_primary = signed(&rsa, SIGNED);
    let by_subkey = signed(&ed25519(2), SIGNED);
    assert!(verdict(&certificate, &[&by_primary]).is_ok());
    assert_eq!(
        judge(&certificate, &[&by_primary], &strict, NOW),
        Err(Reason::WeakPrimaryKey)
    );
    assert_eq!(
        judge(&certificate, &[&by_subkey], &strict, NOW),
        Err(Reason::WeakPrimaryKey)
    );

    let primary = ed25519(1);
    let certificate = archive(&primary, &rsa);
    assert!(verdict(&certificate, &[&by_primary]).is_ok());
    assert_eq!(
        judge(&certificate, &[&by_primary], &strict, NOW),
        Err(Reason::WeakSubkey)
    );

    // A subkey of an algorithm irongall does not verify with, bound but not
    // backed, and revoked: either would refuse it, but neither is verified,
    // since each is hashed over the whole subkey, which irongall does not
    // read and which may be as long as its packet.
    let body = [&[4][..], &CREATED.to_be_bytes(), &[100], &[0x5A; 60_000]].concat();
    let opaque = Key::with_body(&primary, &body);
    let bound = primary
        .sign(SignatureType::SUBKEY_BINDING, CREATED)
        .key_flags(SIGN)
        .over_subkey(&primary, &opaque);
    let revoked = primary
        .sign(SignatureType::SUBKEY_REVOCATION, CREATED + DAY)
        .over_subkey(&primary, &opaque);
    for signatures in [bound.clone(), [bound, revoked].concat()] {
        let certificate = forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            &opaque.subkey(),
            &signatures,
        ]);
        let (judged, work) = work::of(|| standings(&certificate, NOW));
        assert_eq!(judged[1], Err(Reason::WeakSubkey));
        assert!(work.hashed < 1000, "{work:?}");
    }
}

#[test]
fn a_signature_dated_before_its_key_existed_is_refused() {
    let primary = ed25519(1);
    let certificate = archive(&primary, &ed25519(2));
    assert_eq!(
        verdict(&certificate, &[&signed(&primary, CREATED - DAY)]),
        Err(Reason::BeforeKeyCreation)
    );
    assert!(verdict(&certificate, &[&signed(&primary, CREATED)]).is_ok());
}

/// A signature's expiration refuses it once passed, if the policy requires
/// fresh signatures; a stated zero means it does not expire.
#[test]
fn an_expired_signature_is_refused_when_fresh_ones_are_required() {
    let primary = ed25519(1);
    let certificate = archive(&primary, &ed25519(2));
    let expiring = |seconds: u32| {
        primary
            .sign(SignatureType::TEXT, SIGNED)
            .expiration(seconds)
            .over_document(DOCUMENT)
    };
    let pinned = Policy::new().with_fresh_signatures(false);
    for (seconds, fresh) in [(0, true), (DAY + 1, true), (DAY, false), (1, false)] {
        let signature = expiring(seconds);
        let expected = if fresh {
            Ok(primary.public().fingerprint())
        } else {
            Err(Reason::SignatureExpired)
        };
        assert_eq!(verdict(&certificate, &[&signature]), expected, "{seconds}");
        assert!(judge(&certificate, &[&signature], &pinned, NOW).is_ok());
    }
}

/// A primary key whose self-signatures grant it only certification is an
/// anchor for the subkeys it binds, and does not sign documents itself.
#[test]
fn a_certify_only_primary_cannot_sign_a_document() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let certificate = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(&primary, CREATED, Some(CERTIFY), None),
        &subkey.subkey(),
        &binding(&primary, &subkey, CREATED, SIGN),
    ]);
    assert_eq!(
        verdict(&certificate, &[&signed(&primary, SIGNED)]),
        Err(Reason::PrimaryMayNotSign)
    );
    assert!(verdict(&certificate, &[&signed(&subkey, SIGNED)]).is_ok());
}

/// A certificate lapses at the earliest of its primary key's expirations and
/// those of the self-signatures in force, whether or not its primary key may
/// sign, and every key's window closes by then. One whose self-signatures
/// are no longer in force grants nothing, and has no lapse.
#[test]
fn a_certificate_lapses_whether_or_not_its_primary_may_sign() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let judged = |certification: &[u8], now: u64| {
        let certificate = forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            certification,
            &subkey.subkey(),
            &binding(&primary, &subkey, CREATED, SIGN),
        ]);
        let authority = Authority::new(&certificate, &Policy::new(), now);
        let standings: Vec<_> = authority.signers().map(|(_, standing)| standing).collect();
        (authority.lapse(), standings)
    };
    let two_years = u64::from(CREATED) + u64::from(TWO_YEARS);

    // Certify-only, so the primary key signs nothing, expiring long before
    // the time judged at: the lapse is still the key's expiration.
    let expiring = certification(&primary, CREATED, Some(CERTIFY), Some(TWO_YEARS));
    assert_eq!(
        judged(&expiring, NOW),
        (
            Ok(Some(two_years)),
            vec![
                Err(Reason::PrimaryMayNotSign),
                Ok(window(CREATED, Some(two_years)))
            ]
        )
    );
    let unbounded = certification(&primary, CREATED, Some(CERTIFY), None);
    assert_eq!(judged(&unbounded, NOW).0, Ok(None));

    // A self-signature that expires before the key does bounds the lapse
    // while it is in force, and once it has expired binds nothing.
    let short = primary
        .sign(SignatureType::POSITIVE_CERTIFICATION, CREATED)
        .key_flags(CERTIFY)
        .key_expiration(TWO_YEARS)
        .expiration(DAY)
        .over_user_id(&primary, USER_ID);
    let day = u64::from(CREATED + DAY);
    assert_eq!(
        judged(&short, u64::from(CREATED + DAY / 2)),
        (
            Ok(Some(day)),
            vec![
                Err(Reason::PrimaryMayNotSign),
                Ok(window(CREATED, Some(day)))
            ]
        )
    );
    assert_eq!(
        judged(&short, NOW),
        (
            Err(Reason::MissingSelfSignature),
            vec![Err(Reason::MissingSelfSignature); 2]
        )
    );
}

/// What a primary key may do is what its governing self-signatures state.
/// One stating no key flags grants nothing and takes no part; where two
/// state different flags, the narrower holds.
#[test]
fn a_self_signature_stating_no_key_flags_grants_nothing() {
    let primary = ed25519(1);
    let second = "archive <second@example.invalid>";
    let document = signed(&primary, SIGNED);
    let certified = |flags: [Option<u8>; 2]| {
        let certificate = forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &certification(&primary, CREATED, flags[0], None),
            &forge::user_id(second),
            &certification_of(&primary, second, CREATED, flags[1], None),
        ]);
        verdict(&certificate, &[&document])
    };
    let signs = Some(CERTIFY | SIGN);
    assert!(certified([signs, signs]).is_ok());
    assert!(certified([signs, None]).is_ok());
    assert_eq!(certified([None, None]), Err(Reason::PrimaryMayNotSign));
    assert_eq!(
        certified([signs, Some(CERTIFY)]),
        Err(Reason::PrimaryMayNotSign)
    );
}

/// A direct-key signature is a self-signature over the primary key alone,
/// governing beside the user IDs' certifications.
#[test]
fn a_direct_key_signature_governs_the_primary_key() {
    let primary = ed25519(1);
    let direct = |flags: u8, expires: Option<u32>| {
        let mut signing = primary
            .sign(SignatureType::DIRECT_KEY, CREATED)
            .key_flags(flags);
        if let Some(expires) = expires {
            signing = signing.key_expiration(expires);
        }
        signing.over_key(&primary)
    };
    let certified = certification(&primary, CREATED, Some(CERTIFY | SIGN), None);
    let with = |direct: &[u8]| {
        forge::certificate(&[
            &primary.primary(),
            direct,
            &forge::user_id(USER_ID),
            &certified,
        ])
    };
    assert_eq!(
        standings(&with(&direct(CERTIFY | SIGN, None)), NOW)[0],
        Ok(window(CREATED, None))
    );
    assert_eq!(
        standings(&with(&direct(CERTIFY, None)), NOW)[0],
        Err(Reason::PrimaryMayNotSign)
    );
    let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
    assert_eq!(
        standings(&with(&direct(CERTIFY | SIGN, Some(TWO_YEARS))), NOW)[0],
        Ok(window(CREATED, Some(lapse)))
    );
    // Alone, with no user ID.
    let bare = forge::certificate(&[&primary.primary(), &direct(CERTIFY | SIGN, None)]);
    assert_eq!(standings(&bare, NOW)[0], Ok(window(CREATED, None)));
}

/// RFC 9580 §5.2.3.10: a version 6 key is not used without a valid
/// direct-key signature, which keeps an adversary from stripping one that
/// states an expiration.
#[test]
fn a_version_6_certificate_needs_a_direct_key_signature() {
    let primary = Key::ed25519(1, Version::V6, CREATED);
    let certified = certification(&primary, CREATED, Some(CERTIFY | SIGN), None);
    let direct = primary
        .sign(SignatureType::DIRECT_KEY, CREATED)
        .key_flags(CERTIFY | SIGN)
        .over_key(&primary);
    let document = signed(&primary, SIGNED);
    let without = forge::certificate(&[&primary.primary(), &forge::user_id(USER_ID), &certified]);
    assert_eq!(
        verdict(&without, &[&document]),
        Err(Reason::MissingDirectKeySignature)
    );
    let with = forge::certificate(&[
        &primary.primary(),
        &direct,
        &forge::user_id(USER_ID),
        &certified,
    ]);
    assert_eq!(
        verdict(&with, &[&document]),
        Ok(primary.public().fingerprint())
    );
    // A version 4 certificate needs none.
    let v4 = ed25519(1);
    let certificate = forge::certificate(&[
        &v4.primary(),
        &forge::user_id(USER_ID),
        &certification(&v4, CREATED, Some(CERTIFY | SIGN), None),
    ]);
    assert!(verdict(&certificate, &[&signed(&v4, SIGNED)]).is_ok());
}

/// A self-signature the primary key withdrew, with a certification
/// revocation no older than it, neither grants nor restricts: its user ID is
/// no longer the key's, and says nothing about it. So a key whose expiration
/// was extended after one of its user IDs was revoked, which leaves that user
/// ID's last certification stating the old one, is held to the new.
#[test]
fn a_withdrawn_self_signature_neither_grants_nor_restricts() {
    let primary = ed25519(1);
    let second = "archive <second@example.invalid>";
    let document = signed(&primary, SIGNED);
    let withdrawing = |user_id: &str, created: u32| {
        primary
            .sign(SignatureType::CERTIFICATION_REVOCATION, created)
            .hashed(
                crate::signature::SubpacketType::REASON_FOR_REVOCATION,
                &[32],
            )
            .over_user_id(&primary, user_id)
    };
    let grant = certification(&primary, CREATED, Some(CERTIFY | SIGN), None);
    let one = |revocation: &[u8]| {
        forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &grant,
            revocation,
        ])
    };
    // The only certification, withdrawn later or in the same second, leaves
    // nothing to bind the key.
    for created in [CREATED + DAY, CREATED] {
        assert_eq!(
            verdict(&one(&withdrawing(USER_ID, created)), &[&document]),
            Err(Reason::MissingSelfSignature)
        );
    }
    // A revocation older than the certification is answered by it.
    assert!(verdict(&one(&withdrawing(USER_ID, CREATED - 1)), &[&document]).is_ok());
    // One another key made withdraws nothing.
    let foreign = ed25519(3)
        .sign(SignatureType::CERTIFICATION_REVOCATION, CREATED + DAY)
        .over_user_id(&primary, USER_ID);
    assert!(verdict(&one(&foreign), &[&document]).is_ok());

    // Beside another user ID's grant: its expiration no longer bounds the
    // key, its key flags no longer deny signing, and it is not the primary
    // user ID however it is marked.
    let two = |first: &[u8]| {
        forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            first,
            &withdrawing(USER_ID, CREATED + DAY),
            &forge::user_id(second),
            &certification_of(&primary, second, CREATED, Some(CERTIFY | SIGN), None),
        ])
    };
    let expiring = primary
        .sign(SignatureType::POSITIVE_CERTIFICATION, CREATED)
        .key_flags(CERTIFY | SIGN)
        .key_expiration(TWO_YEARS)
        .primary_user_id()
        .over_user_id(&primary, USER_ID);
    let certificate = two(&expiring);
    assert_eq!(standings(&certificate, NOW)[0], Ok(window(CREATED, None)));
    let authority = Authority::new(&certificate, &Policy::new(), NOW);
    assert_eq!(
        authority.primary_user_id().map(|user_id| user_id.value()),
        Some(second.as_bytes())
    );
    let certifying = certification(&primary, CREATED, Some(CERTIFY), None);
    assert!(verdict(&two(&certifying), &[&document]).is_ok());
    assert!(verdict(&two(&grant), &[&document]).is_ok());
    // Not withdrawn, each still restricts.
    let unwithdrawn = |first: &[u8]| {
        forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            first,
            &forge::user_id(second),
            &certification_of(&primary, second, CREATED, Some(CERTIFY | SIGN), None),
        ])
    };
    let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
    assert_eq!(
        standings(&unwithdrawn(&expiring), NOW)[0],
        Ok(window(CREATED, Some(lapse)))
    );
    assert_eq!(
        verdict(&unwithdrawn(&certifying), &[&document]),
        Err(Reason::PrimaryMayNotSign)
    );

    // Withdrawn by a revocation irongall does not honor, it refuses the
    // certificate: what that revocation withdraws, irongall cannot tell.
    let unhonored = primary
        .sign(SignatureType::CERTIFICATION_REVOCATION, CREATED + DAY)
        .critical_notation()
        .over_user_id(&primary, USER_ID);
    for certificate in [
        one(&unhonored),
        unwithdrawn(&[&grant[..], &unhonored].concat()),
    ] {
        assert_eq!(
            verdict(&certificate, &[&document]),
            Err(Reason::UnhonoredSelfSignature)
        );
    }

    // A direct-key signature withdrawn neither grants nor restricts either,
    // and is no version 6 certificate's direct-key signature.
    for version in [Version::V4, Version::V6] {
        let primary = Key::ed25519(1, version, CREATED);
        let direct = primary
            .sign(SignatureType::DIRECT_KEY, CREATED)
            .key_flags(CERTIFY | SIGN)
            .over_key(&primary);
        let withdrawn = primary
            .sign(SignatureType::CERTIFICATION_REVOCATION, CREATED + DAY)
            .over_key(&primary);
        let certificate = forge::certificate(&[&primary.primary(), &direct, &withdrawn]);
        let expected = match version {
            Version::V4 => Reason::MissingSelfSignature,
            Version::V6 => Reason::MissingDirectKeySignature,
        };
        assert_eq!(standings(&certificate, NOW)[0], Err(expected));
        let certificate = forge::certificate(&[&primary.primary(), &direct]);
        assert!(standings(&certificate, NOW)[0].is_ok());
    }
}

/// A certification revocation of a direct-key signature withdraws it
/// wherever it is placed. A User ID, User Attribute, or subkey packet put
/// before it, which no signature covers, does not move it onto another
/// subject, and one that follows a user ID withdraws no certification of
/// that user ID.
#[test]
fn a_withdrawal_stands_wherever_it_is_placed() {
    for version in [Version::V4, Version::V6] {
        let primary = Key::ed25519(1, version, CREATED);
        let document = signed(&primary, SIGNED);
        let direct = primary
            .sign(SignatureType::DIRECT_KEY, CREATED)
            .key_flags(CERTIFY | SIGN)
            .key_expiration(TWO_YEARS)
            .over_key(&primary);
        let withdrawn = primary
            .sign(SignatureType::CERTIFICATION_REVOCATION, CREATED + DAY)
            .over_key(&primary);
        let attribute = forge::packet(Tag::USER_ATTRIBUTE, &[0x05, 0x01, 0x00]);
        let subkey = Key::ed25519(2, version, CREATED).subkey();
        let expected = match version {
            Version::V4 => Reason::MissingSelfSignature,
            Version::V6 => Reason::MissingDirectKeySignature,
        };
        let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
        let certificate = forge::certificate(&[&primary.primary(), &direct]);
        assert_eq!(
            standings(&certificate, NOW)[0],
            Ok(window(CREATED, Some(lapse)))
        );
        for inserted in [&[][..], &forge::user_id(USER_ID), &attribute, &subkey] {
            let certificate =
                forge::certificate(&[&primary.primary(), &direct, inserted, &withdrawn]);
            assert_eq!(
                verdict(&certificate, &[&document]),
                Err(expected),
                "{version:?} {inserted:?}"
            );
        }

        // After a user ID's certification, it withdraws the direct-key
        // signature and leaves the certification in force: the key is no
        // longer bound by the direct-key signature's expiration.
        let certified = forge::certificate(&[
            &primary.primary(),
            &direct,
            &forge::user_id(USER_ID),
            &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            &withdrawn,
        ]);
        let expected = match version {
            Version::V4 => Ok(window(CREATED, None)),
            Version::V6 => Err(Reason::MissingDirectKeySignature),
        };
        assert_eq!(standings(&certified, NOW)[0], expected, "{version:?}");
    }
}

/// A statement over a user ID or a subkey restricts wherever it is placed.
/// A packet put before it, which no signature covers, places it with
/// another part, or with something passed over, or where its type does not
/// belong; moved, it follows another part. Each restriction is found
/// wherever it is, and refuses as it does in place: a revoked subkey, a
/// newer binding that withholds signing, a newer certification that
/// shortens the key's life or withholds signing, and the withdrawal of the
/// one certification that bound the key.
#[test]
fn a_statement_restricts_wherever_it_is_placed() {
    let mut tried = 0;
    for version in [Version::V4, Version::V6] {
        let primary = Key::ed25519(1, version, CREATED);
        let subkey = Key::ed25519(2, version, CREATED);
        let documents = [signed(&primary, SIGNED), signed(&subkey, SIGNED)];
        let later = CREATED + DAY;
        let second = "second <second@example.invalid>";
        let direct = primary
            .sign(SignatureType::DIRECT_KEY, CREATED)
            .key_flags(CERTIFY | SIGN)
            .over_key(&primary);
        // The packets before the restriction, and the document it refuses.
        let base = |with_direct: bool| {
            let mut packets = vec![primary.primary()];
            if with_direct {
                packets.push(direct.clone());
            }
            packets.extend([
                forge::user_id(USER_ID),
                certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
                forge::user_id(second),
                certification_of(&primary, second, CREATED, Some(CERTIFY | SIGN), None),
                subkey.subkey(),
                binding(&primary, &subkey, CREATED, SIGN),
            ]);
            packets
        };
        let cases = [
            (
                base(true),
                primary
                    .sign(SignatureType::SUBKEY_REVOCATION, later)
                    .over_subkey(&primary, &subkey),
                1,
                Reason::SubkeyRevoked,
            ),
            (
                base(true),
                primary
                    .sign(SignatureType::SUBKEY_BINDING, later)
                    .key_flags(ENCRYPT)
                    .over_subkey(&primary, &subkey),
                1,
                Reason::SubkeyMayNotSign,
            ),
            (
                base(true),
                certification(&primary, later, Some(CERTIFY | SIGN), Some(TWO_YEARS)),
                0,
                Reason::AfterKeyExpiration,
            ),
            (
                base(true),
                certification_of(&primary, second, later, Some(CERTIFY), None),
                0,
                Reason::PrimaryMayNotSign,
            ),
            (
                // Without a direct-key signature, so that the user IDs
                // alone bind the key: the second's certification withdrawn,
                // and the restriction withdrawing the first's.
                [
                    &base(false)[..5],
                    &[primary
                        .sign(SignatureType::CERTIFICATION_REVOCATION, later)
                        .over_user_id(&primary, second)],
                ]
                .concat(),
                primary
                    .sign(SignatureType::CERTIFICATION_REVOCATION, later)
                    .over_user_id(&primary, USER_ID),
                0,
                match version {
                    Version::V4 => Reason::MissingSelfSignature,
                    Version::V6 => Reason::MissingDirectKeySignature,
                },
            ),
        ];
        let inserted = [
            forge::user_id("inserted <inserted@example.invalid>"),
            forge::user_id(USER_ID),
            forge::user_id(second),
            forge::user_id(&"x".repeat(2049)),
            forge::packet(Tag::USER_ATTRIBUTE, &[0x05, 0x01, 0x00]),
            Key::ed25519(9, version, CREATED).subkey(),
            subkey.subkey(),
            // A subkey of the other version, and one that does not read.
            Key::ed25519(9, other_version(version), CREATED).subkey(),
            forge::packet(Tag::PUBLIC_SUBKEY, &[0x04, 0, 0]),
        ];
        for (packets, restriction, document, reason) in cases {
            let parts = |packets: &[Vec<u8>]| {
                let parts: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
                forge::certificate(&parts)
            };
            let document = &documents[document];
            if version == Version::V4 || reason != Reason::MissingDirectKeySignature {
                assert!(verdict(&parts(&packets), &[document]).is_ok(), "{reason:?}");
            }
            let mut rewrites = Vec::new();
            // In place, then after each packet: moved before the parts, or
            // after another part or its signatures.
            for at in 1..=packets.len() {
                let mut rewrite = packets.clone();
                rewrite.insert(at, restriction.clone());
                rewrites.push(rewrite);
            }
            for packet in &inserted {
                let mut rewrite = packets.clone();
                rewrite.extend([packet.clone(), restriction.clone()]);
                rewrites.push(rewrite);
            }
            for rewrite in rewrites {
                assert_eq!(
                    verdict(&parts(&rewrite), &[document]),
                    Err(reason),
                    "{version:?} {reason:?}\n{:?}",
                    parts(&rewrite)
                );
                // Combined with a copy that lacks the restriction, in either
                // order, it still restricts.
                for keyring in [
                    Keyring::new([parts(&packets), parts(&rewrite)]),
                    Keyring::new([parts(&rewrite), parts(&packets)]),
                ] {
                    assert_eq!(
                        judge(&keyring.certificates()[0], &[document], &Policy::new(), NOW),
                        Err(reason),
                        "{version:?} {reason:?} combined"
                    );
                }
                tried += 1;
            }
        }
    }
    assert_eq!(tried, 2 * (4 * (8 + 9) + (6 + 9)));
}

/// A certificate of `primary`, bound by a direct-key signature to certify
/// and sign, with a user ID for each of `user_ids`, the first certified by
/// the primary key, and `foreign` placed after it: certifications by another
/// key, which verify over nothing as the primary key's, and so are tried
/// over every user ID.
fn with_foreign(primary: &Key, user_ids: &[String], foreign: &[Vec<u8>]) -> Certificate {
    let mut packets = vec![
        primary.primary(),
        primary
            .sign(SignatureType::DIRECT_KEY, CREATED)
            .key_flags(CERTIFY | SIGN)
            .over_key(primary),
    ];
    for (at, user_id) in user_ids.iter().enumerate() {
        packets.push(forge::user_id(user_id));
        if at == 0 {
            packets.push(certification_of(primary, user_id, CREATED, None, None));
            packets.extend_from_slice(foreign);
        }
    }
    let parts: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
    forge::certificate(&parts)
}

/// The octets of every signature `certificate` holds, as the search for
/// what they are over is bounded by.
fn signature_octets(certificate: &Certificate) -> usize {
    let mut all: Vec<&Signature> = certificate.primary_signatures().iter().collect();
    for user_id in certificate.user_ids() {
        all.extend(user_id.signatures());
    }
    let (unplaced, _) = certificate.unplaced_signatures();
    all.extend(unplaced);
    all.iter().map(|signature| signature.length()).sum()
}

/// Searching for what a certificate's signatures are over is bounded by the
/// certificate's own size. Certifications another key made over user IDs,
/// which every certificate may carry, are each tried over every user ID:
/// a few hundred over several user IDs are well within the bound, and the
/// certificate is judged as it would be without them. The same signatures,
/// each tried over hundreds of user IDs that cost little to add, are not,
/// and the certificate grants nothing. Holding a certificate twice changes
/// neither, even at the point where one turns into the other.
#[test]
fn the_search_for_what_a_signature_is_over_is_bounded() {
    let primary = ed25519(1);
    let stranger = ed25519(5);
    let document = signed(&primary, SIGNED);
    let user_ids =
        |count: usize| -> Vec<String> { (0..count).map(|at| format!("u{at}")).collect() };
    let foreign = |count: usize, user_id: &str| -> Vec<Vec<u8>> {
        (0..count)
            .map(|at| {
                stranger
                    .sign(SignatureType::GENERIC_CERTIFICATION, CREATED + at as u32)
                    .over_user_id(&primary, user_id)
            })
            .collect()
    };

    let carried = with_foreign(&primary, &user_ids(8), &foreign(200, "u0"));
    let (verdict_carried, work) = work::of(|| verdict(&carried, &[&document]));
    assert_eq!(verdict_carried, Ok(primary.public().fingerprint()));
    let authority = Authority::new(&carried, &Policy::new(), NOW);
    assert_eq!(
        authority.primary_user_id().map(UserId::value),
        Some(&b"u0"[..])
    );
    // Each is checked by its equation once, over the user ID it follows,
    // where its hash prefix matches, and over the seven others its prefix
    // rules it out: the rest are the primary key's two self-signatures and
    // the document's signature.
    assert_eq!(work.operations, 200 + 3);
    let bound = 128 * signature_octets(&carried) as u64;
    assert!(work.hashed < bound, "{work:?} {bound}");

    let crowded = with_foreign(&primary, &user_ids(300), &foreign(50, "u0"));
    let (refused, work) = work::of(|| verdict(&crowded, &[&document]));
    assert_eq!(refused, Err(Reason::UnattributedSignatures));
    assert!(
        work.hashed <= 128 * signature_octets(&crowded) as u64 + 4096,
        "{work:?}"
    );
    let authority = Authority::new(&crowded, &Policy::new(), NOW);
    assert_eq!(authority.lapse(), Err(Reason::UnattributedSignatures));
    assert_eq!(authority.primary_user_id(), None);

    // Ten such certifications, tried over ever more user IDs.
    let mut turned = None;
    for count in 60..140 {
        let certificate = with_foreign(&primary, &user_ids(count), &foreign(10, "u0"));
        let once = standings(&certificate, NOW);
        let keyring = Keyring::new([certificate.clone(), certificate]);
        assert_eq!(standings(&keyring.certificates()[0], NOW), once, "{count}");
        let unbounded = once[0] == Err(Reason::UnattributedSignatures);
        match turned {
            None if unbounded => turned = Some(count),
            None => assert!(once[0].is_ok()),
            Some(_) => assert!(unbounded, "{count}"),
        }
    }
    // Every try is charged what it hashes and a fixed overhead, so where the
    // bound falls is exact: a change to either moves it.
    assert_eq!(turned, Some(109));
}

/// A user ID over which `signature`, a version 4 certification, has the
/// hash prefix it carries, though not the key's equation: one found by
/// trying names, as anyone can, since everything a signature is hashed
/// over is public.
fn colliding_user_id(primary: &Key, signature: &Signature, from: usize) -> (String, usize) {
    let trailer = |fields: &[u8]| {
        let length = u32::try_from(fields.len()).unwrap().to_be_bytes();
        [fields, &[4, 0xFF][..], &length].concat()
    };
    let key = crate::test_support::hashed_key(primary.public().body());
    let fields = trailer(signature.hashed_fields());
    (from..)
        .map(|at| (format!("collides {at}"), at))
        .find(|(user_id, _)| {
            let data = [
                &key[..],
                &crate::test_support::hashed_user_id(user_id.as_bytes()),
                &fields,
            ]
            .concat();
            let digest = crate::test_support::digest(signature.hash_algorithm(), &data);
            digest.as_bytes()[..2] == signature.hash_prefix()
        })
        .unwrap()
}

/// The search checks no more signatures by their equation than the
/// certificate holds. A signature's hash prefix lets an equation be
/// skipped, but anyone can find user IDs over which a signature's prefix
/// matches, so each is tried by its equation: past the bound, the
/// certificate grants nothing.
#[test]
fn the_search_checks_no_more_equations_than_there_are_signatures() {
    let primary = ed25519(1);
    let stranger = ed25519(5);
    let document = signed(&primary, SIGNED);
    let foreign = stranger
        .sign(SignatureType::GENERIC_CERTIFICATION, CREATED)
        .over_user_id(&primary, "u0");
    let signature = forge::read(&foreign);
    let mut colliding = Vec::new();
    let mut from = 0;
    for _ in 0..4 {
        let (user_id, at) = colliding_user_id(&primary, &signature, from);
        colliding.push(user_id);
        from = at + 1;
    }
    // The direct-key signature, the first user ID's certification, and the
    // foreign one: three equations, and each user ID a collision costs one.
    for (count, expected) in [
        (3, Ok(primary.public().fingerprint())),
        (4, Err(Reason::UnattributedSignatures)),
    ] {
        let mut user_ids = vec!["u0".to_string()];
        user_ids.extend(colliding[..count].iter().cloned());
        let certificate = with_foreign(&primary, &user_ids, core::slice::from_ref(&foreign));
        let (judged, work) = work::of(|| verdict(&certificate, &[&document]));
        assert_eq!(judged, expected, "{count}");
        assert!(work.operations <= 3 + 4 + 1, "{work:?}");
    }
}

/// The other of the two key versions.
fn other_version(version: Version) -> Version {
    match version {
        Version::V4 => Version::V6,
        Version::V6 => Version::V4,
    }
}

/// A user ID or subkey held twice is one, judged from every signature over
/// either copy. So a copy with only an older signature over it revives
/// nothing that a revocation or a newer signature withdrew, whether it comes
/// before them or after.
#[test]
fn a_repeated_part_revives_nothing() {
    for version in [Version::V4, Version::V6] {
        let primary = Key::ed25519(1, version, CREATED);
        let subkey = Key::ed25519(2, version, CREATED);
        let documents = [signed(&primary, SIGNED), signed(&subkey, SIGNED)];
        let direct = primary
            .sign(SignatureType::DIRECT_KEY, CREATED)
            .key_flags(CERTIFY | SIGN)
            .over_key(&primary);
        let later = CREATED + DAY;
        let user_id = [
            &forge::user_id(USER_ID)[..],
            &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
        ]
        .concat();
        let bound = [
            &subkey.subkey()[..],
            &binding(&primary, &subkey, CREATED, SIGN),
        ]
        .concat();
        let restrictions: [(&[u8], &[u8], usize, Reason); 3] = [
            (
                &user_id,
                &certification(&primary, later, Some(CERTIFY), None),
                0,
                Reason::PrimaryMayNotSign,
            ),
            (
                &bound,
                &primary
                    .sign(SignatureType::SUBKEY_REVOCATION, later)
                    .over_subkey(&primary, &subkey),
                1,
                Reason::SubkeyRevoked,
            ),
            (
                &bound,
                &primary
                    .sign(SignatureType::SUBKEY_BINDING, later)
                    .key_flags(ENCRYPT)
                    .over_subkey(&primary, &subkey),
                1,
                Reason::SubkeyMayNotSign,
            ),
        ];
        let key = primary.primary();
        for (copy, restriction, document, reason) in restrictions {
            let with = |parts: &[&[u8]]| {
                let mut all: Vec<&[u8]> = vec![&key, &direct];
                all.extend(parts);
                forge::certificate(&all)
            };
            let document = &documents[document];
            assert!(verdict(&with(&[copy]), &[document]).is_ok());
            let restricted = [copy, restriction].concat();
            for parts in [[&restricted[..], copy], [copy, &restricted]] {
                let certificate = with(&parts);
                assert_eq!(
                    certificate.user_ids().len() + certificate.subkeys().len(),
                    1
                );
                assert_eq!(
                    verdict(&certificate, &[document]),
                    Err(reason),
                    "{version:?} {reason:?}"
                );
            }
        }
    }

    // A user ID whose certification was withdrawn, repeated with that
    // certification alone, is still withdrawn.
    let primary = ed25519(1);
    let document = signed(&primary, SIGNED);
    let certified = [
        &forge::user_id(USER_ID)[..],
        &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
    ]
    .concat();
    let withdrawn = [
        &certified[..],
        &primary
            .sign(SignatureType::CERTIFICATION_REVOCATION, CREATED + DAY)
            .over_user_id(&primary, USER_ID),
    ]
    .concat();
    assert!(
        verdict(
            &forge::certificate(&[&primary.primary(), &certified]),
            &[&document]
        )
        .is_ok()
    );
    for parts in [[&withdrawn, &certified], [&certified, &withdrawn]] {
        let certificate = forge::certificate(&[&primary.primary(), parts[0], parts[1]]);
        assert_eq!(
            verdict(&certificate, &[&document]),
            Err(Reason::MissingSelfSignature)
        );
    }
}

/// A certificate whose primary key has revoked itself grants nothing, to
/// the primary key or its subkeys, whenever the revocation was made and for
/// whatever reason. One made by another key revokes nothing.
#[test]
fn a_revoked_certificate_grants_nothing() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let documents = [signed(&primary, SIGNED), signed(&subkey, SIGNED)];
    let with = |revocation: &[u8]| {
        forge::certificate(&[
            &primary.primary(),
            revocation,
            &forge::user_id(USER_ID),
            &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            &subkey.subkey(),
            &binding(&primary, &subkey, CREATED, SIGN),
        ])
    };
    // Superseded (1), with no reason, and dated after the documents.
    let superseded = primary
        .sign(SignatureType::KEY_REVOCATION, CREATED + DAY)
        .hashed(crate::signature::SubpacketType::REASON_FOR_REVOCATION, &[1])
        .over_key(&primary);
    let later = primary
        .sign(SignatureType::KEY_REVOCATION, SIGNED + 1)
        .over_key(&primary);
    for revocation in [&superseded, &later] {
        let certificate = with(revocation);
        for document in &documents {
            assert_eq!(
                verdict(&certificate, &[document]),
                Err(Reason::CertificateRevoked)
            );
        }
    }
    let foreign = ed25519(3)
        .sign(SignatureType::KEY_REVOCATION, CREATED)
        .over_key(&primary);
    assert!(verdict(&with(&foreign), &[&documents[0]]).is_ok());
}

/// A signature irongall does not honor, for a critical subpacket it does not
/// implement, grants nothing, but still restricts: as a revocation it
/// revokes, and as the governing self-signature it refuses the certificate
/// rather than letting an older one govern.
#[test]
fn an_unhonored_signature_restricts_but_does_not_grant() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let documents = [signed(&primary, SIGNED), signed(&subkey, SIGNED)];
    let certified = certification(&primary, CREATED + 1, Some(CERTIFY | SIGN), None);
    let parts = |before_user_id: &[u8], after_user_id: &[u8], on_subkey: &[u8]| {
        forge::certificate(&[
            &primary.primary(),
            before_user_id,
            &forge::user_id(USER_ID),
            &certified,
            after_user_id,
            &subkey.subkey(),
            on_subkey,
            &binding(&primary, &subkey, CREATED, SIGN),
        ])
    };

    let revocation = primary
        .sign(SignatureType::KEY_REVOCATION, CREATED + DAY)
        .critical_notation()
        .over_key(&primary);
    let certificate = parts(&revocation, &[], &[]);
    assert_eq!(certificate.skipped().len(), 1);
    assert!(certificate.primary_signatures().is_empty());
    assert_eq!(
        verdict(&certificate, &[&documents[0]]),
        Err(Reason::CertificateRevoked)
    );

    let subkey_revocation = primary
        .sign(SignatureType::SUBKEY_REVOCATION, CREATED + DAY)
        .critical_notation()
        .over_subkey(&primary, &subkey);
    let certificate = parts(&[], &[], &subkey_revocation);
    assert_eq!(
        verdict(&certificate, &[&documents[1]]),
        Err(Reason::SubkeyRevoked)
    );
    assert!(verdict(&certificate, &[&documents[0]]).is_ok());

    let newer = primary
        .sign(SignatureType::POSITIVE_CERTIFICATION, CREATED + DAY)
        .key_flags(CERTIFY | SIGN)
        .critical_notation()
        .over_user_id(&primary, USER_ID);
    let certificate = parts(&[], &newer, &[]);
    for document in &documents {
        assert_eq!(
            verdict(&certificate, &[document]),
            Err(Reason::UnhonoredSelfSignature)
        );
    }
    // An older one does not govern, and refuses nothing.
    let older = primary
        .sign(SignatureType::POSITIVE_CERTIFICATION, CREATED)
        .critical_notation()
        .over_user_id(&primary, USER_ID);
    assert!(verdict(&parts(&[], &older, &[]), &[&documents[0]]).is_ok());
    // Nor does one another key made.
    let foreign = ed25519(3)
        .sign(SignatureType::KEY_REVOCATION, CREATED + DAY)
        .critical_notation()
        .over_key(&primary);
    assert!(verdict(&parts(&foreign, &[], &[]), &[&documents[0]]).is_ok());
}

/// What anyone who handles a signature can append to its unhashed area, each
/// damaged: a Signature Expiration Time of one octet rather than four, an
/// Issuer Key ID of two octets rather than eight, an Embedded Signature that
/// does not read, and a subpacket whose length runs past the area's end.
const DAMAGE: [&[u8]; 4] = [
    &[0x02, 0x03, 0x00],
    &[0x03, 0x10, 0x00, 0x00],
    &[0x03, 0x20, 0x04, 0x00],
    &[0x05, 0x10],
];

/// A Signature packet changed where no signature covers it.
#[derive(Debug)]
struct Altered {
    /// How it was changed.
    how: String,
    /// For a change to how the integers of its material are written, how
    /// they are.
    encoding: Option<forge::Encoding>,
    /// The packet.
    packet: Vec<u8>,
    /// Whether it still reads as a signature irongall honors.
    reads: bool,
    /// Whether irongall honors it as a certificate's statement: it reads,
    /// and its hash prefix is its hash's.
    honored: bool,
}

/// The ways anyone who handles `signature` can change it without touching
/// what its signature covers: its unhashed area damaged as each of
/// [`DAMAGE`] damages it, its hash prefix inverted, an octet appended after
/// its material, and the integers of its material written each way
/// [`forge::Encoding`] names, where they can be. Version 4 tolerates an
/// integer whose length counts leading zeros, so such a signature is still
/// honored; nothing else is.
fn altered(signature: &[u8]) -> Vec<Altered> {
    let version = forge::read(signature).version();
    let mut altered: Vec<Altered> = DAMAGE
        .iter()
        .map(|damage| Altered {
            how: format!("unhashed {damage:02X?}"),
            encoding: None,
            packet: forge::with_unhashed(signature, |area| [area, damage].concat()),
            reads: false,
            honored: false,
        })
        .collect();
    altered.push(Altered {
        how: "prefix".to_string(),
        encoding: None,
        packet: forge::with_prefix_inverted(signature),
        reads: true,
        honored: false,
    });
    altered.push(Altered {
        how: "appended".to_string(),
        encoding: None,
        packet: forge::with_appended(signature, &[0x00]),
        reads: false,
        honored: false,
    });
    for encoding in forge::Encoding::ALL {
        if let Some(packet) = forge::with_integers(signature, encoding) {
            let tolerated = version == Version::V4 && encoding.tolerated_in_version_4();
            altered.push(Altered {
                how: format!("{encoding:?}"),
                encoding: Some(encoding),
                packet,
                reads: tolerated,
                honored: tolerated,
            });
        }
    }
    for altered in &altered {
        let packet = packet::packets(&altered.packet).next().unwrap().unwrap();
        assert_eq!(
            Signature::from_packet(&packet).is_ok(),
            altered.reads,
            "{}",
            altered.how
        );
        assert!(
            Signature::from_packet_unhonored(&packet).is_ok(),
            "{}",
            altered.how
        );
    }
    altered
}

/// The primary keys of the certificates the tests alter: Ed25519 and RSA,
/// each in version 4 and version 6, with an Ed25519 subkey of the same
/// version.
fn primaries() -> [(Key, Key); 4] {
    [Version::V4, Version::V6]
        .map(|version| Key::ed25519(1, version, CREATED))
        .into_iter()
        .chain([Version::V4, Version::V6].map(|version| Key::rsa(version, CREATED)))
        .map(|primary| {
            let subkey = Key::ed25519(2, primary.public().version(), CREATED);
            (primary, subkey)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// A signature changed where its signer's signature does not cover it,
/// which anyone who handles the certificate can do, grants nothing, unless
/// it still reads and verifies as it was made. What it restricts, it still
/// restricts: a revocation still revokes, and a newer self-signature or
/// binding that withholds signing, or the withdrawal of a self-signature,
/// refuses the certificate or the subkey rather than letting what it
/// superseded govern. The changes: its unhashed area damaged, its hash
/// prefix inverted, an octet appended after its material, and the integers
/// of its material written other than exactly. Finding what each is over
/// takes the public-key operations it took before it was changed: one, over
/// the part it is placed with.
#[test]
fn a_restriction_altered_where_nothing_covers_it_still_restricts() {
    let mut encodings = Vec::new();
    for (primary, subkey) in primaries() {
        let version = primary.public().version();
        let documents = [signed(&primary, SIGNED), signed(&subkey, SIGNED)];
        let later = CREATED + DAY;
        let direct = |created: u32, flags: u8| {
            primary
                .sign(SignatureType::DIRECT_KEY, created)
                .key_flags(flags)
                .over_key(&primary)
        };
        // Where a signature goes: after the direct-key signature, after the
        // user ID's certification, or after the subkey's binding.
        const ON_KEY: usize = 0;
        const ON_USER_ID: usize = 1;
        const ON_SUBKEY: usize = 2;
        let with = |slot: usize, signature: &[u8]| {
            let mut slots: [&[u8]; 3] = [&[]; 3];
            slots[slot] = signature;
            forge::certificate(&[
                &primary.primary(),
                &direct(CREATED, CERTIFY | SIGN),
                slots[ON_KEY],
                &forge::user_id(USER_ID),
                &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
                slots[ON_USER_ID],
                &subkey.subkey(),
                &binding(&primary, &subkey, CREATED, SIGN),
                slots[ON_SUBKEY],
            ])
        };
        for document in &documents {
            assert!(verdict(&with(ON_KEY, &[]), &[document]).is_ok());
        }

        let revocation = primary
            .sign(SignatureType::KEY_REVOCATION, later)
            .over_key(&primary);
        let withholding_user_id = certification(&primary, later, Some(CERTIFY), None);
        let subkey_revocation = primary
            .sign(SignatureType::SUBKEY_REVOCATION, later)
            .over_subkey(&primary, &subkey);
        let withholding_binding = primary
            .sign(SignatureType::SUBKEY_BINDING, later)
            .key_flags(ENCRYPT)
            .over_subkey(&primary, &subkey);
        let withdrawal = primary
            .sign(SignatureType::CERTIFICATION_REVOCATION, later)
            .over_key(&primary);
        let cases: [(usize, &[u8], usize, Reason, Reason); 5] = [
            (
                ON_KEY,
                &revocation,
                0,
                Reason::CertificateRevoked,
                Reason::CertificateRevoked,
            ),
            (
                ON_KEY,
                &direct(later, CERTIFY),
                0,
                Reason::PrimaryMayNotSign,
                Reason::UnhonoredSelfSignature,
            ),
            (
                ON_USER_ID,
                &withholding_user_id,
                0,
                Reason::PrimaryMayNotSign,
                Reason::UnhonoredSelfSignature,
            ),
            (
                ON_SUBKEY,
                &subkey_revocation,
                1,
                Reason::SubkeyRevoked,
                Reason::SubkeyRevoked,
            ),
            (
                ON_SUBKEY,
                &withholding_binding,
                1,
                Reason::SubkeyMayNotSign,
                Reason::UnhonoredBinding,
            ),
        ];
        for (slot, restriction, document, undamaged, reason) in cases {
            let document = &documents[document];
            let attributed = |certificate: &Certificate| {
                work::of(|| Statements::of(certificate, &Policy::new())).1
            };
            let as_made = attributed(&with(slot, restriction));
            assert_eq!(
                verdict(&with(slot, restriction), &[document]),
                Err(undamaged)
            );
            for altered in altered(restriction) {
                let expected = if altered.honored { undamaged } else { reason };
                let certificate = with(slot, &altered.packet);
                assert_eq!(
                    verdict(&certificate, &[document]),
                    Err(expected),
                    "{version:?} {undamaged:?} {}",
                    altered.how
                );
                assert_eq!(
                    attributed(&certificate).operations,
                    as_made.operations,
                    "{}",
                    altered.how
                );
                if let Some(encoding) = altered.encoding {
                    encodings.push((version, encoding, altered.honored));
                }
            }
        }
        // Withdrawn, the direct-key signature no longer binds a version 6
        // key; altered, the withdrawal leaves it in force, unhonored. So
        // too after the user ID, where the withdrawal is tried over the user
        // ID and then over the primary key alone.
        let undamaged = match version {
            Version::V4 => Ok(()),
            Version::V6 => Err(Reason::MissingDirectKeySignature),
        };
        for slot in [ON_KEY, ON_USER_ID] {
            assert_eq!(
                standings(&with(slot, &withdrawal), NOW)[0].map(|_| ()),
                undamaged
            );
            for altered in altered(&withdrawal) {
                let certificate = with(slot, &altered.packet);
                let expected = if altered.honored {
                    undamaged
                } else {
                    Err(Reason::UnhonoredSelfSignature)
                };
                assert_eq!(
                    standings(&certificate, NOW)[0].map(|_| ()),
                    expected,
                    "{version:?} {slot} {}",
                    altered.how
                );
            }
        }

        // The only binding, altered, grants nothing, and is recorded as
        // passed over where it does not read.
        for altered in altered(&binding(&primary, &subkey, CREATED, SIGN)) {
            let certificate = forge::certificate(&[
                &primary.primary(),
                &direct(CREATED, CERTIFY | SIGN),
                &subkey.subkey(),
                &altered.packet,
            ]);
            let expected = if altered.honored {
                Ok(subkey.public().fingerprint())
            } else {
                Err(Reason::UnhonoredBinding)
            };
            assert_eq!(
                verdict(&certificate, &[&documents[1]]),
                expected,
                "{version:?} {}",
                altered.how
            );
            assert_eq!(
                certificate.skipped().len(),
                usize::from(!altered.reads),
                "{}",
                altered.how
            );
        }
    }
    // Every way of writing an integer was tried in both versions, and
    // version 4 tolerated all but one.
    for version in [Version::V4, Version::V6] {
        for encoding in forge::Encoding::ALL {
            let tried: Vec<bool> = encodings
                .iter()
                .filter(|&&(held, written, _)| held == version && written == encoding)
                .map(|&(_, _, honored)| honored)
                .collect();
            assert!(!tried.is_empty(), "{version:?} {encoding:?}");
            let tolerated = version == Version::V4 && encoding.tolerated_in_version_4();
            assert!(tried.iter().all(|&honored| honored == tolerated));
        }
    }
}

/// A signature by a key a certificate does not hold, or over another type
/// of subject, verifies nothing: a standalone signature, for one, is not
/// over the document.
#[test]
fn only_a_signature_over_the_document_verifies_it() {
    let primary = ed25519(1);
    let certificate = archive(&primary, &ed25519(2));
    let standalone = primary.sign(SignatureType::STANDALONE, SIGNED).over(&[]);
    assert_eq!(
        verdict(&certificate, &[&standalone]),
        Err(Reason::Unverified)
    );
    let binary = primary
        .sign(SignatureType::BINARY, SIGNED)
        .over_document(DOCUMENT);
    assert!(verdict(&certificate, &[&binary]).is_ok());
}

/// Each signature is hashed over the whole document and tried with every
/// key that may have made it, so the number a document may carry is
/// bounded.
#[test]
fn a_document_carrying_too_many_signatures_is_refused() {
    let primary = ed25519(1);
    let certificate = archive(&primary, &ed25519(2));
    let signature = signed(&primary, SIGNED);
    let at_bound: Vec<&[u8]> = vec![&signature; 16];
    assert!(verdict(&certificate, &at_bound).is_ok());
    let over: Vec<&[u8]> = vec![&signature; 17];
    assert_eq!(verdict(&certificate, &over), Err(Reason::TooManySignatures));
    let raised = Policy::new().with_max_signatures(17);
    assert!(judge(&certificate, &over, &raised, NOW).is_ok());
    // Every signature the document carries counts, those that cannot be
    // hashed over it among them.
    let standalone = primary.sign(SignatureType::STANDALONE, SIGNED).over(&[]);
    let mut mixed = at_bound.clone();
    mixed.push(&standalone);
    assert_eq!(
        verdict(&certificate, &mixed),
        Err(Reason::TooManySignatures)
    );
}

/// The primary user ID: one marked primary, else the one certified most
/// recently, else the first; only those whose certification verifies.
#[test]
fn the_primary_user_id() {
    let primary = ed25519(1);
    let foreign = ed25519(3);
    let names = ["first", "second", "third"];
    let with = |certifications: [Vec<u8>; 3]| {
        let packets: Vec<Vec<u8>> = names
            .iter()
            .zip(certifications)
            .flat_map(|(name, certification)| [forge::user_id(name), certification])
            .collect();
        let mut all = vec![primary.primary()];
        all.extend(packets);
        let parts: Vec<&[u8]> = all.iter().map(Vec::as_slice).collect();
        let certificate = forge::certificate(&parts);
        Authority::new(&certificate, &Policy::new(), NOW)
            .primary_user_id()
            .map(|user_id| user_id.value().to_vec())
    };
    let plain =
        |name: &str, created: u32| certification_of(&primary, name, created, Some(SIGN), None);
    let marked = |name: &str, created: u32| {
        primary
            .sign(SignatureType::POSITIVE_CERTIFICATION, created)
            .key_flags(SIGN)
            .primary_user_id()
            .over_user_id(&primary, name)
    };
    assert_eq!(
        with([
            plain("first", CREATED),
            plain("second", CREATED),
            plain("third", CREATED)
        ]),
        Some(b"first".to_vec())
    );
    assert_eq!(
        with([
            plain("first", CREATED),
            plain("second", CREATED + 1),
            plain("third", CREATED)
        ]),
        Some(b"second".to_vec())
    );
    assert_eq!(
        with([
            plain("first", CREATED + 1),
            plain("second", CREATED),
            marked("third", CREATED)
        ]),
        Some(b"third".to_vec())
    );
    let forged = foreign
        .sign(SignatureType::POSITIVE_CERTIFICATION, CREATED + 1)
        .primary_user_id()
        .over_user_id(&primary, "first");
    assert_eq!(
        with([
            forged,
            plain("second", CREATED),
            plain("third", CREATED + 1)
        ]),
        Some(b"third".to_vec())
    );
}

/// A certificate grants nothing unless a self-signature in force binds its
/// primary key. Its subkeys rest on that binding: without it, removing the
/// self-signatures that state the key's expiration would lift it for them.
#[test]
fn a_certificate_no_self_signature_binds_grants_nothing() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let document = signed(&subkey, SIGNED);
    let bound = binding(&primary, &subkey, CREATED, SIGN);
    let with = |self_signatures: &[u8]| {
        forge::certificate(&[
            &primary.primary(),
            self_signatures,
            &subkey.subkey(),
            &bound,
        ])
    };
    let certified = |certification: &[u8]| [&forge::user_id(USER_ID)[..], certification].concat();
    let expiring = certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(TWO_YEARS));
    assert_eq!(
        verdict(&with(&certified(&expiring)), &[&document]),
        Err(Reason::AfterKeyExpiration)
    );
    // Stripped of its user ID.
    let stripped = with(&[]);
    assert_eq!(
        standings(&stripped, NOW),
        [Err(Reason::MissingSelfSignature); 2]
    );
    assert_eq!(
        verdict(&stripped, &[&document]),
        Err(Reason::MissingSelfSignature)
    );
    // Certified only by a signature that does not count: one another key
    // made, or one dated after the time judged at.
    let foreign = ed25519(3)
        .sign(SignatureType::POSITIVE_CERTIFICATION, CREATED)
        .key_flags(CERTIFY | SIGN)
        .over_user_id(&primary, USER_ID);
    let ahead = u32::try_from(NOW).unwrap() + DAY;
    let postdated = certification(&primary, ahead, Some(CERTIFY | SIGN), None);
    for certification in [foreign, postdated] {
        assert_eq!(
            verdict(&with(&certified(&certification)), &[&document]),
            Err(Reason::MissingSelfSignature)
        );
    }
    // A direct-key signature binds it alone.
    let direct = primary
        .sign(SignatureType::DIRECT_KEY, CREATED)
        .key_flags(CERTIFY)
        .over_key(&primary);
    assert_eq!(
        verdict(&with(&direct), &[&document]),
        Ok(subkey.public().fingerprint())
    );
}

/// Self-signatures or bindings made in the same second are all the newest.
/// Packet order, which no signature covers, decides nothing: what they state
/// is combined restrictively, whichever comes first. The earliest expiration
/// holds, and one that does not grant signing denies it.
#[test]
fn signatures_made_in_the_same_second_are_combined_restrictively() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let document = signed(&subkey, SIGNED);
    let lasting = certification(&primary, CREATED, Some(CERTIFY | SIGN), None);
    let expiring = certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(TWO_YEARS));
    let certifying = certification(&primary, CREATED, Some(CERTIFY), None);
    let signing = binding(&primary, &subkey, CREATED, SIGN);
    let with = |certifications: [&[u8]; 2], bindings: [&[u8]; 2]| {
        forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            certifications[0],
            certifications[1],
            &subkey.subkey(),
            bindings[0],
            bindings[1],
        ])
    };

    // Over a user ID.
    let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
    for pair in [[&lasting, &expiring], [&expiring, &lasting]] {
        let certificate = with([pair[0], pair[1]], [&signing, &[]]);
        assert_eq!(
            standings(&certificate, NOW),
            [Ok(window(CREATED, Some(lapse))); 2]
        );
        assert_eq!(
            verdict(&certificate, &[&document]),
            Err(Reason::AfterKeyExpiration)
        );
    }
    for pair in [[&lasting, &certifying], [&certifying, &lasting]] {
        let certificate = with([pair[0], pair[1]], [&signing, &[]]);
        assert_eq!(
            standings(&certificate, NOW)[0],
            Err(Reason::PrimaryMayNotSign)
        );
    }
    // A second later, the newer alone governs.
    let later = certification(&primary, CREATED + 1, Some(CERTIFY | SIGN), None);
    assert_eq!(
        standings(&with([&expiring, &later], [&signing, &[]]), NOW)[0],
        Ok(window(CREATED, None))
    );

    // Over a subkey.
    let expiring = primary
        .sign(SignatureType::SUBKEY_BINDING, CREATED)
        .key_flags(SIGN)
        .key_expiration(DAY)
        .embed(&back_signature(&primary, &subkey, CREATED))
        .over_subkey(&primary, &subkey);
    let encrypting = binding(&primary, &subkey, CREATED, ENCRYPT);
    for pair in [[&signing, &expiring], [&expiring, &signing]] {
        let certificate = with([&lasting, &[]], [pair[0], pair[1]]);
        assert_eq!(
            standings(&certificate, NOW)[1],
            Ok(window(CREATED, Some(u64::from(CREATED + DAY))))
        );
    }
    for pair in [[&signing, &encrypting], [&encrypting, &signing]] {
        let certificate = with([&lasting, &[]], [pair[0], pair[1]]);
        assert_eq!(
            standings(&certificate, NOW)[1],
            Err(Reason::SubkeyMayNotSign)
        );
    }
}

/// A signature dated after the time judged at, by more than the clock skew
/// the policy tolerates, claims a time not yet reached: as a document's
/// signature it is refused, as a self-signature it does not govern, and as a
/// back-signature it gives no consent. Within the skew, it counts as made.
#[test]
fn a_postdated_signature_is_refused() {
    let (primary, subkey) = (ed25519(1), ed25519(2));
    let certificate = archive(&primary, &subkey);
    let now = u32::try_from(NOW).unwrap();
    let skew = 30 * 60;
    assert_eq!(Policy::new().clock_skew(), u64::from(skew));
    let exact = Policy::new().with_clock_skew(0);
    for (made, policy, accepted) in [
        (now + skew, Policy::new(), true),
        (now + skew + 1, Policy::new(), false),
        (4_000_000_000, Policy::new(), false),
        (now, exact.clone(), true),
        (now + 1, exact, false),
    ] {
        let expected = if accepted {
            Ok(subkey.public().fingerprint())
        } else {
            Err(Reason::Postdated)
        };
        assert_eq!(
            judge(&certificate, &[&signed(&subkey, made)], &policy, NOW),
            expected,
            "{made}"
        );
    }

    let expiring = certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(TWO_YEARS));
    let renewed = |made: u32| {
        forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &expiring,
            &certification(&primary, made, Some(CERTIFY | SIGN), None),
        ])
    };
    let lapse = u64::from(CREATED) + u64::from(TWO_YEARS);
    assert_eq!(
        standings(&renewed(now + skew), NOW)[0],
        Ok(window(CREATED, None))
    );
    assert_eq!(
        standings(&renewed(now + skew + 1), NOW)[0],
        Ok(window(CREATED, Some(lapse)))
    );

    // A back-signature dated later gives no consent yet, though the binding
    // that embeds it is in effect.
    let consenting = |made: u32| {
        forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            &subkey.subkey(),
            &primary
                .sign(SignatureType::SUBKEY_BINDING, CREATED)
                .key_flags(SIGN)
                .embed(&back_signature(&primary, &subkey, made))
                .over_subkey(&primary, &subkey),
        ])
    };
    let document = signed(&subkey, SIGNED);
    for (made, policy, accepted) in [
        (now + skew, Policy::new(), true),
        (now + skew + 1, Policy::new(), false),
        (now + DAY, Policy::new(), false),
        (now, Policy::new().with_clock_skew(0), true),
        (now + 1, Policy::new().with_clock_skew(0), false),
    ] {
        let expected = if accepted {
            Ok(subkey.public().fingerprint())
        } else {
            Err(Reason::MissingBackSignature)
        };
        assert_eq!(
            judge(&consenting(made), &[&document], &policy, NOW),
            expected,
            "{made}"
        );
    }
}

/// A self-signature over the primary key made before 1 February 2023 grants
/// over a hash the policy refuses as over any other: here, a newer SHA-1
/// certification lifts an older one's expiration. A user ID certified over
/// such a hash is the primary user ID only if no other user ID that is
/// marked primary as often is certified over a hash the policy accepts.
#[test]
fn a_self_signature_over_a_weak_hash_grants_but_is_not_preferred() {
    // RSA, since Ed25519 verifies over no hash narrower than 256 bits.
    let primary = Key::rsa(Version::V4, CREATED);
    let second = "archive <second@example.invalid>";
    let sha1 = |created: u32| {
        primary
            .sign(SignatureType::POSITIVE_CERTIFICATION, created)
            .hash(HashAlgorithm::SHA1)
            .key_flags(CERTIFY | SIGN)
    };
    let certificate = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(TWO_YEARS)),
        &sha1(CREATED + DAY).over_user_id(&primary, USER_ID),
    ]);
    assert_eq!(
        verdict(&certificate, &[&signed(&primary, SIGNED)]),
        Ok(primary.public().fingerprint())
    );

    let primary_user_id = |first: &[u8], other: &[u8]| {
        let certificate = forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            first,
            &forge::user_id(second),
            other,
        ]);
        Authority::new(&certificate, &Policy::new(), NOW)
            .primary_user_id()
            .map(|user_id| user_id.value().to_vec())
    };
    let plain = certification_of(&primary, second, CREATED, Some(CERTIFY | SIGN), None);
    let marked = primary
        .sign(SignatureType::POSITIVE_CERTIFICATION, CREATED)
        .key_flags(CERTIFY | SIGN)
        .primary_user_id()
        .over_user_id(&primary, second);
    let weak = sha1(CREATED + DAY).over_user_id(&primary, USER_ID);
    let weak_marked = sha1(CREATED + DAY)
        .primary_user_id()
        .over_user_id(&primary, USER_ID);
    // Newer, over SHA-1: the other.
    assert_eq!(
        primary_user_id(&weak, &plain),
        Some(second.as_bytes().to_vec())
    );
    // Marked primary, where the other is not: this one.
    assert_eq!(
        primary_user_id(&weak_marked, &plain),
        Some(USER_ID.as_bytes().to_vec())
    );
    // Both marked: the other.
    assert_eq!(
        primary_user_id(&weak_marked, &marked),
        Some(second.as_bytes().to_vec())
    );
}

/// From 1 February 2023, a self-signature over the primary key must rest on
/// a hash the policy accepts. One that does not grants nothing and governs
/// still, so it refuses the certificate rather than let an older one govern
/// in its place: here, an older certification whose expiration has passed.
/// One made the second before grants, as does one a policy accepting the
/// hash judges, and a revocation over such a hash revokes whenever made.
#[test]
fn a_recent_self_signature_over_a_weak_hash_refuses_its_certificate() {
    /// 2023-02-01, stated here apart from the policy's own constant.
    const FEBRUARY_2023: u32 = 1_675_209_600;
    // RSA, since Ed25519 verifies over no hash narrower than 256 bits.
    let primary = Key::rsa(Version::V4, CREATED);
    let document = signed(&primary, SIGNED);
    let second = "archive <second@example.invalid>";
    let sha1 = |signature_type: SignatureType, created: u32| {
        primary
            .sign(signature_type, created)
            .hash(HashAlgorithm::SHA1)
    };
    let newer = |created: u32| {
        sha1(SignatureType::POSITIVE_CERTIFICATION, created)
            .key_flags(CERTIFY | SIGN)
            .over_user_id(&primary, USER_ID)
    };
    let key = primary.primary();
    let user_id = forge::user_id(USER_ID);
    let older = certification(&primary, CREATED, Some(CERTIFY | SIGN), Some(TWO_YEARS));
    let with = |parts: &[&[u8]]| {
        let mut all: Vec<&[u8]> = vec![&key, &user_id, &older];
        all.extend(parts);
        forge::certificate(&all)
    };
    let accepting = Policy::new().with_hash(HashAlgorithm::SHA1, true);

    // The older certification alone has lapsed by the time the document is
    // signed.
    assert_eq!(
        verdict(&with(&[]), &[&document]),
        Err(Reason::AfterKeyExpiration)
    );
    // A newer one made the second before the date lifts its expiration.
    assert!(verdict(&with(&[&newer(FEBRUARY_2023 - 1)]), &[&document]).is_ok());
    // One made at the date refuses the certificate.
    let recent = with(&[&newer(FEBRUARY_2023)]);
    assert_eq!(
        verdict(&recent, &[&document]),
        Err(Reason::WeakSelfSignature)
    );
    assert!(judge(&recent, &[&document], &accepting, NOW).is_ok());
    // So does a direct-key signature, and a certification of another user
    // ID, which bounds the key as every user ID in force does.
    let direct = sha1(SignatureType::DIRECT_KEY, FEBRUARY_2023)
        .key_flags(CERTIFY | SIGN)
        .over_key(&primary);
    let other = sha1(SignatureType::POSITIVE_CERTIFICATION, FEBRUARY_2023)
        .key_flags(CERTIFY | SIGN)
        .primary_user_id()
        .over_user_id(&primary, second);
    let other = [&forge::user_id(second)[..], &other].concat();
    let fresh = certification(&primary, CREATED + DAY, Some(CERTIFY | SIGN), None);
    for weak in [&direct, &other] {
        let certificate = with(&[&fresh, weak]);
        assert_eq!(
            verdict(&certificate, &[&document]),
            Err(Reason::WeakSelfSignature)
        );
        assert!(judge(&certificate, &[&document], &accepting, NOW).is_ok());
    }
    // A user ID it certifies is not the primary user ID, though marked so.
    assert_eq!(
        Authority::new(&with(&[&fresh, &other]), &Policy::new(), NOW)
            .primary_user_id()
            .map(|user_id| user_id.value().to_vec()),
        Some(USER_ID.as_bytes().to_vec())
    );

    // A certification revocation is held to the same date, since a
    // withdrawal can lift a restriction: made at it, the self-signature it
    // is over stays in force, as weak, and made before it, or under a policy
    // that accepts SHA-1, it withdraws the self-signature.
    let withdrawal = |created: u32| {
        sha1(SignatureType::CERTIFICATION_REVOCATION, created).over_user_id(&primary, USER_ID)
    };
    let certificate = with(&[&fresh, &withdrawal(FEBRUARY_2023)]);
    assert_eq!(
        verdict(&certificate, &[&document]),
        Err(Reason::WeakSelfSignature)
    );
    assert_eq!(
        judge(&certificate, &[&document], &accepting, NOW),
        Err(Reason::MissingSelfSignature)
    );
    assert_eq!(
        verdict(
            &with(&[&fresh, &withdrawal(FEBRUARY_2023 - 1)]),
            &[&document]
        ),
        Err(Reason::MissingSelfSignature)
    );
    // A key revocation over SHA-1 made at the date revokes.
    let revocation = sha1(SignatureType::KEY_REVOCATION, FEBRUARY_2023).over_key(&primary);
    assert_eq!(
        verdict(&with(&[&fresh, &revocation]), &[&document]),
        Err(Reason::CertificateRevoked)
    );

    // The date holds for any hash a policy refuses, in either version.
    for version in [Version::V4, Version::V6] {
        let primary = Key::ed25519(1, version, CREATED);
        let refusing = Policy::new().with_hash(HashAlgorithm::SHA256, false);
        let lapse = |created: u32| {
            let direct = primary
                .sign(SignatureType::DIRECT_KEY, created)
                .key_flags(CERTIFY | SIGN)
                .over_key(&primary);
            let certificate = forge::certificate(&[&primary.primary(), &direct]);
            Authority::new(&certificate, &refusing, NOW).lapse()
        };
        assert_eq!(lapse(FEBRUARY_2023 - 1), Ok(None), "{version:?}");
        assert_eq!(
            lapse(FEBRUARY_2023),
            Err(Reason::WeakSelfSignature),
            "{version:?}"
        );
    }
}

/// A signature dated before either key it speaks about cannot have been made
/// when it says. A binding so dated binds nothing, and a self-signature so
/// dated binds nothing either. A subkey made before its primary key had no
/// part in the certificate before the primary key existed, so its authority
/// begins with the primary key's.
/// A statement over SHA3-256 or SHA3-512, which RFC 9580 permits in either
/// version, counts as one over any other hash: a document signature over
/// either is accepted under the default policy, and a revocation over either
/// revokes.
#[test]
fn statements_over_sha3_count() {
    let mut checked = 0;
    for primary in [
        Key::ed25519(1, Version::V4, CREATED),
        Key::ed25519(1, Version::V6, CREATED),
        Key::rsa(Version::V4, CREATED),
    ] {
        let direct = primary
            .sign(SignatureType::DIRECT_KEY, CREATED)
            .key_flags(CERTIFY | SIGN)
            .over_key(&primary);
        let with = |revocation: &[u8]| {
            forge::certificate(&[
                &primary.primary(),
                &direct,
                revocation,
                &forge::user_id(USER_ID),
                &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            ])
        };
        for hash in [HashAlgorithm::SHA3_256, HashAlgorithm::SHA3_512] {
            let document = primary
                .sign(SignatureType::TEXT, SIGNED)
                .hash(hash)
                .over_document(DOCUMENT);
            assert_eq!(
                verdict(&with(&[]), &[&document]),
                Ok(primary.public().fingerprint()),
                "{hash}"
            );
            let revocation = primary
                .sign(SignatureType::KEY_REVOCATION, CREATED + DAY)
                .hash(hash)
                .over_key(&primary);
            assert_eq!(
                verdict(&with(&revocation), &[&document]),
                Err(Reason::CertificateRevoked),
                "{hash}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 6);
}

/// An Ed25519 key's statement over a hash shorter than 256 bits, on which
/// RFC 9580 §5.2.3.3 and §5.2.3.4 forbid an Ed25519 signature to rest, is
/// still the key's, so it restricts what the certificate grants and grants
/// nothing: a revocation revokes, and a self-signature, binding, or
/// withdrawal that would govern refuses its certificate or subkey rather
/// than let an older statement govern in its place. Each is checked beside
/// the same statement over SHA2-256, in both versions.
#[test]
fn a_restriction_over_a_hash_too_short_for_ed25519_still_restricts() {
    for version in [Version::V4, Version::V6] {
        let primary = Key::ed25519(1, version, CREATED);
        let subkey = Key::ed25519(2, version, CREATED);
        let later = CREATED + DAY;
        // A version 6 certificate is bound by a direct-key signature.
        let direct = match version {
            Version::V4 => Vec::new(),
            _ => primary
                .sign(SignatureType::DIRECT_KEY, CREATED)
                .key_flags(CERTIFY | SIGN)
                .over_key(&primary),
        };
        let documents = [signed(&primary, SIGNED), signed(&subkey, SIGNED)];
        // Each key's verdict on a document it signed, with statements added
        // over the primary key, the user ID, and the subkey.
        let verdicts = |over_key: &[u8], over_user_id: &[u8], over_subkey: &[u8]| {
            let certificate = forge::certificate(&[
                &primary.primary(),
                &direct,
                over_key,
                &forge::user_id(USER_ID),
                &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
                over_user_id,
                &subkey.subkey(),
                &binding(&primary, &subkey, CREATED, SIGN),
                over_subkey,
            ]);
            documents
                .each_ref()
                .map(|document| verdict(&certificate, &[document]))
        };
        let by_primary = Ok(primary.public().fingerprint());
        let by_subkey = Ok(subkey.public().fingerprint());
        assert_eq!(verdicts(&[], &[], &[]), [by_primary, by_subkey]);
        let both = |reason| [Err(reason), Err(reason)];

        let hashes = match version {
            Version::V4 => &[
                HashAlgorithm::SHA256,
                HashAlgorithm::SHA224,
                HashAlgorithm::SHA1,
            ][..],
            // A version 6 signature cannot rest on SHA-1, which RFC 9580
            // gives no salt size.
            _ => &[HashAlgorithm::SHA256, HashAlgorithm::SHA224],
        };
        for &hash in hashes {
            let short = hash != HashAlgorithm::SHA256;
            let sign = |signature_type| primary.sign(signature_type, later).hash(hash);
            let case = format!("{version:?} {hash}");

            let revocation = sign(SignatureType::KEY_REVOCATION).over_key(&primary);
            assert_eq!(
                verdicts(&revocation, &[], &[]),
                both(Reason::CertificateRevoked),
                "{case}"
            );
            let revocation = sign(SignatureType::SUBKEY_REVOCATION).over_subkey(&primary, &subkey);
            assert_eq!(
                verdicts(&[], &[], &revocation),
                [by_primary, Err(Reason::SubkeyRevoked)],
                "{case}"
            );

            // A newer self-signature that shortens the key's life, over the
            // key or the user ID: an older one, without the expiration, must
            // not govern in its place. A short hash is refused whatever the
            // signature's date, which here is before 1 February 2023.
            let expiring = both(if short {
                Reason::WeakSelfSignature
            } else {
                Reason::AfterKeyExpiration
            });
            let shorter = sign(SignatureType::DIRECT_KEY)
                .key_flags(CERTIFY | SIGN)
                .key_expiration(TWO_YEARS)
                .over_key(&primary);
            assert_eq!(verdicts(&shorter, &[], &[]), expiring, "{case}");
            let shorter = sign(SignatureType::POSITIVE_CERTIFICATION)
                .key_flags(CERTIFY | SIGN)
                .key_expiration(TWO_YEARS)
                .over_user_id(&primary, USER_ID);
            assert_eq!(verdicts(&[], &shorter, &[]), expiring, "{case}");

            // A withdrawal of the self-signature that binds the key: over a
            // short hash it withdraws nothing, and the self-signature stays
            // in force but refuses the certificate.
            let (withdrawal, withdrawn) = match version {
                Version::V4 => (
                    sign(SignatureType::CERTIFICATION_REVOCATION).over_user_id(&primary, USER_ID),
                    Reason::MissingSelfSignature,
                ),
                _ => (
                    sign(SignatureType::CERTIFICATION_REVOCATION).over_key(&primary),
                    Reason::MissingDirectKeySignature,
                ),
            };
            let withdrawn = both(if short {
                Reason::WeakSelfSignature
            } else {
                withdrawn
            });
            let placed = match version {
                Version::V4 => verdicts(&[], &withdrawal, &[]),
                _ => verdicts(&withdrawal, &[], &[]),
            };
            assert_eq!(placed, withdrawn, "{case}");

            // A newer binding that withdraws the signing flag refuses the
            // subkey for its flags, whatever its hash; one that grants
            // signing refuses it for its hash.
            let encrypting = sign(SignatureType::SUBKEY_BINDING)
                .key_flags(ENCRYPT)
                .over_subkey(&primary, &subkey);
            assert_eq!(
                verdicts(&[], &[], &encrypting),
                [by_primary, Err(Reason::SubkeyMayNotSign)],
                "{case}"
            );
            let rebound = sign(SignatureType::SUBKEY_BINDING)
                .key_flags(SIGN)
                .embed(&back_signature(&primary, &subkey, later))
                .over_subkey(&primary, &subkey);
            let rebound_verdict = if short {
                Err(Reason::WeakBinding)
            } else {
                by_subkey
            };
            assert_eq!(
                verdicts(&[], &[], &rebound),
                [by_primary, rebound_verdict],
                "{case}"
            );

            // A document signature over a short hash is the key's, and is
            // refused for its hash, even by a policy that accepts SHA-1.
            let certificate = forge::certificate(&[
                &primary.primary(),
                &direct,
                &forge::user_id(USER_ID),
                &certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            ]);
            let document = primary
                .sign(SignatureType::TEXT, SIGNED)
                .hash(hash)
                .over_document(DOCUMENT);
            let expected = if short {
                Err(Reason::WeakHash)
            } else {
                by_primary
            };
            for policy in [
                Policy::new(),
                Policy::new().with_hash(HashAlgorithm::SHA1, true),
            ] {
                assert_eq!(
                    judge(&certificate, &[&document], &policy, NOW),
                    expected,
                    "{case}"
                );
            }
        }
    }
}

#[test]
fn nothing_dated_before_the_keys_counts() {
    let primary = ed25519(1);
    let certified = certification(&primary, CREATED, Some(CERTIFY | SIGN), None);
    let with = |subkey: &Key, binding: &[u8]| {
        forge::certificate(&[
            &primary.primary(),
            &forge::user_id(USER_ID),
            &certified,
            &subkey.subkey(),
            binding,
        ])
    };

    let made = CREATED + 10 * DAY;
    let late = Key::ed25519(2, Version::V4, made);
    let binding_at = |created: u32| {
        primary
            .sign(SignatureType::SUBKEY_BINDING, created)
            .key_flags(SIGN)
            .embed(&back_signature(&primary, &late, made))
            .over_subkey(&primary, &late)
    };
    assert_eq!(
        standings(&with(&late, &binding_at(CREATED)), NOW)[1],
        Err(Reason::UnboundSubkey)
    );
    assert_eq!(
        standings(&with(&late, &binding_at(made)), NOW)[1],
        Ok(window(made, None))
    );

    let early = Key::ed25519(2, Version::V4, CREATED - 10 * DAY);
    let certificate = with(&early, &binding(&primary, &early, CREATED, SIGN));
    assert_eq!(standings(&certificate, NOW)[1], Ok(window(CREATED, None)));
    assert_eq!(
        verdict(&certificate, &[&signed(&early, CREATED - DAY)]),
        Err(Reason::BeforeKeyCreation)
    );
    assert_eq!(
        verdict(&certificate, &[&signed(&early, CREATED)]),
        Ok(early.public().fingerprint())
    );

    let predated = forge::certificate(&[
        &primary.primary(),
        &forge::user_id(USER_ID),
        &certification(&primary, CREATED - 1, Some(CERTIFY | SIGN), None),
    ]);
    assert_eq!(
        standings(&predated, NOW)[0],
        Err(Reason::MissingSelfSignature)
    );
}

/// Certificates of `primary` and `subkey` that each restrict what they
/// grant, by every kind of statement a certificate makes about itself, as
/// their packets: a revoked subkey, a subkey whose newer binding withholds
/// signing, a revoked certificate, a withdrawn direct-key signature, a newer
/// certification that shortens the key's life, an expiring back-signature,
/// in the binding's unhashed area and in its hashed area, a newer direct-key
/// signature that withholds signing, and a withdrawn user ID that alone
/// bound the key.
fn restricted(primary: &Key, subkey: &Key) -> Vec<Vec<Vec<u8>>> {
    let (primary, subkey) = (primary.clone(), subkey.clone());
    let later = CREATED + DAY;
    let direct = |created: u32, flags: u8| {
        primary
            .sign(SignatureType::DIRECT_KEY, created)
            .key_flags(flags)
            .over_key(&primary)
    };
    let base = |extra: &[Vec<u8>]| {
        let mut packets = vec![
            primary.primary(),
            direct(CREATED, CERTIFY | SIGN),
            forge::user_id(USER_ID),
            certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            subkey.subkey(),
            binding(&primary, &subkey, CREATED, SIGN),
        ];
        packets.extend_from_slice(extra);
        packets
    };
    let expiring = subkey
        .sign(SignatureType::PRIMARY_KEY_BINDING, later)
        .expiration(TWO_YEARS)
        .over_subkey(&primary, &subkey);
    let expiring_back =
        |signing: forge::Signing<'_>| signing.key_flags(SIGN).over_subkey(&primary, &subkey);
    let newer_binding = || primary.sign(SignatureType::SUBKEY_BINDING, later);
    vec![
        base(&[primary
            .sign(SignatureType::SUBKEY_REVOCATION, later)
            .over_subkey(&primary, &subkey)]),
        base(&[primary
            .sign(SignatureType::SUBKEY_BINDING, later)
            .key_flags(ENCRYPT)
            .over_subkey(&primary, &subkey)]),
        base(&[primary
            .sign(SignatureType::KEY_REVOCATION, later)
            .over_key(&primary)]),
        base(&[primary
            .sign(SignatureType::CERTIFICATION_REVOCATION, later)
            .over_key(&primary)]),
        {
            let mut packets = base(&[]);
            packets.insert(
                4,
                certification(&primary, later, Some(CERTIFY | SIGN), Some(TWO_YEARS)),
            );
            packets
        },
        base(&[expiring_back(newer_binding().embed(&expiring))]),
        base(&[expiring_back(newer_binding().embed_hashed(&expiring))]),
        base(&[direct(later, CERTIFY)]),
        vec![
            primary.primary(),
            forge::user_id(USER_ID),
            certification(&primary, CREATED, Some(CERTIFY | SIGN), None),
            primary
                .sign(SignatureType::CERTIFICATION_REVOCATION, later)
                .over_user_id(&primary, USER_ID),
            subkey.subkey(),
            binding(&primary, &subkey, CREATED, SIGN),
        ],
    ]
}

/// The standing of each key `certificate` grants anything to, by its
/// fingerprint.
fn by_fingerprint(certificate: &Certificate) -> Vec<(Fingerprint, Result<Window, Reason>)> {
    Authority::new(certificate, &Policy::new(), NOW)
        .signers()
        .map(|(key, standing)| (key.fingerprint(), standing))
        .collect()
}

/// Whether `after` grants no more than `before`: nothing where `before`
/// grants nothing, and otherwise no earlier and no longer.
fn within(after: Result<Window, Reason>, before: Result<Window, Reason>) -> bool {
    match (before, after) {
        (_, Err(_)) => true,
        (Err(_), Ok(_)) => false,
        (Ok(before), Ok(after)) => {
            after.created >= before.created
                && match (before.expires, after.expires) {
                    (None, _) => true,
                    (Some(_), None) => false,
                    (Some(before), Some(after)) => after <= before,
                }
        }
    }
}

/// The certificates made from `packets` by rewriting what none of their
/// signatures covers: repeating a user ID or subkey with only one of the
/// signatures over it, replacing a signature's unhashed area or changing it
/// in each of the ways [`altered`] does, putting a User ID, User Attribute,
/// or Subkey packet before a signature, and moving a signature to follow the
/// primary key or to the end. The packets are of a certificate of
/// `version`.
fn rewritten(packets: &[Vec<u8>], version: Version) -> Vec<Vec<Vec<u8>>> {
    let tag = |packet: &[u8]| packet::packets(packet).next().unwrap().unwrap().tag();
    let mut rewrites = Vec::new();
    for (at, part) in packets.iter().enumerate() {
        match tag(part) {
            Tag::USER_ID | Tag::PUBLIC_SUBKEY => {
                for signature in packets[at + 1..]
                    .iter()
                    .take_while(|packet| tag(packet) == Tag::SIGNATURE)
                {
                    let mut rewrite = packets.to_vec();
                    rewrite.extend([part.clone(), signature.clone()]);
                    rewrites.push(rewrite);
                }
            }
            Tag::SIGNATURE => {
                // Its unhashed area emptied or naming another issuer, and
                // every other change no signature covers.
                let mut amended = vec![
                    forge::with_unhashed(part, |_| Vec::new()),
                    forge::with_unhashed(part, |_| [&[9, 16][..], &[0x99; 8]].concat()),
                ];
                amended.extend(altered(part).into_iter().map(|altered| altered.packet));
                for signature in amended {
                    let mut rewrite = packets.to_vec();
                    rewrite[at] = signature;
                    rewrites.push(rewrite);
                }
                for inserted in [
                    forge::user_id("inserted <inserted@example.invalid>"),
                    forge::packet(Tag::USER_ATTRIBUTE, &[0x05, 0x01, 0x00]),
                    Key::ed25519(9, version, CREATED).subkey(),
                ] {
                    let mut rewrite = packets.to_vec();
                    rewrite.insert(at, inserted);
                    rewrites.push(rewrite);
                }
                for to in [1, packets.len() - 1] {
                    let mut rewrite = packets.to_vec();
                    let moved = rewrite.remove(at);
                    rewrite.insert(to, moved);
                    rewrites.push(rewrite);
                }
            }
            _ => {}
        }
    }
    rewrites
}

/// Rewriting what none of a certificate's signatures covers, which anyone
/// who handles the certificate can do, widens nothing it grants: repeating a
/// part with only an older signature over it, changing a signature's
/// unhashed area, hash prefix, length, or how the integers of its material
/// are written, inserting a packet before a statement or moving it, or
/// combining the certificate with an older copy of itself, in either order.
/// Each certificate here restricts what it grants by another kind of
/// statement, under an Ed25519 and an RSA primary key of each version, and
/// every rewrite is tried at every place.
#[test]
fn what_no_signature_covers_widens_nothing() {
    let mut tried = 0;
    for (primary, subkey) in primaries() {
        let version = primary.public().version();
        for packets in restricted(&primary, &subkey) {
            let parts: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
            let certificate = forge::certificate(&parts);
            let before = by_fingerprint(&certificate);
            let mut variants: Vec<Certificate> = rewritten(&packets, version)
                .iter()
                .map(|rewrite| {
                    let parts: Vec<&[u8]> = rewrite.iter().map(Vec::as_slice).collect();
                    forge::certificate(&parts)
                })
                .collect();
            for length in 1..packets.len() {
                let older = forge::certificate(&parts[..length]);
                for keyring in [
                    Keyring::new([certificate.clone(), older.clone()]),
                    Keyring::new([older, certificate.clone()]),
                ] {
                    let [combined] = keyring.certificates() else {
                        panic!("one certificate");
                    };
                    variants.push(combined.clone());
                }
            }
            for variant in &variants {
                for (fingerprint, after) in by_fingerprint(variant) {
                    let before = before
                        .iter()
                        .find(|(held, _)| *held == fingerprint)
                        .map_or(Err(Reason::UnboundSubkey), |&(_, before)| before);
                    assert!(
                        within(after, before),
                        "{version:?} {fingerprint}: {before:?} became {after:?}\n{variant:?}"
                    );
                }
                tried += 1;
            }
        }
    }
    assert_eq!(tried, 2625);
}

#[test]
fn reasons_are_described() {
    assert_eq!(
        Reason::WeakHash.to_string(),
        "the signature rests on a hash the policy does not accept"
    );
    assert_eq!(
        Reason::TextSignature.to_string(),
        "the signature is a text signature, and the policy accepts only binary ones"
    );
    assert_eq!(Policy::default(), Policy::new());
    let window = window(CREATED, Some(u64::from(CREATED) + 10));
    assert!(!window.contains(u64::from(CREATED) - 1));
    assert!(window.contains(u64::from(CREATED)));
    assert!(window.contains(u64::from(CREATED) + 9));
    assert!(!window.contains(u64::from(CREATED) + 10));
}
