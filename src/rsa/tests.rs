//! Wycheproof's RSASSA-PKCS1-v1_5 vectors, signatures GnuPG made, and the
//! bounds on keys.

use alloc::format;
use alloc::vec::Vec;

use super::RsaError;
use crate::hash::{Digest, HashAlgorithm, HashFunction, Sha256};
use crate::key::{KeyMaterial, PublicKey};
use crate::packet::{self, Packet, Tag};
use crate::signature::{Signature, SignatureMaterial, SignatureType};
use crate::test_support::{
    Json, digest, hashed_key, hashed_user_id, hex, signature_digest, vector, vector_bytes,
};

/// Verifies `signature` over `digest` with the key `modulus` and `exponent`
/// make, as a caller of the public API does: the key's refusal, if it has
/// one, or the signature's verdict.
fn verify(
    modulus: &[u8],
    exponent: &[u8],
    digest: &Digest,
    signature: &[u8],
) -> Result<(), RsaError> {
    super::PublicKey::new(modulus, exponent)?.verify(digest, signature)
}

/// The hash algorithm Wycheproof names `name`.
fn wycheproof_hash(name: &str) -> HashAlgorithm {
    match name {
        "SHA-1" => HashAlgorithm::SHA1,
        "SHA-224" => HashAlgorithm::SHA224,
        "SHA-256" => HashAlgorithm::SHA256,
        "SHA-384" => HashAlgorithm::SHA384,
        "SHA-512" => HashAlgorithm::SHA512,
        "SHA3-256" => HashAlgorithm::SHA3_256,
        "SHA3-512" => HashAlgorithm::SHA3_512,
        _ => panic!("a hash function the vectors were not chosen for: {name}"),
    }
}

/// Runs every test of a Wycheproof file, returning how many it held. `expect`
/// gives the verdict for a test from its group, its result, and its flags.
fn wycheproof(
    file: &str,
    key: &str,
    expect: impl Fn(&Json, &str, &[&str]) -> Result<(), RsaError>,
) -> usize {
    let text = vector(&format!("wycheproof/{file}"));
    let json = Json::parse(&text);
    assert_eq!(json.member("algorithm").as_str(), "RSASSA-PKCS1-v1_5");
    let mut checked = 0;
    for group in json.member("testGroups").as_array() {
        let key = group.member(key);
        let modulus = hex(key.member("modulus").as_str());
        let exponent = hex(key.member("publicExponent").as_str());
        let hash = wycheproof_hash(group.member("sha").as_str());
        // One key for the group, made once and used for each of its tests.
        let group_key = super::PublicKey::new(&modulus, &exponent);
        for test in group.member("tests").as_array() {
            let id = test.member("tcId").as_usize();
            let digest = digest(hash, &hex(test.member("msg").as_str()));
            let signature = hex(test.member("sig").as_str());
            let result = test.member("result").as_str();
            let flags: Vec<&str> = test
                .member("flags")
                .as_array()
                .iter()
                .map(Json::as_str)
                .collect();
            let verdict = group_key
                .as_ref()
                .map_err(|error| *error)
                .and_then(|key| key.verify(&digest, &signature));
            assert_eq!(
                verdict,
                expect(group, result, &flags),
                "{file}, test {id}: {result} {flags:?}, {}",
                test.member("comment").as_str()
            );
            assert_eq!(verify(&modulus, &exponent, &digest, &signature), verdict);
            checked += 1;
        }
    }
    assert_eq!(checked, json.member("numberOfTests").as_usize(), "{file}");
    checked
}

#[test]
fn wycheproof_verification() {
    let mut checked = 0;
    for bits in [2048, 3072, 4096, 8192] {
        for hash in [
            "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512",
        ] {
            let published = match hash {
                "sha224" => bits == 2048,
                "sha3_256" | "sha3_512" => bits <= 3072,
                _ => true,
            };
            if !published {
                continue;
            }
            let file = format!("rsa_signature_{bits}_{hash}_test.json");
            checked += wycheproof(&file, "publicKey", |_, result, flags| match result {
                "valid" => Ok(()),
                // A DigestInfo without the NULL parameters field, which Table
                // 24 of RFC 9580 includes. RFC 8017 §9.2 lets a verifier
                // accept the shorter form; one that compares against the
                // encoding it builds does not.
                "acceptable" if flags == ["MissingNull"] => Err(RsaError::BadSignature),
                "invalid" => Err(RsaError::BadSignature),
                _ => panic!("{file}: an unexpected result: {result} {flags:?}"),
            });
        }
    }
    assert_eq!(checked, 4396);
}

/// Wycheproof's signature generation vectors: valid signatures, some of them
/// over SHA-1 or with the exponent 3, which verification accepts, and some
/// with moduli narrower than 2048 bits, which it refuses.
#[test]
fn wycheproof_generation() {
    let mut checked = 0;
    for bits in [1024, 1536, 2048, 3072, 4096] {
        let file = format!("rsa_pkcs1_{bits}_sig_gen_test.json");
        checked += wycheproof(&file, "privateKey", |group, result, flags| {
            assert!(
                matches!(result, "valid" | "acceptable")
                    && flags
                        .iter()
                        .all(|flag| ["SmallModulus", "WeakHash", "SmallPublicKey"].contains(flag)),
                "{file}: an unexpected result: {result} {flags:?}"
            );
            if group.member("keySize").as_usize() < 2048 {
                Err(RsaError::ModulusTooShort)
            } else {
                Ok(())
            }
        });
    }
    assert_eq!(checked, 158);
}

#[test]
fn gnupg_self_signatures() {
    let data = vector_bytes("gnupg/rsa.pgp");
    let packets: Vec<Packet<'_>> = packet::packets(&data).map(Result::unwrap).collect();
    let tags: Vec<Tag> = packets.iter().map(Packet::tag).collect();
    assert_eq!(
        tags,
        [
            Tag::PUBLIC_KEY,
            Tag::USER_ID,
            Tag::SIGNATURE,
            Tag::PUBLIC_SUBKEY,
            Tag::SIGNATURE
        ]
    );
    let [primary, user_id, certification, subkey, binding] =
        <[Packet<'_>; 5]>::try_from(packets).unwrap();
    let rsa_material =
        |packet: &Packet<'_>| match PublicKey::from_packet(packet).unwrap().material() {
            KeyMaterial::Rsa { modulus, exponent } => (modulus.clone(), exponent.clone()),
            other => panic!("not an RSA key: {other:?}"),
        };
    let (modulus, exponent) = rsa_material(&primary);
    let (subkey_modulus, subkey_exponent) = rsa_material(&subkey);

    // The positive certification of the user ID, over the primary key and the
    // user ID.
    let certification = Signature::from_packet(&certification).unwrap();
    assert_eq!(
        certification.signature_type(),
        SignatureType::POSITIVE_CERTIFICATION
    );
    let data = [hashed_key(primary.body()), hashed_user_id(user_id.body())].concat();
    let certification_digest = signature_digest(&certification, &data);
    let SignatureMaterial::Rsa(value) = certification.material() else {
        panic!("not an RSA signature");
    };
    assert_eq!(
        verify(&modulus, &exponent, &certification_digest, value),
        Ok(())
    );
    // Not by the subkey, and not over another digest.
    assert_eq!(
        verify(
            &subkey_modulus,
            &subkey_exponent,
            &certification_digest,
            value
        ),
        Err(RsaError::BadSignature)
    );
    let mut altered = certification_digest;
    if let Digest::Sha512(bytes) = &mut altered {
        bytes[63] ^= 1;
    }
    assert_eq!(
        verify(&modulus, &exponent, &altered, value),
        Err(RsaError::BadSignature)
    );

    // The subkey's binding, over the primary key and the subkey. Its value is
    // 2044 bits, narrower than the modulus.
    let binding = Signature::from_packet(&binding).unwrap();
    assert_eq!(binding.signature_type(), SignatureType::SUBKEY_BINDING);
    let data = [hashed_key(primary.body()), hashed_key(subkey.body())].concat();
    let binding_digest = signature_digest(&binding, &data);
    let SignatureMaterial::Rsa(value) = binding.material() else {
        panic!("not an RSA signature");
    };
    assert_eq!(crate::bignum::bit_length(value), 2044);
    assert_eq!(verify(&modulus, &exponent, &binding_digest, value), Ok(()));
    // Leading zeros carry no meaning in any of the three integers.
    let padded = |value: &[u8]| [&[0, 0][..], value].concat();
    assert_eq!(
        verify(
            &padded(&modulus),
            &padded(&exponent),
            &binding_digest,
            &padded(value)
        ),
        Ok(())
    );
}

/// A modulus of `bits` bits, odd, its value otherwise arbitrary.
fn modulus_of(bits: usize) -> Vec<u8> {
    let mut modulus = alloc::vec![0x5A; bits.div_ceil(8)];
    modulus[0] = 0xFF >> ((8 - bits % 8) % 8);
    *modulus.last_mut().unwrap() |= 1;
    assert_eq!(crate::bignum::bit_length(&modulus), bits);
    modulus
}

#[test]
fn key_bounds() {
    let digest = Digest::Sha256(Sha256::digest(b"irongall"));
    let e = [0x01, 0x00, 0x01];
    // A signature value no modulus here makes valid, below every one of them.
    let signature = [0x02];
    for (bits, expected) in [
        (0, RsaError::ModulusTooShort),
        (1024, RsaError::ModulusTooShort),
        (2047, RsaError::ModulusTooShort),
        (2048, RsaError::BadSignature),
        (8192, RsaError::BadSignature),
        (8193, RsaError::ModulusTooLong),
        (65535, RsaError::ModulusTooLong),
    ] {
        let modulus = if bits == 0 {
            Vec::new()
        } else {
            modulus_of(bits)
        };
        assert_eq!(
            verify(&modulus, &e, &digest, &signature),
            Err(expected),
            "{bits} bits"
        );
    }

    let modulus = modulus_of(2048);
    for (exponent, expected) in [
        (&[][..], RsaError::InvalidKey),
        (&[0], RsaError::InvalidKey),
        (&[1], RsaError::InvalidKey),
        (&[2], RsaError::InvalidKey),
        (&[0x01, 0x00, 0x00], RsaError::InvalidKey),
        (&[3], RsaError::BadSignature),
        (&[0x01, 0xFF, 0xFF, 0xFF, 0xFF], RsaError::BadSignature),
        (&[0x02, 0x00, 0x00, 0x00, 0x01], RsaError::ExponentTooLarge),
        (
            &[0x01, 0, 0, 0, 0, 0, 0, 0, 0x01],
            RsaError::ExponentTooLarge,
        ),
        // An even exponent past the bound is too large, whether or not it
        // fits in 64 bits.
        (&[0x02, 0x00, 0x00, 0x00, 0x00], RsaError::ExponentTooLarge),
        (&[0x01, 0, 0, 0, 0, 0], RsaError::ExponentTooLarge),
        (
            &[0x01, 0, 0, 0, 0, 0, 0, 0, 0x00],
            RsaError::ExponentTooLarge,
        ),
    ] {
        assert_eq!(
            verify(&modulus, exponent, &digest, &signature),
            Err(expected),
            "exponent {exponent:02x?}"
        );
    }

    // A key names its width and exponent, and not its modulus.
    let key = super::PublicKey::new(&modulus, &e).unwrap();
    assert_eq!(
        format!("{key:?}"),
        "PublicKey { bits: 2048, exponent: 65537, .. }"
    );

    let mut even = modulus.clone();
    *even.last_mut().unwrap() &= !1;
    assert_eq!(
        verify(&even, &e, &digest, &signature),
        Err(RsaError::InvalidKey)
    );

    // A signature value equal to the modulus, above it, or wider than it.
    let mut above = modulus.clone();
    *above.last_mut().unwrap() += 2;
    let wider = [&[1][..], &modulus].concat();
    for signature in [&modulus, &above, &wider] {
        assert_eq!(
            verify(&modulus, &e, &digest, signature),
            Err(RsaError::BadSignature)
        );
    }
}

#[test]
fn encodings_follow_table_24() {
    // The DigestInfo prefixes, as Table 24 of RFC 9580 prints them.
    for (digest, prefix) in [
        (Digest::Sha1([0; 20]), "3021300906052b0e03021a05000414"),
        (
            Digest::Sha224([0; 28]),
            "302d300d06096086480165030402040500041c",
        ),
        (
            Digest::Sha256([0; 32]),
            "3031300d060960864801650304020105000420",
        ),
        (
            Digest::Sha384([0; 48]),
            "3041300d060960864801650304020205000430",
        ),
        (
            Digest::Sha512([0; 64]),
            "3051300d060960864801650304020305000440",
        ),
    ] {
        let prefix = hex(prefix);
        let encoding = super::encoding(&digest, 256);
        assert_eq!(encoding.len(), 256);
        let fill = 256 - 3 - prefix.len() - digest.as_bytes().len();
        assert_eq!(encoding[..2], [0x00, 0x01]);
        assert!(encoding[2..2 + fill].iter().all(|&octet| octet == 0xFF));
        assert_eq!(encoding[2 + fill], 0x00);
        assert_eq!(encoding[3 + fill..3 + fill + prefix.len()], prefix);
        assert_eq!(&encoding[3 + fill + prefix.len()..], digest.as_bytes());
    }
}
