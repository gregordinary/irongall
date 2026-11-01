//! RFC 8032's vectors, Wycheproof's, and ed25519-speccheck's; a comparison
//! with ed25519-dalek over generated signatures; and OpenPGP signatures, RFC
//! 9580's samples and those GnuPG made.

use alloc::format;
use alloc::vec::Vec;

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use num_bigint::BigUint;

use super::{Ed25519Error, verify, verify_message};
use crate::armor;
use crate::hash::{Digest, HashAlgorithm};
use crate::key::{KeyMaterial, PublicKey};
use crate::packet::{self, Packet, Tag};
use crate::signature::{Signature, SignatureMaterial, SignatureType};
use crate::test_support::rfc9580::{A1_KEY, A2_SIGNATURE, A3_CERTIFICATE, A6_SIGNATURE, A6_TEXT};
use crate::test_support::{
    Json, Rng, digest, hashed_key, hashed_user_id, hex, signature_digest, signature_input, vector,
    vector_bytes,
};

/// The test vectors of RFC 8032 §7.1: the public key, the message, and the
/// signature.
const RFC_8032: [(&str, &str, &str); 5] = [
    // TEST 1.
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "\
        e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
        5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    // TEST 2.
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "\
        92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
        085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    // TEST 3.
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "\
        6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
        18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    // TEST 1024.
    (
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "\
        08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98\
        fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8\
        79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d\
        658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc\
        1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe\
        ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e\
        06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef\
        efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7\
        aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1\
        85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2\
        d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24\
        554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270\
        88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc\
        2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07\
        07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba\
        b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a\
        ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e\
        c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7\
        51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c\
        42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8\
        ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df\
        f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08\
        d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649\
        de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4\
        88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3\
        2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e\
        6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f\
        b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5\
        0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1\
        369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d\
        b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c\
        0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        "\
        0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350\
        aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    ),
    // TEST SHA(abc).
    (
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "\
        ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
        2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "\
        dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
        09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
];

#[test]
fn rfc_8032() {
    let mut checked = 0;
    for (key, message, signature) in RFC_8032 {
        let key = hex(key).try_into().unwrap();
        let mut message = hex(message);
        let signature = hex(signature).try_into().unwrap();
        assert_eq!(verify_message(&key, &message, &signature), Ok(()));
        message.push(0);
        assert_eq!(
            verify_message(&key, &message, &signature),
            Err(Ed25519Error::BadSignature)
        );
        checked += 1;
    }
    assert_eq!(checked, 5);
}

/// Whether ed25519-dalek's `verify_strict` accepts a signature.
fn dalek_strict(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    })
}

/// Whether ed25519-dalek's `verify`, the check rPGP makes, accepts a
/// signature.
fn dalek_lenient(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify(message, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    })
}

/// Wycheproof's verification tests. Of the signatures it calls acceptable,
/// irongall refuses those by a key of small order and verifies those by a
/// key of mixed order; ed25519-dalek's `verify_strict` agrees on every test.
#[test]
fn wycheproof() {
    let json = Json::parse(&vector("wycheproof/ed25519_test.json"));
    assert_eq!(json.member("algorithm").as_str(), "EDDSA");
    let mut checked = 0;
    let mut other_lengths = 0;
    for group in json.member("testGroups").as_array() {
        let key = group.member("publicKey").member("pk").as_str();
        let key: [u8; 32] = hex(key).try_into().unwrap();
        for test in group.member("tests").as_array() {
            checked += 1;
            let id = test.member("tcId").as_usize();
            let message = hex(test.member("msg").as_str());
            let result = test.member("result").as_str();
            let flags: Vec<&str> = test
                .member("flags")
                .as_array()
                .iter()
                .map(Json::as_str)
                .collect();
            // A signature of another length never reaches the verifier: the
            // signature packet reads exactly 64 octets.
            let Ok(signature) = <[u8; 64]>::try_from(hex(test.member("sig").as_str())) else {
                assert_eq!(result, "invalid", "test {id}");
                other_lengths += 1;
                continue;
            };
            let expected = match (result, flags.as_slice()) {
                ("valid", _) | ("acceptable", ["MixedOrderPublicKey"]) => Ok(()),
                ("acceptable", ["SmallOrderPublicKey"]) => Err(Ed25519Error::InvalidKey),
                ("invalid", _) => Err(Ed25519Error::BadSignature),
                _ => panic!("test {id}: an unexpected result: {result} {flags:?}"),
            };
            assert_eq!(
                verify_message(&key, &message, &signature),
                expected,
                "test {id}: {result} {flags:?}, {}",
                test.member("comment").as_str()
            );
            assert_eq!(
                dalek_strict(&key, &message, &signature),
                expected.is_ok(),
                "test {id}"
            );
        }
    }
    assert_eq!(checked, json.member("numberOfTests").as_usize());
    assert_eq!(checked, 210);
    assert_eq!(other_lengths, 12);
}

/// ed25519-speccheck's twelve cases, each on one rule verifiers differ on.
#[test]
fn speccheck() {
    use Ed25519Error::{BadSignature, InvalidKey};
    // irongall's verdicts, and ed25519-dalek's under `verify_strict` and
    // `verify`, as the vectors' repository tabulates them.
    let expected = [
        // 0: S = 0, a key and an R of small order.
        (Err(InvalidKey), false, true),
        // 1: a key of small order.
        (Err(InvalidKey), false, true),
        // 2: an R of small order.
        (Err(BadSignature), false, true),
        // 3: a key and an R of mixed order, satisfying both equations.
        (Ok(()), true, true),
        // 4: satisfying the cofactored equation only.
        (Err(BadSignature), false, false),
        // 5: satisfying the cofactored equation only, with 8k unreduced.
        (Err(BadSignature), false, false),
        // 6 and 7: S of L or more.
        (Err(BadSignature), false, false),
        (Err(BadSignature), false, false),
        // 8 and 9: a non-canonical encoding of an R of small order.
        (Err(BadSignature), false, false),
        (Err(BadSignature), false, false),
        // 10 and 11: a non-canonical encoding of a key of small order, the
        // hash over its canonical encoding, then over the encoding given.
        (Err(InvalidKey), false, false),
        (Err(InvalidKey), false, true),
    ];
    let json = Json::parse(&vector("speccheck/cases.json"));
    let cases = json.as_array();
    assert_eq!(cases.len(), expected.len());
    for (number, (case, (verdict, strict, lenient))) in cases.iter().zip(expected).enumerate() {
        let key = hex(case.member("pub_key").as_str()).try_into().unwrap();
        let message = hex(case.member("message").as_str());
        let signature = hex(case.member("signature").as_str()).try_into().unwrap();
        assert_eq!(
            verify_message(&key, &message, &signature),
            verdict,
            "case {number}"
        );
        assert_eq!(
            dalek_strict(&key, &message, &signature),
            strict,
            "case {number}"
        );
        assert_eq!(
            dalek_lenient(&key, &message, &signature),
            lenient,
            "case {number}"
        );
    }
}

/// A signing key generated from `seed`, and its public key.
fn key_pair(seed: [u8; 32]) -> (SigningKey, [u8; 32]) {
    let signing = SigningKey::from_bytes(&seed);
    let key = signing.verifying_key().to_bytes();
    (signing, key)
}

/// A digest of any length is the message signed: the floor RFC 9580 sets
/// on an OpenPGP signature's hash is applied above this module, which the
/// policy relies on to attribute a signature over a shorter one.
#[test]
fn digests_of_any_length_verify() {
    let (signing, key) = key_pair([7; 32]);
    let mut checked = 0;
    for algorithm in [
        HashAlgorithm::SHA1,
        HashAlgorithm::SHA224,
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512,
    ] {
        let signed = digest(algorithm, b"irongall");
        let signature = signing.sign(signed.as_bytes()).to_bytes();
        assert_eq!(verify(&key, &signed, &signature), Ok(()), "{algorithm}");
        assert_eq!(
            verify(&key, &digest(algorithm, b"iron gall"), &signature),
            Err(Ed25519Error::BadSignature),
            "{algorithm}"
        );
        checked += 1;
    }
    assert_eq!(checked, 5);
}

/// Whether a key's y-coordinate is below p: whether its encoding can be
/// canonical, decided without irongall's field arithmetic.
fn y_below_p(key: &[u8; 32]) -> bool {
    let mut y = *key;
    y[31] &= 0x7F;
    BigUint::from_bytes_le(&y) < (BigUint::from(1u8) << 255u32) - 19u8
}

/// Compares irongall's verdict on a signature with ed25519-dalek's, and
/// returns it. irongall accepts what `verify_strict` accepts, except a key
/// encoded with a y-coordinate of p or more; it refuses a key exactly where
/// dalek cannot decode it, finds it weak, or it is encoded so; and nothing it
/// accepts does `verify`, the check rPGP makes, refuse.
fn compare(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<(), Ed25519Error> {
    let verdict = verify_message(key, message, signature);
    let canonical = y_below_p(key);
    assert_eq!(
        verdict.is_ok(),
        dalek_strict(key, message, signature) && canonical,
        "key {key:02x?}, signature {signature:02x?}"
    );
    let weak = VerifyingKey::from_bytes(key).map_or(true, |key| key.is_weak());
    assert_eq!(
        verdict == Err(Ed25519Error::InvalidKey),
        weak || !canonical,
        "key {key:02x?}"
    );
    assert!(verdict.is_err() || dalek_lenient(key, message, signature));
    verdict
}

/// The one place irongall and `verify_strict` part: a key encoded with a
/// y-coordinate of p + y, for the y below 19 whose points are not of small
/// order. dalek reduces the coordinate and accepts the key; RFC 8032 §5.1.3
/// fails the decoding, and so does irongall.
#[test]
fn non_canonical_keys_dalek_accepts() {
    let p = (BigUint::from(1u8) << 255u32) - 19u8;
    let mut refused = Vec::new();
    for y in 0u8..19 {
        let key: [u8; 32] = (&p + y).to_bytes_le().try_into().unwrap();
        if VerifyingKey::from_bytes(&key).is_ok_and(|key| !key.is_weak()) {
            assert_eq!(
                verify_message(&key, b"", &[0; 64]),
                Err(Ed25519Error::InvalidKey),
                "y = p + {y}"
            );
            refused.push(y);
        }
    }
    assert_eq!(refused, [3, 4, 5, 6, 9, 10, 14, 15, 16, 18]);
}

/// Signatures ed25519-dalek makes verify, and altered ones are judged as
/// dalek judges them.
#[test]
fn agrees_with_ed25519_dalek() {
    let mut rng = Rng::new(40);
    let l = (BigUint::from(1u8) << 252u32)
        + "27742317777372353535851937790883648493"
            .parse::<BigUint>()
            .unwrap();
    let mut verdicts = [0; 3];
    for _ in 0..200 {
        let (signing, key) = key_pair(rng.bytes(32).try_into().unwrap());
        let length = rng.below(300);
        let message = rng.bytes(length);
        let signature = signing.sign(&message).to_bytes();
        assert_eq!(compare(&key, &message, &signature), Ok(()));

        let mut altered = Vec::new();
        // One bit flipped, in the key, the signature, or the message.
        let mut flipped_key = key;
        flipped_key[rng.below(32)] ^= 1 << rng.below(8);
        altered.push((flipped_key, message.clone(), signature));
        let mut flipped_signature = signature;
        flipped_signature[rng.below(64)] ^= 1 << rng.below(8);
        altered.push((key, message.clone(), flipped_signature));
        if !message.is_empty() {
            let mut flipped_message = message.clone();
            flipped_message[rng.below(message.len())] ^= 1 << rng.below(8);
            altered.push((key, flipped_message, signature));
        }
        // S + L, and S + 2 L where it fits: the same scalar, not reduced.
        for multiple in [1u8, 2] {
            let s = BigUint::from_bytes_le(&signature[32..]) + &l * multiple;
            let s = s.to_bytes_le();
            if s.len() <= 32 {
                let mut malleated = signature;
                malleated[32..32 + s.len()].copy_from_slice(&s);
                altered.push((key, message.clone(), malleated));
            }
        }
        // A key of random bytes, and one with a y-coordinate of p or more.
        altered.push((
            rng.bytes(32).try_into().unwrap(),
            message.clone(),
            signature,
        ));
        let mut high = [0xFF; 32];
        high[0] = 0xED + u8::try_from(rng.below(19)).unwrap();
        high[31] &= if rng.below(2) == 0 { 0x7F } else { 0xFF };
        altered.push((high, message.clone(), signature));

        for (key, message, signature) in altered {
            match compare(&key, &message, &signature) {
                Ok(()) => verdicts[0] += 1,
                Err(Ed25519Error::InvalidKey) => verdicts[1] += 1,
                Err(_) => verdicts[2] += 1,
            }
        }
    }
    // Nothing altered verifies; roughly half of the random keys do not
    // decode.
    assert_eq!(verdicts[0], 0, "{verdicts:?}");
    assert!(verdicts[1] > 300, "{verdicts:?}");
}

/// The packets of `data`, which must all read.
fn packets(data: &[u8]) -> Vec<Packet<'_>> {
    packet::packets(data).map(Result::unwrap).collect()
}

/// The Ed25519 key in a key packet.
fn ed25519_key(packet: &Packet<'_>) -> [u8; 32] {
    match PublicKey::from_packet(packet).unwrap().material() {
        KeyMaterial::Ed25519(key) => *key,
        other => panic!("not an Ed25519 key: {other:?}"),
    }
}

/// Checks that `signature`, over `data`, verifies with `key`, and with no
/// other key or digest.
fn check(signature: &Signature, key: &[u8; 32], data: &[u8]) {
    let SignatureMaterial::Ed25519(value) = signature.material() else {
        panic!("not an Ed25519 signature: {:?}", signature.material());
    };
    let digest = signature_digest(signature, data);
    assert_eq!(verify(key, &digest, value), Ok(()));
    let (_, other) = key_pair([1; 32]);
    assert_eq!(
        verify(&other, &digest, value),
        Err(Ed25519Error::BadSignature)
    );
    let mut altered = digest;
    match &mut altered {
        Digest::Sha256(bytes) => bytes[31] ^= 1,
        Digest::Sha384(bytes) => bytes[47] ^= 1,
        Digest::Sha512(bytes) => bytes[63] ^= 1,
        other => panic!("a digest too short for Ed25519: {other:?}"),
    }
    assert_eq!(
        verify(key, &altered, value),
        Err(Ed25519Error::BadSignature)
    );
}

/// The armored block's data.
fn dearmor(armored: &str) -> Vec<u8> {
    armor::decode(armored.as_bytes()).unwrap().into_data()
}

/// RFC 9580's version 4 sample: the EdDSALegacy signature of Appendix A.2
/// over "OpenPGP", by the key of Appendix A.1.
#[test]
fn rfc_9580_version_4() {
    let key = dearmor(A1_KEY);
    let [key] = <[Packet<'_>; 1]>::try_from(packets(&key)).unwrap();
    let signature = dearmor(A2_SIGNATURE);
    let [signature] = <[Packet<'_>; 1]>::try_from(packets(&signature)).unwrap();
    let signature = Signature::from_packet(&signature).unwrap();
    // The hash input and the digest the appendix gives.
    assert_eq!(
        signature_input(&signature, b"OpenPGP"),
        hex("4f70656e504750040016080006050255f95f9504ff0000000c")
    );
    assert_eq!(
        signature_digest(&signature, b"OpenPGP").as_bytes(),
        hex("f6220a3f757814f4c2176ffbb68b00249cd4ccdc059c4b34ad871f30b1740280")
    );
    check(&signature, &ed25519_key(&key), b"OpenPGP");
}

/// RFC 9580's version 6 samples: the certificate of Appendix A.3, its
/// direct-key signature and subkey binding over the data Appendix A.3.1
/// gives, and the text signature of Appendix A.6.
#[test]
fn rfc_9580_version_6() {
    let certificate = dearmor(A3_CERTIFICATE);
    let all = packets(&certificate);
    let tags: Vec<Tag> = all.iter().map(Packet::tag).collect();
    assert_eq!(
        tags,
        [
            Tag::PUBLIC_KEY,
            Tag::SIGNATURE,
            Tag::PUBLIC_SUBKEY,
            Tag::SIGNATURE
        ]
    );
    let [primary, direct, subkey, binding] = <[Packet<'_>; 4]>::try_from(all).unwrap();
    let key = ed25519_key(&primary);

    let direct = Signature::from_packet(&direct).unwrap();
    assert_eq!(direct.signature_type(), SignatureType::DIRECT_KEY);
    let data = hashed_key(primary.body());
    assert_eq!(
        signature_input(&direct, &data),
        hex("\
            103e2d7d227ec0e6d7ce4471db36bfc97083253690271498a7ef0576c07faae1\
            9b0000002a0663877fe31b00000020f94da7bb48d60a61e567706a6587d03319\
            99bb9d891a08242ead84543df895a3061f1b0a00000042058263877fe3030b09\
            0705150a0e080c021600029b03021e09222106cb186c4f0609a697e4d52dfa6c\
            722b0c1f1e27c18a56708f6525ec27bad9acc905270902070206ff0000004a")
    );
    check(&direct, &key, &data);

    let binding = Signature::from_packet(&binding).unwrap();
    assert_eq!(binding.signature_type(), SignatureType::SUBKEY_BINDING);
    let data = [hashed_key(primary.body()), hashed_key(subkey.body())].concat();
    assert_eq!(
        signature_input(&binding, &data),
        hex("\
            a6e9186d9d5935fc8fe56314cdb527486a5a5120f9b762a235a729f039010a56\
            9b0000002a0663877fe31b00000020f94da7bb48d60a61e567706a6587d03319\
            99bb9d891a08242ead84543df895a39b0000002a0663877fe319000000208693\
            248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e44350618\
            1b0a0000002c058263877fe3029b0c222106cb186c4f0609a697e4d52dfa6c72\
            2b0c1f1e27c18a56708f6525ec27bad9acc906ff00000034")
    );
    check(&binding, &key, &data);

    let text = dearmor(A6_SIGNATURE);
    let [text] = <[Packet<'_>; 1]>::try_from(packets(&text)).unwrap();
    let text = Signature::from_packet(&text).unwrap();
    assert_eq!(text.signature_type(), SignatureType::TEXT);
    assert_eq!(
        signature_digest(&text, A6_TEXT.as_bytes()).as_bytes(),
        hex(
            "69365bf44a97af1f0844f1f6ab83fdf6b36f26692efaa621a8aac91c4e29ea07\
             e894cabc6e2f20eedfce6c03b89141a2cc7cbe245e6e7a5654addbec5000b89b"
        )
    );
    check(&text, &key, A6_TEXT.as_bytes());
}

/// The certificates GnuPG made with EdDSALegacy keys, and the detached
/// signatures its signing subkey made.
#[test]
fn gnupg_signatures() {
    let mut checked = 0;
    for name in ["ed25519", "ed25519-signing"] {
        let certificate = vector_bytes(&format!("gnupg/{name}.pgp"));
        let all = packets(&certificate);
        let tags: Vec<Tag> = all.iter().map(Packet::tag).collect();
        assert_eq!(
            tags,
            [
                Tag::PUBLIC_KEY,
                Tag::USER_ID,
                Tag::SIGNATURE,
                Tag::PUBLIC_SUBKEY,
                Tag::SIGNATURE
            ],
            "{name}"
        );
        let [primary, user_id, certification, subkey, binding] =
            <[Packet<'_>; 5]>::try_from(all).unwrap();
        let key = ed25519_key(&primary);

        let certification = Signature::from_packet(&certification).unwrap();
        assert_eq!(
            certification.signature_type(),
            SignatureType::POSITIVE_CERTIFICATION
        );
        let data = [hashed_key(primary.body()), hashed_user_id(user_id.body())].concat();
        check(&certification, &key, &data);

        let binding = Signature::from_packet(&binding).unwrap();
        assert_eq!(binding.signature_type(), SignatureType::SUBKEY_BINDING);
        let data = [hashed_key(primary.body()), hashed_key(subkey.body())].concat();
        check(&binding, &key, &data);
        checked += 2;

        if name == "ed25519-signing" {
            // The subkey's back-signature, over the same keys, by the subkey.
            let subkey = ed25519_key(&subkey);
            let [back] = binding.embedded_signatures() else {
                panic!("one embedded signature");
            };
            assert_eq!(back.signature_type(), SignatureType::PRIMARY_KEY_BINDING);
            check(back, &subkey, &data);

            let document = vector_bytes("gnupg/document.txt");
            let text: Vec<u8> = document
                .split(|&octet| octet == b'\n')
                .collect::<Vec<_>>()
                .join(&b"\r\n"[..]);
            for (file, signature_type, data) in [
                ("binary", SignatureType::BINARY, &document),
                ("text", SignatureType::TEXT, &text),
            ] {
                let signature = vector_bytes(&format!("gnupg/{file}.sig"));
                let [signature] = <[Packet<'_>; 1]>::try_from(packets(&signature)).unwrap();
                let signature = Signature::from_packet(&signature).unwrap();
                assert_eq!(signature.signature_type(), signature_type);
                check(&signature, &subkey, data);
            }
            checked += 3;
        }
    }
    assert_eq!(checked, 7);
}
