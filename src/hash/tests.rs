//! Known-answer tests from NIST's validation vectors, and differential tests
//! against RustCrypto's implementations.

use alloc::vec::Vec;

use sha2::Digest as _;

use super::sha3::{ROTATIONS, ROUND_CONSTANTS};
use super::{
    Context, HashAlgorithm, HashFunction, Sha1, Sha3_256, Sha3_512, Sha224, Sha256, Sha384, Sha512,
};
use crate::test_support::{Rng, hex, vector};

/// Checks every message in a CAVP short- or long-message file, at `file`
/// under the vectors' directory, which holds `expected` of them.
fn cavp_messages<H: HashFunction>(file: &str, expected: usize) {
    let text = vector(file);
    let mut bits = None;
    let mut message = None;
    let mut checked = 0;
    for line in text.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("Len = ") {
            bits = Some(value.parse::<usize>().unwrap());
        } else if let Some(value) = line.strip_prefix("Msg = ") {
            message = Some(hex(value));
        } else if let Some(value) = line.strip_prefix("MD = ") {
            let bits = bits.take().unwrap();
            let mut message = message.take().unwrap();
            // The empty message is written `Msg = 00`; its length is in `Len`.
            assert_eq!(
                bits % 8,
                0,
                "{file}: a bit length the byte vectors do not use"
            );
            message.truncate(bits / 8);
            assert_eq!(
                H::digest(&message).as_ref(),
                hex(value),
                "{file}: Len = {bits}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, expected, "{file}: messages checked");
}

/// Runs the Monte Carlo test of a CAVP SHA-1 or SHA-2 file (SHAVS §6.4): a
/// hundred checkpoints, each a thousand chained hashes past the one before.
fn cavp_monte<H: HashFunction>(file: &str) {
    let text = vector(&alloc::format!("cavp-shs/{file}"));
    let mut lines = text.lines().map(str::trim);
    let seed = lines.find_map(|line| line.strip_prefix("Seed = ")).unwrap();
    let mut seed = hex(seed);
    let mut checked = 0;
    for expected in lines.filter_map(|line| line.strip_prefix("MD = ")) {
        let mut previous = [seed.clone(), seed.clone(), seed];
        for _ in 3..1003 {
            let message = previous.concat();
            let digest = H::digest(&message).as_ref().to_vec();
            previous = [previous[1].clone(), previous[2].clone(), digest];
        }
        seed = previous[2].clone();
        assert_eq!(seed, hex(expected), "{file}: COUNT = {checked}");
        checked += 1;
    }
    assert_eq!(checked, 100, "{file}: checkpoints checked");
}

/// Runs the Monte Carlo test of a CAVP SHA-3 file (SHA3VS §6.2.3): a
/// hundred checkpoints, each a thousand hashes past the one before, every
/// hash taken of the digest before it alone.
fn cavp_sha3_monte<H: HashFunction>(file: &str) {
    let text = vector(&alloc::format!("cavp-sha3/{file}"));
    let mut lines = text.lines().map(str::trim);
    let seed = lines.find_map(|line| line.strip_prefix("Seed = ")).unwrap();
    let mut digest = hex(seed);
    let mut checked = 0;
    for expected in lines.filter_map(|line| line.strip_prefix("MD = ")) {
        for _ in 0..1000 {
            digest = H::digest(&digest).as_ref().to_vec();
        }
        assert_eq!(digest, hex(expected), "{file}: COUNT = {checked}");
        checked += 1;
    }
    assert_eq!(checked, 100, "{file}: checkpoints checked");
}

/// Compares `H` against `reference` over every length up to three of the
/// largest block size, SHA3-256's rate of 136 bytes, and random lengths past
/// that, each given whole and in random pieces.
fn agrees_with<H: HashFunction>(seed: u64, reference: impl Fn(&[u8]) -> Vec<u8>) {
    let mut rng = Rng::new(seed);
    let lengths: Vec<usize> = (0..=3 * 136)
        .chain((0..200).map(|_| rng.below(20_000)))
        .collect();
    for len in lengths {
        let data = rng.bytes(len);
        let expected = reference(&data);
        assert_eq!(H::digest(&data).as_ref(), expected, "length {len}");

        let mut hash = H::new();
        let mut rest = &data[..];
        while !rest.is_empty() {
            // Empty pieces too, which must change nothing.
            let (piece, tail) = rest.split_at(rng.below(rest.len().min(300) + 1));
            hash.update(piece);
            rest = tail;
        }
        assert_eq!(
            hash.finalize().as_ref(),
            expected,
            "length {len}, in pieces"
        );
    }
}

/// A hash cloned part-way through continues independently of the original.
fn clones_are_independent<H: HashFunction>() {
    let mut rng = Rng::new(0x636c_6f6e);
    let (prefix, first, second) = (rng.bytes(150), rng.bytes(70), rng.bytes(300));
    let mut hash = H::new();
    hash.update(&prefix);
    let mut clone = hash.clone();
    hash.update(&first);
    clone.update(&second);
    assert_eq!(
        hash.finalize().as_ref(),
        H::digest(&[&prefix[..], &first].concat()).as_ref()
    );
    assert_eq!(
        clone.finalize().as_ref(),
        H::digest(&[&prefix[..], &second].concat()).as_ref()
    );
}

#[test]
fn sha1_cavp() {
    cavp_messages::<Sha1>("cavp-shs/SHA1ShortMsg.rsp", 65);
    cavp_messages::<Sha1>("cavp-shs/SHA1LongMsg.rsp", 64);
    cavp_monte::<Sha1>("SHA1Monte.rsp");
}

#[test]
fn sha224_cavp() {
    cavp_messages::<Sha224>("cavp-shs/SHA224ShortMsg.rsp", 65);
    cavp_messages::<Sha224>("cavp-shs/SHA224LongMsg.rsp", 64);
    cavp_monte::<Sha224>("SHA224Monte.rsp");
}

#[test]
fn sha256_cavp() {
    cavp_messages::<Sha256>("cavp-shs/SHA256ShortMsg.rsp", 65);
    cavp_messages::<Sha256>("cavp-shs/SHA256LongMsg.rsp", 64);
    cavp_monte::<Sha256>("SHA256Monte.rsp");
}

#[test]
fn sha384_cavp() {
    cavp_messages::<Sha384>("cavp-shs/SHA384ShortMsg.rsp", 129);
    cavp_messages::<Sha384>("cavp-shs/SHA384LongMsg.rsp", 128);
    cavp_monte::<Sha384>("SHA384Monte.rsp");
}

#[test]
fn sha512_cavp() {
    cavp_messages::<Sha512>("cavp-shs/SHA512ShortMsg.rsp", 129);
    cavp_messages::<Sha512>("cavp-shs/SHA512LongMsg.rsp", 128);
    cavp_monte::<Sha512>("SHA512Monte.rsp");
}

#[test]
fn sha3_256_cavp() {
    cavp_messages::<Sha3_256>("cavp-sha3/SHA3_256ShortMsg.rsp", 137);
    cavp_messages::<Sha3_256>("cavp-sha3/SHA3_256LongMsg.rsp", 100);
    cavp_sha3_monte::<Sha3_256>("SHA3_256Monte.rsp");
}

#[test]
fn sha3_512_cavp() {
    cavp_messages::<Sha3_512>("cavp-sha3/SHA3_512ShortMsg.rsp", 73);
    cavp_messages::<Sha3_512>("cavp-sha3/SHA3_512LongMsg.rsp", 100);
    cavp_sha3_monte::<Sha3_512>("SHA3_512Monte.rsp");
}

/// The round constants and the rotations of Keccak-f\[1600\] are those FIPS
/// 202's own algorithms compute: the round constants from the linear
/// feedback shift register of Algorithm 5, placed as Algorithm 6 places
/// them (§3.2.5), and the rotations from the walk of Algorithm 2 (§3.2.2).
#[test]
fn keccak_tables_follow_fips_202() {
    // rc(t): the register R starts as 10000000, R[i] at bit i. Each step
    // prepends a zero, folds R[8] into R[0], R[4], R[5], and R[6], and
    // truncates R to eight bits; rc(t) is R[0] after t mod 255 steps.
    let rc = |t: usize| -> u64 {
        let mut r: u16 = 1;
        for _ in 0..t % 255 {
            r <<= 1;
            if r & 0x100 != 0 {
                r ^= 0x171;
            }
        }
        u64::from(r & 1)
    };
    let constants: Vec<u64> = (0..24)
        .map(|round| {
            (0..7)
                .map(|j| rc(j + 7 * round) << ((1 << j) - 1))
                .fold(0, |constant, bit| constant | bit)
        })
        .collect();
    assert_eq!(constants, ROUND_CONSTANTS);

    let mut rotations = [0; 25];
    let (mut x, mut y) = (1, 0);
    for t in 0..24 {
        rotations[x + 5 * y] = u32::try_from((t + 1) * (t + 2) / 2 % 64).unwrap();
        (x, y) = (y, (2 * x + 3 * y) % 5);
    }
    assert_eq!(rotations, ROTATIONS);
}

#[test]
fn agrees_with_rustcrypto() {
    agrees_with::<Sha1>(1, |data| sha1::Sha1::digest(data).to_vec());
    agrees_with::<Sha224>(224, |data| sha2::Sha224::digest(data).to_vec());
    agrees_with::<Sha256>(256, |data| sha2::Sha256::digest(data).to_vec());
    agrees_with::<Sha384>(384, |data| sha2::Sha384::digest(data).to_vec());
    agrees_with::<Sha512>(512, |data| sha2::Sha512::digest(data).to_vec());
    agrees_with::<Sha3_256>(3256, |data| sha3::Sha3_256::digest(data).to_vec());
    agrees_with::<Sha3_512>(3512, |data| sha3::Sha3_512::digest(data).to_vec());
}

#[test]
fn byte_at_a_time_matches_whole() {
    fn check<H: HashFunction>() {
        let data = Rng::new(0x6279_7465).bytes(1000);
        let mut hash = H::new();
        data.iter().for_each(|byte| hash.update(&[*byte]));
        assert_eq!(hash.finalize().as_ref(), H::digest(&data).as_ref());
    }
    check::<Sha1>();
    check::<Sha224>();
    check::<Sha256>();
    check::<Sha384>();
    check::<Sha512>();
    check::<Sha3_256>();
    check::<Sha3_512>();
}

#[test]
fn clones() {
    clones_are_independent::<Sha1>();
    clones_are_independent::<Sha224>();
    clones_are_independent::<Sha256>();
    clones_are_independent::<Sha384>();
    clones_are_independent::<Sha512>();
    clones_are_independent::<Sha3_256>();
    clones_are_independent::<Sha3_512>();
}

#[test]
fn default_is_the_empty_state() {
    fn check<H: HashFunction + Default>() {
        assert_eq!(
            H::default().finalize().as_ref(),
            H::new().finalize().as_ref()
        );
    }
    check::<Sha1>();
    check::<Sha224>();
    check::<Sha256>();
    check::<Sha384>();
    check::<Sha512>();
    check::<Sha3_256>();
    check::<Sha3_512>();
}

/// The table of what RFC 9580 gives of each hash algorithm agrees with the
/// implementations: each digest is as long as the table says, names its
/// algorithm, and has a DigestInfo whose DER lengths count it.
#[test]
fn descriptions_agree_with_the_implementations() {
    let mut implemented = 0;
    for description in &super::DESCRIPTIONS {
        let algorithm = description.algorithm;
        assert_eq!(
            HashAlgorithm::from_text_name(description.text_name),
            Some(algorithm)
        );
        let Some(context) = Context::new(algorithm) else {
            assert_eq!(description.digest_info, None, "{algorithm}");
            continue;
        };
        let digest = context.finalize();
        assert_eq!(digest.algorithm(), algorithm);
        assert_eq!(
            Some(digest.as_bytes().len()),
            algorithm.digest_length(),
            "{algorithm}"
        );
        // SEQUENCE { AlgorithmIdentifier, OCTET STRING of the digest }.
        let prefix = algorithm.digest_info_prefix().unwrap();
        assert_eq!(prefix[0], 0x30, "{algorithm}");
        assert_eq!(
            usize::from(prefix[1]),
            prefix.len() - 2 + description.digest_length,
            "{algorithm}"
        );
        assert_eq!(
            prefix[prefix.len() - 2..],
            [0x04, u8::try_from(description.digest_length).unwrap()],
            "{algorithm}"
        );
        implemented += 1;
    }
    assert_eq!(implemented, 7);
    assert_eq!(HashAlgorithm(100).digest_length(), None);
    assert_eq!(HashAlgorithm::from_text_name("sha256"), None);
}
