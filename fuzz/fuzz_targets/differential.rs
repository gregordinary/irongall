//! irongall and rPGP over arbitrary input: what both read, they read alike,
//! and on every signature both read, over every subject the input offers,
//! they reach the same verdict or differ as a `Divergence` says they may.
//!
//! The input is a two-octet big-endian length, that many octets of packets,
//! and a document. Each signature in the packets, and its first embedded
//! signature, is verified with each key in them over the document, over
//! each key, over each key with each user ID, and over each pair of keys.

#![no_main]

#[path = "../../tests/differential/compare.rs"]
mod compare;

use compare::{Key, Over, Packets, Signature};
use libfuzzer_sys::fuzz_target;

/// How many keys, user IDs and signatures are tried. The subjects grow with
/// their product, so a long input is cut to these rather than slowing every
/// run.
const KEYS: usize = 4;
const USER_IDS: usize = 2;
const SIGNATURES: usize = 4;

/// Verifies `signature` with each key over each subject, comparing the
/// verdicts.
fn check(signature: &Signature, keys: &[Key], packets: &Packets, document: &[u8]) {
    let user_ids = &packets.user_ids[..packets.user_ids.len().min(USER_IDS)];
    let mut subjects = vec![Over::Document(document)];
    for key in keys {
        subjects.push(Over::Key(key));
        subjects.extend(user_ids.iter().map(|user_id| Over::UserId { key, user_id }));
        subjects.extend(keys.iter().map(|subkey| Over::Subkey {
            primary: key,
            subkey,
        }));
    }
    for signer in keys {
        for &over in &subjects {
            if let Err(disagreement) = compare::verify(signature, signer, over) {
                panic!("{disagreement}");
            }
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((length, rest)) = input.split_first_chunk::<2>() else {
        return;
    };
    let length = usize::from(u16::from_be_bytes(*length)).min(rest.len());
    let (data, document) = rest.split_at(length);
    let packets = match compare::read(data) {
        Ok(packets) => packets,
        Err(disagreement) => panic!("{disagreement}"),
    };
    let keys = &packets.keys[..packets.keys.len().min(KEYS)];
    for signature in packets.signatures.iter().take(SIGNATURES) {
        check(signature, keys, &packets, document);
        if let Some(back) = &signature.embedded {
            check(back, keys, &packets, document);
        }
    }
});
