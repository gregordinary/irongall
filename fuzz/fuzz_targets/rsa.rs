//! RSA key reading and signature verification over arbitrary input: no
//! panic, and a key's verdict on a signature is the same whatever leading
//! zeros the signature carries.

#![no_main]

use irongall::hash::{Digest, HashFunction as _, Sha256};
use irongall::rsa::PublicKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    // Two octets give the modulus's length and one the exponent's; the rest
    // is the signature.
    let [high, low, exponent_length, rest @ ..] = input else {
        return;
    };
    let modulus_length = usize::from(u16::from_be_bytes([*high, *low])).min(rest.len());
    let (modulus, rest) = rest.split_at(modulus_length);
    let (exponent, signature) = rest.split_at(usize::from(*exponent_length).min(rest.len()));
    let Ok(key) = PublicKey::new(modulus, exponent) else {
        return;
    };
    let digest = Digest::Sha256(Sha256::digest(input));
    let verdict = key.verify(&digest, signature);
    let padded = [&[0, 0][..], signature].concat();
    assert_eq!(key.verify(&digest, &padded), verdict);
});
