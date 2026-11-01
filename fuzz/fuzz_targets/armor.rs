//! Armor decoding over arbitrary input: no panic, and the two entry points
//! agree on an input holding a single block.

#![no_main]

use irongall::armor::{self, ArmorErrorKind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let all = armor::decode_all(input);
    let one = armor::decode(input);
    match (&all, &one) {
        (Ok(blocks), Ok(block)) => assert_eq!(blocks.as_slice(), core::slice::from_ref(block)),
        (Ok(blocks), Err(error)) => {
            assert!(blocks.len() > 1);
            assert_eq!(error.kind(), ArmorErrorKind::ExtraBlock);
        }
        (Err(_), Ok(_)) => panic!("decode accepted what decode_all refused"),
        (Err(_), Err(_)) => {}
    }
    // The data is at most three quarters of the input it was decoded from.
    if let Ok(blocks) = all {
        let decoded: usize = blocks.iter().map(|block| block.data().len()).sum();
        assert!(decoded <= input.len() / 4 * 3);
    }
});
