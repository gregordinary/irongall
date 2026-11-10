//! Tests of what the crate as a whole promises, beyond any one module.

use core::mem::size_of;

use crate::armor::Header;
use crate::cert::{Certificate, Subkey, UserId};
use crate::signature::{Signature, Subpacket};

/// SECURITY.md states how many times its size input packed with the
/// smallest certificates, user IDs, subkeys, signatures, subpackets, and
/// armor headers is held in, on a 64-bit target. Those factors rest on the
/// size of the structure each is held in: a structure that grows raises
/// them, and the statement with them.
#[cfg(target_pointer_width = "64")]
#[test]
fn the_structures_input_is_held_in_keep_their_sizes() {
    assert!(size_of::<Certificate>() <= 280);
    assert!(size_of::<UserId>() <= 72);
    assert!(size_of::<Subkey>() <= 160);
    assert!(size_of::<Signature>() <= 224);
    assert!(size_of::<Subpacket>() <= 32);
    assert!(size_of::<Header>() <= 48);
}
