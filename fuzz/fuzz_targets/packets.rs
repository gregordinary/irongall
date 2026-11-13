//! Packet framing, key reading, and signature reading over arbitrary input:
//! no panic, every packet the framing returns lies inside the input in order,
//! every key that reads has a fingerprint of its own version, and every
//! signature that reads is consistent with its own subpackets.

#![no_main]

use irongall::key::PublicKey;
use irongall::packet::{self, Packet, Tag, Version};
use irongall::signature::{Signature, SubpacketType};
use libfuzzer_sys::fuzz_target;

fn check_key(packet: &Packet<'_>) {
    if let Ok(key) = PublicKey::from_packet(packet) {
        assert_eq!(key.fingerprint().version(), key.version());
        assert_eq!(key.fingerprint().key_id(), key.key_id());
    }
}

fn check_signature(packet: &Packet<'_>, input_len: usize) {
    let signature = match Signature::from_packet(packet) {
        Ok(signature) => signature,
        Err(error) => {
            assert!(error.offset() <= input_len);
            return;
        }
    };
    assert_eq!(signature.salt().is_empty(), signature.version() == Version::V4);
    let created = signature
        .hashed_subpackets()
        .filter(|subpacket| subpacket.subpacket_type() == SubpacketType::SIGNATURE_CREATION_TIME)
        .last()
        .expect("a hashed creation time");
    assert_eq!(created.body(), signature.creation_time().to_be_bytes());
    for embedded in signature.embedded_signatures() {
        assert!(embedded.embedded_signatures().is_empty());
    }
    for fingerprint in signature.issuer_fingerprints() {
        assert_eq!(fingerprint.version(), signature.version());
    }
}

fuzz_target!(|input: &[u8]| {
    // The input as a sequence of packets.
    let base = input.as_ptr() as usize;
    let mut end = 0;
    for packet in packet::packets(input) {
        let Ok(packet) = packet else { break };
        let body_start = packet.body().as_ptr() as usize - base;
        assert_eq!(packet.offset(), end);
        assert!(body_start > packet.offset());
        end = body_start + packet.body().len();
        assert!(end <= input.len());
        match packet.tag() {
            Tag::PUBLIC_KEY | Tag::PUBLIC_SUBKEY => check_key(&packet),
            Tag::SIGNATURE => check_signature(&packet, input.len()),
            _ => {}
        }
    }

    // The input as the body of one Public Key packet, and of one Signature
    // packet, so each reader is reached without the framing having to be
    // found first.
    let Ok(length) = u32::try_from(input.len()) else { return };
    for tag in [0xC6, 0xC2] {
        let wrapped = [&[tag, 0xFF][..], &length.to_be_bytes(), input].concat();
        if let Some(Ok(packet)) = packet::packets(&wrapped).next() {
            check_key(&packet);
            check_signature(&packet, wrapped.len());
        }
    }
});
