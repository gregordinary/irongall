//! Signatures and keys rPGP made, with each octet altered in turn, read and
//! verified by both.

use pgp::crypto::hash::HashAlgorithm;

use super::{DOCUMENTS, Tally, framed, made, paired_key};
use crate::compare::{self, Divergence, Key, Over, Verdict};
use crate::make;

/// `packet` with one bit of the octet at each offset flipped in turn.
fn altered(packet: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    (0..packet.len()).map(|at| {
        let mut copy = packet.to_vec();
        copy[at] ^= 1 << (at % 8);
        copy
    })
}

/// Reads each alteration of the signature packet `packet` with both, and
/// verifies every signature both read in it, and its back-signature, with
/// `signer` (`back_signer`) over `over`.
fn alter_signature(
    packet: &[u8],
    signer: &Key,
    back_signer: &Key,
    over: Over<'_>,
    tally: &mut Tally,
) {
    for copy in altered(packet) {
        let packets = compare::read(&copy).unwrap();
        tally.read(&packets);
        for signature in &packets.signatures {
            tally.verify(Some(signature), signer, over);
            if let Some(back) = &signature.embedded {
                tally.verify(Some(back), back_signer, over);
            }
        }
    }
}

#[test]
fn every_octet() {
    let document = DOCUMENTS[3].as_bytes();
    let mut seed = 3000;
    for made in made() {
        let mut tally = Tally::default();
        let certificate = &made.certificate;
        let packets = &made.packets;
        let primary = paired_key(packets, certificate.primary());
        let subkey = &certificate.subkeys()[0];
        let signing = paired_key(packets, subkey.key());
        let packet_of = |signature: &irongall::signature::Signature| {
            framed(&made.data)
                .into_iter()
                .find(|packet| {
                    let mut framed = irongall::packet::packets(packet);
                    let packet = framed.next().unwrap().unwrap();
                    irongall::signature::Signature::from_packet(&packet).as_ref() == Ok(signature)
                })
                .unwrap()
        };

        // The self-signatures: a certification, the signing subkey's binding
        // and its back-signature, and a version 6 certificate's direct-key
        // signature.
        let user_id = &packets.user_ids[0];
        let over = Over::UserId {
            key: primary,
            user_id,
        };
        let certification = &certificate.user_ids()[0].signatures()[0];
        alter_signature(packet_of(certification), primary, primary, over, &mut tally);
        let over = Over::Subkey {
            primary,
            subkey: signing,
        };
        alter_signature(
            packet_of(&subkey.signatures()[0]),
            primary,
            signing,
            over,
            &mut tally,
        );
        if let Some(direct) = certificate.primary_signatures().first() {
            alter_signature(
                packet_of(direct),
                primary,
                primary,
                Over::Key(primary),
                &mut tally,
            );
        }

        // Document signatures by the signing subkey, binary and text.
        let secret = &*made.secret.secret_subkeys[0];
        for text in [false, true] {
            seed += 1;
            let signature =
                make::detached(secret, HashAlgorithm::Sha256, text, document, seed).unwrap();
            alter_signature(
                &signature,
                signing,
                signing,
                Over::Document(document),
                &mut tally,
            );

            // And the signing subkey's own packet, under the signature.
            let signature = &compare::read(&signature).unwrap().signatures[0];
            let key_packet = framed(&made.data)
                .into_iter()
                .find(|packet| {
                    compare::read(packet)
                        .unwrap()
                        .keys
                        .first()
                        .is_some_and(|key| key.irongall == signing.irongall)
                })
                .unwrap();
            for copy in altered(key_packet) {
                let packets = compare::read(&copy).unwrap();
                tally.read(&packets);
                for altered_key in &packets.keys {
                    tally.verify(Some(signature), altered_key, Over::Document(document));
                }
            }
        }
        // Altered, a signature still verifies where only what it does not
        // cover changed: its unhashed area, or a key's packet outside its
        // material. rPGP then refuses one whose issuer names the key as it
        // was. The counts move from run to run, as rPGP stamps what it signs
        // with its clock and an RSA signature's leading octets change with
        // it. Some alterations leave a packet only one of the two reads,
        // among them, always, a signature that no longer states its creation
        // time, which irongall refuses and rPGP reads.
        let name = made.shape.name;
        assert!(
            tally.one_sided.contains_key(&Divergence::NoCreationTime),
            "{name}: {tally:?}"
        );
        assert!(
            tally.verdicts.contains_key(&Verdict::Verified),
            "{name}: {tally:?}"
        );
        assert!(
            tally.verdicts.contains_key(&Verdict::Refused),
            "{name}: {tally:?}"
        );
        for verdict in tally.verdicts.keys() {
            assert!(
                matches!(
                    verdict,
                    Verdict::Verified
                        | Verdict::Refused
                        | Verdict::Diverged(
                            Divergence::IssuerNamesAnotherKey | Divergence::Reencoded
                        )
                ),
                "{name}: {tally:?}"
            );
        }
    }
}
