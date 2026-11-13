//! irongall and rPGP side by side: the same octets read by both, and every
//! verdict compared.
//!
//! rPGP is an independent implementation of the same specification. Given
//! the same packets, the two must frame them alike, read the same keys and
//! signatures out of them, and agree on whether each signature verifies over
//! each subject it can be made over. Where they differ, the difference must
//! be one of those [`Divergence`] lists: a rule one of the two keeps and the
//! other does not. Each is recognized from the input, never from either
//! verdict, so that a defect cannot pass as a divergence by producing the
//! verdict the divergence would. Any other difference is a [`Disagreement`],
//! and that holds for a packet only one of the two reads as for a signature
//! only one of them verifies: [`form`] reads what is in such a packet.
//!
//! The `differential` tests and the `differential` fuzz target share this
//! file; the fuzz target includes it by path.

#[path = "form.rs"]
mod form;

use std::collections::BTreeSet;
use std::fmt;
use std::io::Read as _;

use irongall::key::{KeyMaterial, PublicKeyAlgorithm};
use irongall::packet::{self, Packet, PacketError, PacketErrorKind, Tag, Version};
use irongall::signature::{SignatureMaterial, SignatureType, Subject, SubpacketType, VerifyError};
use pgp::packet::{PacketHeader, PacketParser, SignatureVersionSpecific};
use pgp::ser::Serialize as _;
use pgp::types::{
    EddsaLegacyPublicParams, KeyDetails as _, PublicParams, SignatureBytes, Tag as RpgpTag,
};
use rsa::traits::PublicKeyParts as _;

/// A difference between irongall and rPGP that no [`Divergence`] explains.
#[derive(Debug)]
pub(crate) struct Disagreement(String);

impl fmt::Display for Disagreement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Fails with a disagreement over `what` unless the two read the same.
fn same<T: PartialEq + fmt::Debug>(what: &str, irongall: T, rpgp: T) -> Result<(), Disagreement> {
    if irongall == rpgp {
        Ok(())
    } else {
        Err(Disagreement(format!(
            "{what}: irongall reads {irongall:?}, rPGP {rpgp:?}"
        )))
    }
}

/// A key, as both read it from the same packet body.
#[derive(Debug, Clone)]
pub(crate) struct Key {
    pub(crate) irongall: irongall::key::PublicKey,
    pub(crate) rpgp: pgp::packet::PublicKey,
    /// Whether rPGP encodes the key as other octets than the body it read.
    /// rPGP hashes its own encoding of a key, and fingerprints it.
    pub(crate) reencoded: bool,
}

/// A user ID, as both read it from the same packet body.
#[derive(Debug, Clone)]
pub(crate) struct UserId {
    pub(crate) value: Vec<u8>,
    pub(crate) rpgp: pgp::packet::UserId,
}

/// A signature, as both read it from the same packet body.
#[derive(Debug, Clone)]
pub(crate) struct Signature {
    pub(crate) irongall: irongall::signature::Signature,
    pub(crate) rpgp: pgp::packet::Signature,
    /// Whether rPGP encodes the hashed subpacket area as other octets than
    /// it read. rPGP hashes its own encoding of the area.
    pub(crate) reencoded: bool,
    /// The first embedded signature, where both read one.
    pub(crate) embedded: Option<Box<Signature>>,
}

/// The keys, user IDs and signatures in a run of packets, as both read them,
/// in the order of the packets.
///
/// A packet only one of the two reads is left out of these, and the
/// divergence that explains why is kept in its place.
#[derive(Debug, Default)]
pub(crate) struct Packets {
    pub(crate) keys: Vec<Key>,
    pub(crate) user_ids: Vec<UserId>,
    pub(crate) signatures: Vec<Signature>,
    /// For each packet only one of the two frames or reads, in order, the
    /// divergence that explains it.
    pub(crate) one_sided: Vec<Divergence>,
}

/// Reads `input` with both.
///
/// irongall frames the packets, and rPGP must frame every packet irongall
/// frames with the same tag and body, and frame no packet where irongall
/// frames none, unless a divergence explains why. Each key, user ID and
/// signature packet is then read by both from that body. Where both read it,
/// what they read must agree, and where only one does, a divergence must
/// explain why. Reading stops at the first packet irongall refuses to frame.
///
/// # Errors
///
/// When the two frame or read a packet differently.
pub(crate) fn read(input: &[u8]) -> Result<Packets, Disagreement> {
    let mut rpgp = PacketParser::new(input);
    let mut packets = Packets::default();
    for packet in packet::packets(input) {
        match packet {
            Ok(packet) => {
                same_frame(&mut rpgp, &packet)?;
                read_packet(&packet, &mut packets)?;
            }
            Err(error) => {
                let irongall = format!("irongall refuses to frame a packet ({error})");
                if let Err(disagreement) = frames_none(&mut rpgp, &irongall) {
                    // As for a packet's body, irongall's refusal names its
                    // rule, and the header must show that the rule applies.
                    let explaining = match error.kind() {
                        PacketErrorKind::PartialBodyLength
                        | PacketErrorKind::IndeterminateLength => Divergence::StreamedLength,
                        PacketErrorKind::ReservedType => Divergence::ReservedType,
                        _ => return Err(disagreement),
                    };
                    if !form::header(&input[error.offset()..]).contains(&explaining) {
                        return Err(disagreement);
                    }
                    packets.one_sided.push(explaining);
                }
                return Ok(packets);
            }
        }
    }
    frames_none(&mut rpgp, "irongall finds the input ended")?;
    Ok(packets)
}

/// Checks that rPGP frames no packet next: it finds the input ended, or
/// fails to read the next packet's header or its body. `irongall` says what
/// irongall found instead.
fn frames_none(rpgp: &mut PacketParser<&[u8]>, irongall: &str) -> Result<(), Disagreement> {
    let Some(Ok(mut reader)) = rpgp.next_ref() else {
        return Ok(());
    };
    let tag = reader.packet_header().tag();
    match reader.read_to_end(&mut Vec::new()) {
        Err(_) => Ok(()),
        Ok(_) => Err(Disagreement(format!(
            "{irongall}, and rPGP frames a {tag:?} packet"
        ))),
    }
}

/// Checks that rPGP's next packet is `packet`.
fn same_frame(rpgp: &mut PacketParser<&[u8]>, packet: &Packet<'_>) -> Result<(), Disagreement> {
    let at = packet.offset();
    let mut reader = match rpgp.next_ref() {
        Some(Ok(reader)) => reader,
        Some(Err(error)) => {
            return Err(Disagreement(format!(
                "irongall frames a packet at offset {at}, rPGP fails: {error}"
            )));
        }
        None => {
            return Err(Disagreement(format!(
                "irongall frames a packet at offset {at}, rPGP finds the input ended"
            )));
        }
    };
    let tag = reader.packet_header().tag();
    let mut body = Vec::new();
    reader.read_to_end(&mut body).map_err(|error| {
        Disagreement(format!(
            "irongall frames a packet at offset {at}, rPGP fails to read its body: {error}"
        ))
    })?;
    same(
        &format!("the tag of the packet at offset {at}"),
        packet.tag().number(),
        u8::from(tag),
    )?;
    same(
        &format!("the body of the packet at offset {at}"),
        packet.body(),
        &body[..],
    )
}

/// Reads one packet with both, keeping it in `into` where both read it.
fn read_packet(packet: &Packet<'_>, into: &mut Packets) -> Result<(), Disagreement> {
    let body = packet.body();
    // rPGP is given the body irongall framed under a header of its own, so
    // what it reads is the body alone: framing was compared already. Every
    // key is read as a primary key, since the two key packets share a body.
    let header = |tag| {
        let length = u32::try_from(body.len()).expect("a framed body is shorter than 2^32");
        PacketHeader::new_fixed(tag, length)
    };
    match packet.tag() {
        Tag::PUBLIC_KEY | Tag::PUBLIC_SUBKEY => {
            let irongall = irongall::key::PublicKey::from_packet(packet);
            let rpgp = pgp::packet::PublicKey::try_from_reader(header(RpgpTag::PublicKey), body);
            match (irongall, rpgp) {
                (Ok(irongall), Ok(rpgp)) => {
                    let reencoded = rpgp.to_bytes().ok().as_deref() != Some(body);
                    same_key(&irongall, &rpgp, reencoded)?;
                    into.keys.push(Key {
                        irongall,
                        rpgp,
                        reencoded,
                    });
                }
                (Err(_), Err(_)) => {}
                (ours, theirs) => into.one_sided.push(one_sided(
                    packet,
                    ours.err(),
                    theirs.err(),
                    &form::key(body),
                )?),
            }
        }
        Tag::USER_ID => match pgp::packet::UserId::try_from_reader(header(RpgpTag::UserId), body) {
            Ok(rpgp) => {
                same("a user ID", body, rpgp.id())?;
                into.user_ids.push(UserId {
                    value: body.to_vec(),
                    rpgp,
                });
            }
            Err(error) => {
                return Err(Disagreement(format!(
                    "irongall reads the user ID at offset {}, and rPGP refuses it: {error}",
                    packet.offset()
                )));
            }
        },
        Tag::SIGNATURE => {
            let irongall = irongall::signature::Signature::from_packet(packet);
            let rpgp = pgp::packet::Signature::try_from_reader(header(RpgpTag::Signature), body);
            match (irongall, rpgp) {
                (Ok(irongall), Ok(rpgp)) => into.signatures.push(signature(irongall, rpgp, body)?),
                (Err(_), Err(_)) => {}
                (ours, theirs) => into.one_sided.push(one_sided(
                    packet,
                    ours.err(),
                    theirs.err(),
                    &form::signature(body),
                )?),
            }
        }
        _ => {}
    }
    Ok(())
}

/// Why only one of the two reads `packet`: irongall alone if `refusal` is
/// `None`, rPGP refusing it with `theirs`, and otherwise rPGP alone,
/// irongall refusing it with `refusal`. `departures` are those [`form`]
/// finds in its body. rPGP's refusal is reported, never weighed.
///
/// irongall's refusal says which of its rules refused, and the divergence is
/// accepted only when the body shows that rule applies. Where irongall reads
/// what rPGP refuses, the body must hold something rPGP reads further than
/// irongall does.
fn one_sided(
    packet: &Packet<'_>,
    refusal: Option<PacketError>,
    theirs: Option<pgp::errors::Error>,
    departures: &BTreeSet<Divergence>,
) -> Result<Divergence, Disagreement> {
    let explaining: &[Divergence] = match refusal.as_ref().map(PacketError::kind) {
        None => &[
            Divergence::UndecodedSubpacket,
            Divergence::NestedEmbeddedSignature,
            Divergence::EmbeddedSignatureType,
            Divergence::OpaqueMaterial,
            Divergence::PointOffCurve,
            Divergence::InvalidRsaKey,
            Divergence::ReencodedEmbeddedSignature,
        ],
        Some(PacketErrorKind::UnsupportedVersion) => &[Divergence::OtherVersion],
        Some(PacketErrorKind::MissingCreationTime) => &[Divergence::NoCreationTime],
        Some(PacketErrorKind::InvalidSubpacket) => &[Divergence::MalformedSubpacket],
        Some(PacketErrorKind::CriticalSubpacket) => &[Divergence::CriticalSubpacket],
        Some(PacketErrorKind::InvalidMpi) => &[Divergence::MpiLength],
        // Octets after a version 6 key's counted material trail it, and so
        // do those after an encrypt-only signature's MPI.
        Some(PacketErrorKind::TrailingData) => &[
            Divergence::TrailingMaterial,
            Divergence::MaterialCount,
            Divergence::EncryptOnlyMaterial,
        ],
        Some(PacketErrorKind::TruncatedBody) => &[Divergence::EncryptOnlyMaterial],
        Some(PacketErrorKind::MaterialLength) => &[Divergence::MaterialCount],
        Some(_) => &[],
    };
    explaining
        .iter()
        .copied()
        .find(|divergence| departures.contains(divergence))
        .ok_or_else(|| {
            let at = packet.offset();
            Disagreement(match refusal {
                None => format!(
                    "irongall reads the packet at offset {at} and rPGP refuses it ({}), as \
                     nothing in it explains: {departures:?}",
                    theirs.map_or_else(String::new, |error| error.to_string())
                ),
                Some(error) => format!(
                    "irongall refuses the packet at offset {at} ({error}) and rPGP reads it, as \
                     nothing in it explains: {departures:?}"
                ),
            })
        })
}

/// Pairs a signature both read from `body`, with its first embedded
/// signature, once what they read is shown to agree.
fn signature(
    irongall: irongall::signature::Signature,
    rpgp: pgp::packet::Signature,
    body: &[u8],
) -> Result<Signature, Disagreement> {
    same_signature(&irongall, &rpgp)?;
    // The first embedded signature irongall reads is the body of the first
    // Embedded Signature subpacket, hashed area first.
    let embedded_body = irongall
        .hashed_subpackets()
        .chain(irongall.unhashed_subpackets())
        .find(|subpacket| subpacket.subpacket_type() == SubpacketType::EMBEDDED_SIGNATURE)
        .map(|subpacket| subpacket.body().to_vec());
    let embedded = match (
        irongall.embedded_signatures().first(),
        rpgp.embedded_signature(),
        embedded_body,
    ) {
        (Some(ours), Some(theirs), Some(body)) => {
            same_signature(ours, theirs)?;
            Some(Box::new(Signature {
                irongall: ours.clone(),
                rpgp: theirs.clone(),
                reencoded: reencoded(theirs, &body),
                embedded: None,
            }))
        }
        _ => None,
    };
    Ok(Signature {
        reencoded: reencoded(&rpgp, body),
        irongall,
        rpgp,
        embedded,
    })
}

/// Whether rPGP encodes the hashed subpacket area of the signature it read
/// from `body` as other octets than the area holds.
fn reencoded(rpgp: &pgp::packet::Signature, body: &[u8]) -> bool {
    // The area's length is two octets in a version 4 signature and four in a
    // version 6 one, after the version, type and two algorithm octets
    // (RFC 9580 §5.2.3).
    let area = match body {
        [4, _, _, _, high, low, rest @ ..] => {
            rest.get(..usize::from(u16::from_be_bytes([*high, *low])))
        }
        [6, _, _, _, a, b, c, d, rest @ ..] => {
            let length = u32::from_be_bytes([*a, *b, *c, *d]);
            usize::try_from(length)
                .ok()
                .and_then(|length| rest.get(..length))
        }
        _ => None,
    };
    let mut encoded = Vec::new();
    for subpacket in rpgp
        .config()
        .map_or(&[][..], |config| &config.hashed_subpackets)
    {
        if subpacket.to_writer(&mut encoded).is_err() {
            return true;
        }
    }
    area != Some(&encoded[..])
}

/// The octet a version is on the wire.
fn version_number(version: Version) -> u8 {
    match version {
        Version::V4 => 4,
        Version::V6 => 6,
        other => panic!("a version irongall does not read: {other:?}"),
    }
}

/// Checks that the two read the same key. The fingerprint is compared only
/// where rPGP encodes the key as the octets it read: it fingerprints its own
/// encoding, and RFC 9580 §5.5.4 the packet as it is.
fn same_key(
    ours: &irongall::key::PublicKey,
    theirs: &pgp::packet::PublicKey,
    reencoded: bool,
) -> Result<(), Disagreement> {
    same(
        "a key's version",
        version_number(ours.version()),
        u8::from(theirs.version()),
    )?;
    same(
        "a key's creation time",
        ours.creation_time(),
        theirs.created_at().as_secs(),
    )?;
    same(
        "a key's algorithm",
        ours.algorithm().number(),
        u8::from(theirs.algorithm()),
    )?;
    if !reencoded {
        same(
            "a fingerprint",
            ours.fingerprint().as_bytes(),
            theirs.fingerprint().as_bytes(),
        )?;
        same(
            "a key ID",
            &ours.key_id().as_bytes()[..],
            theirs.legacy_key_id().as_ref(),
        )?;
    }
    match (ours.material(), theirs.public_params()) {
        (KeyMaterial::Rsa { modulus, exponent }, PublicParams::RSA(params)) => {
            same("an RSA modulus", modulus, &params.key.n().to_bytes_be())?;
            same("an RSA exponent", exponent, &params.key.e().to_bytes_be())
        }
        (KeyMaterial::Ed25519(point), PublicParams::Ed25519(params)) => {
            same("an Ed25519 key", point, params.key.as_bytes())
        }
        (
            KeyMaterial::Ed25519(point),
            PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }),
        ) => same("an EdDSALegacy key", point, key.as_bytes()),
        // Material irongall does not read is rPGP's alone: DSA, ECDSA, Ed448
        // and the encryption algorithms.
        (KeyMaterial::Opaque, _) => Ok(()),
        (ours, theirs) => Err(Disagreement(format!(
            "a key's material: irongall reads {ours:?}, rPGP {theirs:?}"
        ))),
    }
}

/// How many subpackets of `kind` the hashed area holds.
///
/// A field read from a subpacket is compared only where the subpacket occurs
/// once: irongall takes the last occurrence (RFC 9580 §5.2.3.9 makes later
/// ones override earlier ones), rPGP the first.
fn hashed_count(signature: &irongall::signature::Signature, kind: SubpacketType) -> usize {
    signature
        .hashed_subpackets()
        .filter(|subpacket| subpacket.subpacket_type() == kind)
        .count()
}

/// Checks that the two read the same signature.
fn same_signature(
    ours: &irongall::signature::Signature,
    theirs: &pgp::packet::Signature,
) -> Result<(), Disagreement> {
    let Some(config) = theirs.config() else {
        return Err(Disagreement(format!(
            "irongall reads a version {} signature rPGP does not",
            version_number(ours.version())
        )));
    };
    same(
        "a signature's version",
        version_number(ours.version()),
        u8::from(theirs.version()),
    )?;
    same(
        "a signature's type",
        ours.signature_type().number(),
        u8::from(config.typ),
    )?;
    same(
        "a signature's public-key algorithm",
        ours.public_key_algorithm().number(),
        u8::from(config.pub_alg),
    )?;
    same(
        "a signature's hash algorithm",
        ours.hash_algorithm().number(),
        u8::from(config.hash_alg),
    )?;
    same(
        "a signature's hash prefix",
        Some(ours.hash_prefix()),
        theirs.signed_hash_value(),
    )?;
    let salt = match &config.version_specific {
        SignatureVersionSpecific::V6 { salt } => &salt[..],
        _ => &[],
    };
    same("a signature's salt", ours.salt(), salt)?;
    same(
        "a signature's issuer key IDs",
        ours.issuer_key_ids()
            .map(|key_id| key_id.as_bytes().to_vec())
            .collect::<Vec<_>>(),
        theirs
            .issuer_key_id()
            .into_iter()
            .map(|key_id| key_id.as_ref().to_vec())
            .collect(),
    )?;
    same(
        "a signature's issuer fingerprints",
        ours.issuer_fingerprints()
            .map(|fingerprint| fingerprint.as_bytes().to_vec())
            .collect::<Vec<_>>(),
        theirs
            .issuer_fingerprint()
            .into_iter()
            .map(|fingerprint| fingerprint.as_bytes().to_vec())
            .collect(),
    )?;
    let once = |kind| hashed_count(ours, kind) == 1;
    if once(SubpacketType::SIGNATURE_CREATION_TIME) {
        same(
            "a signature's creation time",
            Some(ours.creation_time()),
            theirs.created().map(|time| time.as_secs()),
        )?;
    }
    // A zero expiration is none (RFC 9580 §5.2.3.18, §5.2.3.13).
    let expiration = |duration: Option<pgp::types::Duration>| {
        duration
            .map(|duration| duration.as_secs())
            .filter(|&seconds| seconds != 0)
    };
    if once(SubpacketType::SIGNATURE_EXPIRATION_TIME) {
        same(
            "a signature's expiration time",
            ours.expiration_time(),
            expiration(theirs.signature_expiration_time()),
        )?;
    }
    if once(SubpacketType::KEY_EXPIRATION_TIME) {
        same(
            "a key expiration time",
            ours.key_expiration_time(),
            expiration(theirs.key_expiration_time()),
        )?;
    }
    if once(SubpacketType::KEY_FLAGS) {
        let flags = ours.key_flags().expect("the subpacket is there");
        let theirs = theirs.key_flags();
        same(
            "key flags (sign, certify)",
            (flags.may_sign(), flags.may_certify()),
            (theirs.sign(), theirs.certify()),
        )?;
    }
    if once(SubpacketType::PRIMARY_USER_ID) {
        same(
            "the primary user ID flag",
            ours.is_primary_user_id(),
            theirs.is_primary(),
        )?;
    }
    if once(SubpacketType::REASON_FOR_REVOCATION) {
        same(
            "a revocation reason",
            ours.revocation_reason()
                .map(|reason| reason.code().number()),
            theirs.revocation_reason_code().map(|&code| u8::from(code)),
        )?;
    }
    same_material(
        ours.material(),
        theirs.signature(),
        ours.public_key_algorithm(),
    )
}

/// Checks that the two read the same signature material, of a signature
/// naming `algorithm`.
fn same_material(
    ours: SignatureMaterial<'_>,
    theirs: Option<&SignatureBytes>,
    algorithm: PublicKeyAlgorithm,
) -> Result<(), Disagreement> {
    match (ours, theirs) {
        // rPGP keeps the material of RSA's encrypt-only variant, which does
        // not sign, as raw octets; irongall reads it as RSA's. Neither
        // verifies it.
        (SignatureMaterial::Rsa(_), Some(SignatureBytes::Native(_)))
            if algorithm == PublicKeyAlgorithm::RSA_ENCRYPT_ONLY =>
        {
            Ok(())
        }
        (SignatureMaterial::Rsa(value), Some(SignatureBytes::Mpis(mpis))) => same(
            "an RSA signature",
            vec![value],
            mpis.iter().map(AsRef::as_ref).collect(),
        ),
        (SignatureMaterial::Ed25519(encoding), Some(SignatureBytes::Mpis(mpis))) => {
            // EdDSALegacy carries R and S as integers, which irongall pads
            // back to their 32-octet encodings.
            let mut padded = Vec::new();
            for mpi in mpis {
                let value: &[u8] = mpi.as_ref();
                padded.push(
                    [
                        vec![0; 32_usize.saturating_sub(value.len())],
                        value.to_vec(),
                    ]
                    .concat(),
                );
            }
            same(
                "an EdDSALegacy signature",
                vec![encoding[..32].to_vec(), encoding[32..].to_vec()],
                padded,
            )
        }
        (SignatureMaterial::Ed25519(encoding), Some(SignatureBytes::Native(native))) => {
            same("an Ed25519 signature", &encoding[..], &native[..])
        }
        (SignatureMaterial::Opaque, _) => Ok(()),
        (ours, theirs) => Err(Disagreement(format!(
            "a signature's material: irongall reads {ours:?}, rPGP {theirs:?}"
        ))),
    }
}

/// What a signature is over, as both are given it: a [`Subject`] whose keys
/// and user ID are the ones both read.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Over<'a> {
    Document(&'a [u8]),
    Key(&'a Key),
    UserId { key: &'a Key, user_id: &'a UserId },
    Subkey { primary: &'a Key, subkey: &'a Key },
}

impl<'a> Over<'a> {
    /// The subject as irongall is given it.
    fn subject(self) -> Subject<'a> {
        match self {
            Over::Document(document) => Subject::Document(document),
            Over::Key(key) => Subject::Key(&key.irongall),
            Over::UserId { key, user_id } => Subject::UserId {
                key: &key.irongall,
                user_id: &user_id.value,
            },
            Over::Subkey { primary, subkey } => Subject::Subkey {
                primary: &primary.irongall,
                subkey: &subkey.irongall,
            },
        }
    }

    /// The keys the subject holds, which a signature's hash frames.
    fn keys(self) -> Vec<&'a Key> {
        match self {
            Over::Document(_) => Vec::new(),
            Over::Key(key) | Over::UserId { key, .. } => vec![key],
            Over::Subkey { primary, subkey } => vec![primary, subkey],
        }
    }
}

/// A rule one of the two implementations keeps and the other does not, and
/// so a reason their verdicts on a signature differ, or a reason only one of
/// them reads a packet.
///
/// Of the verdicts, the first six are irongall refusing what rPGP verifies;
/// framing and encoding, the next two, go either way; and the three after
/// are rPGP refusing what irongall verifies. Of the readings, the first
/// ten are irongall refusing to frame or read what rPGP reads, and the
/// last seven the other way round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Divergence {
    /// The signature names a public-key algorithm other than its key's.
    /// rPGP verifies with the key's material whatever the signature names,
    /// so an RSA signature naming RSA's sign-only variant verifies with an
    /// RSA key.
    AlgorithmMismatch,
    /// The key is of an algorithm irongall does not verify with: DSA, ECDSA,
    /// Ed448, EdDSALegacy over another curve, or RSA's encrypt-only variant.
    UnsupportedAlgorithm,
    /// The signature's hash is one irongall does not implement: MD5 or
    /// RIPEMD-160.
    UnsupportedHash,
    /// The key's RSA modulus is narrower than 2048 bits, which RFC 9580
    /// §12.4 forbids verifying with.
    ShortModulus,
    /// The key is not a valid key: an RSA modulus that is even or an RSA
    /// exponent that is even or below 3, or an Ed25519 point that is encoded
    /// non-canonically or of small order. A small-order Ed25519 key verifies
    /// a signature over any document under rPGP.
    InvalidKey,
    /// The Ed25519 signature's R is a point of small order, which irongall
    /// refuses as libsodium does.
    SmallOrderR,
    /// The subject holds a key of a version other than the signature's.
    /// irongall frames a key in a signature's hash by the signature's
    /// version, as RFC 9580 §5.2.4 says; rPGP frames it by the key's.
    FramedBySignatureVersion,
    /// rPGP encodes what it read as other octets: a key the subject holds,
    /// whose MPIs carry leading zeros or whose material rPGP does not read,
    /// or the signature's hashed subpacket area. It hashes its own encoding;
    /// irongall hashes the octets as they are (RFC 9580 §5.2.4).
    Reencoded,
    /// The signature names issuers, and its key is none of them. rPGP
    /// refuses it; irongall's verification is cryptographic, and issuers only
    /// choose which keys a keyring tries.
    IssuerNamesAnotherKey,
    /// A certification revocation over a key alone, which RFC 9580
    /// §5.2.1.13 allows for revoking a direct-key signature, and rPGP does
    /// not verify.
    RevocationOverKey,
    /// A text signature over a document that GnuPG reads otherwise: with
    /// CRs before a line's CR LF, or at the document's end. irongall also
    /// verifies it over the document as GnuPG reads it, without those CRs;
    /// rPGP keeps them.
    GnuPgLineEndings,
    /// The packet is a key or a signature of a version other than 4 or 6, or
    /// a signature embeds one. irongall reads those two versions alone; rPGP
    /// reads others.
    OtherVersion,
    /// The signature, or one it embeds, has no creation time in its hashed
    /// area, which RFC 9580 §5.2.3.11 requires. rPGP reads it.
    NoCreationTime,
    /// A subpacket of a type irongall decodes is not of the type's form, such
    /// as a Primary User ID whose Boolean is neither 0 nor 1, or one of a
    /// type it keeps without decoding is not of the length RFC 9580 gives
    /// the type. irongall refuses its signature; rPGP reads what it can.
    MalformedSubpacket,
    /// A hashed subpacket is marked critical, and is of a type irongall does
    /// not honor (RFC 9580 §5.2.3.7). irongall refuses its signature; rPGP
    /// reads it.
    CriticalSubpacket,
    /// An MPI's length is not its value's: it counts fewer bits than the
    /// value has, or, in version 6, more (RFC 9580 §3.2). rPGP reads the
    /// octets the length gives.
    MpiLength,
    /// Octets follow a key's or a signature's material. irongall refuses
    /// them; rPGP passes over them.
    TrailingMaterial,
    /// A version 6 key's count of its material is not the material's length
    /// (RFC 9580 §5.5.2.3). rPGP reads the material its algorithm gives.
    MaterialCount,
    /// A packet's header gives a length that streams it: a partial body
    /// length, or the legacy format's indeterminate length. RFC 9580 permits
    /// them for data packets alone, which irongall does not read, so it
    /// refuses to frame any packet so headed; rPGP frames it.
    StreamedLength,
    /// A signature names RSA's encrypt-only algorithm (2), which signs
    /// nothing, and its material is not one MPI. irongall reads the material
    /// as an RSA signature's, and refuses it; rPGP keeps it as octets.
    EncryptOnlyMaterial,
    /// A packet's header names type 0, which RFC 9580 §5 reserves: no packet
    /// is of it. irongall refuses to frame it; rPGP frames it as a packet of
    /// a type it does not know.
    ReservedType,
    /// A subpacket of a type irongall keeps as it is, without decoding it,
    /// is of the type's length but not of its form: a Revocation Key whose
    /// class lacks the bit every class sets, or text that is not UTF-8.
    /// rPGP decodes the type, and refuses the signature.
    UndecodedSubpacket,
    /// A signature embedded in another embeds one in turn. irongall reads
    /// one level of embedding and keeps a deeper one as it is; rPGP refuses
    /// it.
    NestedEmbeddedSignature,
    /// A signature embeds one of a type other than a primary key binding
    /// (0x19). irongall reads it, and a back-signature of another type gives
    /// no consent; rPGP refuses it.
    EmbeddedSignatureType,
    /// The key or signature is of an algorithm whose material irongall does
    /// not read, and verifies nothing with. rPGP reads the material, and
    /// refuses what does not read.
    OpaqueMaterial,
    /// An Ed25519 key's point is not a point of the curve. irongall reads
    /// the key, and refuses to verify with it as an invalid key; rPGP
    /// refuses to read it.
    PointOffCurve,
    /// An RSA key is not one RSA verifies with: its modulus is even or wider
    /// than 8192 bits, or its exponent is even, below 3, above 2^33 - 1, or
    /// not below the modulus. irongall reads the key, and refuses to verify
    /// with it; rPGP refuses to read it.
    InvalidRsaKey,
    /// A signature embeds one with an MPI written with a leading zero octet,
    /// as RFC 9580 §3.2 lets a version 4 MPI be. irongall reads it; rPGP
    /// writes the MPI without the zero, finds the embedded signature no
    /// longer the length of the subpacket that holds it, and refuses the
    /// signature.
    ReencodedEmbeddedSignature,
}

/// What the two made of one signature over one subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Verdict {
    /// Both verified it.
    Verified,
    /// Both refused it.
    Refused,
    /// One verified it and the other refused it, for the reason named.
    Diverged(Divergence),
}

/// Verifies `signature` with `signer` over `over` with both, and compares the
/// verdicts.
///
/// `None` when the two cannot be compared: the signature's type is not made
/// over a subject of this kind, or it is a binding and `signer` is not the
/// key that makes it, which rPGP has no way to check.
///
/// # Errors
///
/// When the verdicts differ for no reason [`Divergence`] lists.
pub(crate) fn verify(
    signature: &Signature,
    signer: &Key,
    over: Over<'_>,
) -> Result<Option<Verdict>, Disagreement> {
    // rPGP checks a binding only with the key that makes it: the primary key
    // a subkey binding or revocation, the subkey a primary key binding.
    if let Over::Subkey { primary, subkey } = over {
        let maker = match signature.irongall.signature_type() {
            SignatureType::PRIMARY_KEY_BINDING => subkey,
            _ => primary,
        };
        if signer.irongall != maker.irongall {
            return Ok(None);
        }
    }
    let ours = signature.irongall.verify(&signer.irongall, over.subject());
    if let Err(VerifyError::WrongSubject | VerifyError::UnsupportedType) = ours {
        return Ok(None);
    }
    let theirs = rpgp_verify(signature, signer, over);
    let divergence = match (ours, theirs) {
        (Ok(()), Ok(())) => return Ok(Some(Verdict::Verified)),
        (Err(_), Err(_)) => return Ok(Some(Verdict::Refused)),
        (Err(error), Ok(())) => refused(error, signature, signer, over),
        (Ok(()), Err(_)) => verified(signature, signer, over),
    };
    match divergence {
        Ok(divergence) => Ok(Some(Verdict::Diverged(divergence))),
        Err(theirs) => Err(Disagreement(format!(
            "{} over {over:?} by {signer:?}: {theirs}\n{signature:?}",
            match ours {
                Ok(()) => "irongall verifies and rPGP refuses a signature".to_string(),
                Err(error) => format!("irongall refuses ({error}) and rPGP verifies a signature"),
            }
        ))),
    }
}

/// rPGP's verdict on `signature` by `signer` over `over`, through the call
/// rPGP has for a subject of that kind and a signature of that type.
fn rpgp_verify(signature: &Signature, signer: &Key, over: Over<'_>) -> pgp::errors::Result<()> {
    let theirs = &signature.rpgp;
    let key = &signer.rpgp;
    match over {
        Over::Document(document) => theirs.verify(key, document),
        Over::Key(subject) => theirs.verify_key_third_party(&subject.rpgp, key),
        Over::UserId {
            key: subject,
            user_id,
        } => theirs.verify_third_party_certification(
            &subject.rpgp,
            key,
            RpgpTag::UserId,
            &user_id.rpgp,
        ),
        Over::Subkey { primary, subkey } => match signature.irongall.signature_type() {
            SignatureType::PRIMARY_KEY_BINDING => {
                theirs.verify_primary_key_binding(key, &primary.rpgp)
            }
            _ => theirs.verify_subkey_binding(key, &subkey.rpgp),
        },
    }
}

/// Why irongall refused, with `error`, a signature rPGP verifies; an error
/// describing the input when no divergence explains it.
///
/// irongall's error says which of its rules refused; the divergence is
/// accepted only when the input shows that rule applies, read from rPGP's
/// side where the input holds the answer.
fn refused(
    error: VerifyError,
    signature: &Signature,
    signer: &Key,
    over: Over<'_>,
) -> Result<Divergence, String> {
    let config = signature.rpgp.config().expect("rPGP verified it");
    let key = &signer.rpgp;
    let explained = match error {
        VerifyError::AlgorithmMismatch => (u8::from(config.pub_alg) != u8::from(key.algorithm()))
            .then_some(Divergence::AlgorithmMismatch),
        VerifyError::UnsupportedAlgorithm => {
            (!verifies_with(key)).then_some(Divergence::UnsupportedAlgorithm)
        }
        VerifyError::UnsupportedHash => {
            (!implemented(u8::from(config.hash_alg))).then_some(Divergence::UnsupportedHash)
        }
        VerifyError::ModulusTooShort => rsa(key)
            .is_some_and(|(modulus, _)| bit_length(&modulus) < 2048)
            .then_some(Divergence::ShortModulus),
        VerifyError::InvalidKey => {
            let invalid = match (rsa(key), ed25519(key)) {
                (Some((modulus, exponent)), _) => {
                    // An even exponent covers 0 and 2.
                    even(&modulus) || even(&exponent) || exponent == [1]
                }
                (_, Some(point)) => non_canonical(&point) || small_order(&point),
                _ => false,
            };
            invalid.then_some(Divergence::InvalidKey)
        }
        VerifyError::BadSignature | VerifyError::HashPrefixMismatch => {
            if framed_differently(signature, over) {
                Some(Divergence::FramedBySignatureVersion)
            } else if reencoded_subject(signature, over) {
                Some(Divergence::Reencoded)
            } else if let (VerifyError::BadSignature, Some(_), SignatureMaterial::Ed25519(rs)) =
                (error, ed25519(key), signature.irongall.material())
            {
                small_order(rs[..32].try_into().expect("R is 32 octets"))
                    .then_some(Divergence::SmallOrderR)
            } else {
                None
            }
        }
        _ => None,
    };
    explained.ok_or_else(|| "no divergence explains it".to_string())
}

/// Why rPGP refused a signature irongall verifies; an error when no
/// divergence explains it.
fn verified(signature: &Signature, signer: &Key, over: Over<'_>) -> Result<Divergence, String> {
    let ours = &signature.irongall;
    // rPGP matches issuers when verifying over a document, a user ID, or a
    // key, and not when verifying a binding.
    let matches_issuers = matches!(over, Over::Document(_) | Over::UserId { .. } | Over::Key(_));
    let key = &signer.irongall;
    let mut key_ids = ours.issuer_key_ids().peekable();
    let mut fingerprints = ours.issuer_fingerprints().peekable();
    let named = key_ids.peek().is_some() || fingerprints.peek().is_some();
    let names_signer = key_ids.any(|key_id| key_id == key.key_id())
        || fingerprints.any(|fingerprint| fingerprint == key.fingerprint());
    if matches_issuers && named && !names_signer {
        Ok(Divergence::IssuerNamesAnotherKey)
    } else if ours.signature_type() == SignatureType::CERTIFICATION_REVOCATION
        && matches!(over, Over::Key(_))
    {
        Ok(Divergence::RevocationOverKey)
    } else if framed_differently(signature, over) {
        Ok(Divergence::FramedBySignatureVersion)
    } else if reencoded_subject(signature, over) {
        Ok(Divergence::Reencoded)
    } else if ours.signature_type() == SignatureType::TEXT
        && matches!(over, Over::Document(document) if read_otherwise_by_gnupg(document))
    {
        Ok(Divergence::GnuPgLineEndings)
    } else {
        Err("no divergence explains it".to_string())
    }
}

/// Whether GnuPG reads the line endings of `document` otherwise than rPGP
/// does: it has a run of two or more CRs before an LF, or ends in a CR.
fn read_otherwise_by_gnupg(document: &[u8]) -> bool {
    document.ends_with(b"\r") || document.windows(3).any(|window| window == b"\r\r\n")
}

/// Whether the subject holds a key of a version other than the signature's.
fn framed_differently(signature: &Signature, over: Over<'_>) -> bool {
    let version = signature.irongall.version();
    over.keys()
        .iter()
        .any(|key| key.irongall.version() != version)
}

/// Whether rPGP hashes its own encoding of something the signature's hash
/// covers: the hashed subpacket area, or a key the subject holds.
fn reencoded_subject(signature: &Signature, over: Over<'_>) -> bool {
    signature.reencoded || over.keys().iter().any(|key| key.reencoded)
}

/// Whether irongall verifies with a key of this algorithm, read from rPGP's
/// side.
fn verifies_with(key: &pgp::packet::PublicKey) -> bool {
    let algorithm = u8::from(key.algorithm());
    match key.public_params() {
        PublicParams::RSA(_) => {
            algorithm == PublicKeyAlgorithm::RSA.number()
                || algorithm == PublicKeyAlgorithm::RSA_SIGN_ONLY.number()
        }
        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { .. }) => {
            key.version() == pgp::types::KeyVersion::V4
        }
        PublicParams::Ed25519(_) => true,
        _ => false,
    }
}

/// Whether irongall implements the hash algorithm numbered `number`: SHA-1,
/// and the SHA-2 and SHA-3 functions.
fn implemented(number: u8) -> bool {
    matches!(number, 2 | 8 | 9 | 10 | 11 | 12 | 14)
}

/// An RSA key's modulus and exponent, big-endian without leading zeros.
fn rsa(key: &pgp::packet::PublicKey) -> Option<(Vec<u8>, Vec<u8>)> {
    match key.public_params() {
        PublicParams::RSA(params) => {
            Some((params.key.n().to_bytes_be(), params.key.e().to_bytes_be()))
        }
        _ => None,
    }
}

/// An Ed25519 key's encoding, of either algorithm.
fn ed25519(key: &pgp::packet::PublicKey) -> Option<[u8; 32]> {
    match key.public_params() {
        PublicParams::Ed25519(params) => Some(*params.key.as_bytes()),
        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { key }) => {
            Some(*key.as_bytes())
        }
        _ => None,
    }
}

/// The number of bits in a big-endian integer without leading zeros.
fn bit_length(value: &[u8]) -> usize {
    value
        .first()
        .map_or(0, |&top| value.len() * 8 - top.leading_zeros() as usize)
}

/// Whether a big-endian integer is even.
fn even(value: &[u8]) -> bool {
    value.last().is_none_or(|&low| low & 1 == 0)
}

/// Whether an Ed25519 point's encoding is non-canonical: its y coordinate,
/// the low 255 bits, little-endian, is p = 2^255 - 19 or more.
fn non_canonical(encoding: &[u8; 32]) -> bool {
    encoding[0] >= 0xED
        && encoding[1..31].iter().all(|&byte| byte == 0xFF)
        && encoding[31] & 0x7F == 0x7F
}

/// Whether an encoding names a point of small order: one whose order
/// divides 8.
fn small_order(encoding: &[u8; 32]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(encoding).is_ok_and(|point| point.is_weak())
}
