//! Tests for signed documents: the text of a cleartext signed message as
//! GnuPG reads it, the framing and headers refused around it, and the
//! signatures kept and passed over in it and in detached signature files.

use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::{DocumentError, cleartext, detached};
use crate::armor::{self, ArmorErrorKind};
use crate::cert;
use crate::packet::{PacketErrorKind, Tag};
use crate::signature::{SignatureType, Subject, VerifyError};
use crate::test_support::rfc9580::{A3_CERTIFICATE, A6_SIGNATURE, A6_TEXT};
use crate::test_support::vector_bytes;

/// An armored signature block holding `data`.
fn signature_block(data: &[u8]) -> String {
    let encoded = STANDARD.encode(data);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| core::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "-----BEGIN PGP SIGNATURE-----\n\n{}\n-----END PGP SIGNATURE-----\n",
        lines.join("\n")
    )
}

/// A cleartext signed message with armor headers `headers`, each line
/// already ended, the text lines `body`, and a signature block holding
/// `data`.
fn message(headers: &str, body: &[u8], data: &[u8]) -> Vec<u8> {
    [
        b"-----BEGIN PGP SIGNED MESSAGE-----\n",
        headers.as_bytes(),
        b"\n",
        body,
        b"\n",
        signature_block(data).as_bytes(),
    ]
    .concat()
}

/// The signature packets of GnuPG's text signature over `document.txt`.
fn gnupg_text_signature() -> Vec<u8> {
    vector_bytes("gnupg/text.sig")
}

/// The kind and line `input` fails to read with, as a cleartext signed
/// message.
fn armor_failure(input: &[u8]) -> (ArmorErrorKind, usize) {
    match cleartext(input) {
        Err(DocumentError::Armor(error)) => (error.kind(), error.line()),
        other => panic!("expected an armor failure, got {other:?}"),
    }
}

/// RFC 9580 Appendix A.6: the dash-escaped text, read as its signature is
/// made over it, verified with the primary key of A.3.
#[test]
fn rfc_9580_a6() {
    let input = format!(
        "-----BEGIN PGP SIGNED MESSAGE-----\n\nWhat we need from the grocery store:\n\n\
         - - tofu\n- - vegetables\n- - noodles\n\n{A6_SIGNATURE}"
    );
    let message = cleartext(input.as_bytes()).unwrap();
    assert_eq!(message.text(), A6_TEXT.as_bytes());
    assert_eq!(message.skipped(), []);
    let [signature] = message.signatures() else {
        panic!("one signature");
    };
    let data = armor::decode(A3_CERTIFICATE.as_bytes())
        .unwrap()
        .into_data();
    let certificate = cert::certificates(&data).next().unwrap().unwrap();
    assert_eq!(
        signature.verify(certificate.primary(), Subject::Document(message.text())),
        Ok(())
    );
}

/// GnuPG's text signature over `document.txt`, wrapped in a cleartext signed
/// message whose text is the document's: the text verifies, and the same
/// signature wrapped around another text does not.
#[test]
fn a_gnupg_text_signature_verifies_over_the_text() {
    let data = vector_bytes("gnupg/ed25519-signing.pgp");
    let certificate = cert::certificates(&data).next().unwrap().unwrap();
    let key = certificate.subkeys()[0].key();
    let signature = gnupg_text_signature();
    // The document ends with a line feed, so its last line is empty.
    for body in [
        &b"irongall test document\nsecond line\n"[..],
        b"irongall test document  \r\n- second line\t\r\n",
    ] {
        let message = cleartext(&message("Hash: SHA512\n", body, &signature)).unwrap();
        assert_eq!(
            message.text(),
            b"irongall test document\r\nsecond line\r\n",
            "{body:?}"
        );
        let [signature] = message.signatures() else {
            panic!("one signature");
        };
        assert_eq!(
            signature.verify(key, Subject::Document(message.text())),
            Ok(())
        );
    }
    let other = cleartext(&message(
        "",
        b"irongall test document\nsecond line",
        &signature,
    ))
    .unwrap();
    assert_eq!(
        other.signatures()[0].verify(key, Subject::Document(other.text())),
        Err(VerifyError::HashPrefixMismatch)
    );
}

/// The text of each body, read as GnuPG 2.4.4 reads it. Each case was
/// measured by wrapping a GnuPG detached text signature over the expected
/// text around the body, and asking GnuPG to verify the message.
#[test]
fn the_text_is_read_as_gnupg_reads_it() {
    for (body, text) in [
        (&b"foo\nbar"[..], &b"foo\r\nbar"[..]),
        (b"foo \t\nbar\t ", b"foo\r\nbar"),
        (b"foo\r\nbar\r", b"foo\r\nbar"),
        (b"foo\r\r\nbar", b"foo\r\nbar"),
        (b"foo \r\nbar", b"foo\r\nbar"),
        (b"foo\r \nbar", b"foo\r\nbar"),
        (b"foo\rbar\nbaz", b"foo\rbar\r\nbaz"),
        (b"foo\x0c\nbar", b"foo\x0c\r\nbar"),
        (b"foo\x0b\nbar", b"foo\x0b\r\nbar"),
        (b"foo\n\n", b"foo\r\n\r\n"),
        (b"foo\n", b"foo\r\n"),
        (b"", b""),
        (b"- -foo\nbar", b"-foo\r\nbar"),
        (b"- foo\nbar", b"foo\r\nbar"),
        (b"- -foo  \nbar", b"-foo\r\nbar"),
        (b"- \nbar", b"\r\nbar"),
        (b"- - foo\nbar", b"- foo\r\nbar"),
        (
            b"- -----BEGIN PGP SIGNATURE-----",
            b"-----BEGIN PGP SIGNATURE-----",
        ),
    ] {
        let message = cleartext(&message("", body, &[])).unwrap();
        assert_eq!(message.text(), text, "{body:?}");
    }

    // An empty text needs no line at all.
    let input = format!(
        "-----BEGIN PGP SIGNED MESSAGE-----\n\n{}",
        signature_block(&[])
    );
    assert_eq!(cleartext(input.as_bytes()).unwrap().text(), b"");
}

/// A line that begins with a dash must be dash-escaped, unless it opens the
/// signature block. GnuPG keeps such a line as it is, apart from one that
/// begins with five dashes, which it refuses.
#[test]
fn a_dash_must_be_escaped() {
    for line in [
        &b"-"[..],
        b"-x",
        b"-\t",
        b"--",
        b"-----x",
        b"-----BEGIN PGP SIGNED MESSAGE-----",
        b"-----BEGIN PGP SIGNATURE----- x",
        b"-----BEGIN PGP MESSAGE-----",
        b"-----END PGP SIGNATURE-----",
    ] {
        let body = [&b"foo\n"[..], line, b"\nbar"].concat();
        assert_eq!(
            armor_failure(&message("", &body, &[])),
            (ArmorErrorKind::NotDashEscaped, 4),
            "{line:?}"
        );
    }
    // Trailing whitespace on the line that opens the signature block is not
    // significant, as on any armor line.
    let input = b"-----BEGIN PGP SIGNED MESSAGE-----\n\nfoo\n-----BEGIN PGP SIGNATURE----- \t\r\n\n-----END PGP SIGNATURE-----\n";
    assert_eq!(cleartext(input).unwrap().text(), b"foo");
}

/// Only `Hash` headers may precede the text, and each must list hash
/// algorithms by the names RFC 9580 Table 23 gives them. Their content is
/// otherwise ignored, so a header naming another algorithm than the
/// signature's refuses nothing.
#[test]
fn only_a_conformant_hash_header_is_allowed() {
    let signature = gnupg_text_signature();
    let body = b"irongall test document\nsecond line\n";
    for headers in [
        "",
        "Hash: SHA512\n",
        "Hash: SHA1\n",
        "Hash: MD5\n",
        "Hash: SHA256,SHA512\n",
        "Hash: SHA256, SHA512\n",
        "Hash:  SHA256 ,\tSHA512 \n",
        "Hash: SHA256\nHash: SHA512\n",
        "Hash: RIPEMD160,SHA224,SHA384,SHA3-256,SHA3-512\n",
    ] {
        let message = cleartext(&message(headers, body, &signature)).unwrap();
        assert_eq!(message.signatures().len(), 1, "{headers:?}");
    }

    for (headers, kind) in [
        ("Hash: sha256\n", ArmorErrorKind::InvalidHashHeader),
        ("Hash: FOO\n", ArmorErrorKind::InvalidHashHeader),
        ("Hash: SHA256,FOO\n", ArmorErrorKind::InvalidHashHeader),
        ("Hash:\n", ArmorErrorKind::InvalidHashHeader),
        ("Hash: SHA256,\n", ArmorErrorKind::InvalidHashHeader),
        ("Hash: ,SHA256\n", ArmorErrorKind::InvalidHashHeader),
        ("Hash: SHA256,,SHA512\n", ArmorErrorKind::InvalidHashHeader),
        ("Hash: SHA256 SHA512\n", ArmorErrorKind::InvalidHashHeader),
        ("Hash: SHA-256\n", ArmorErrorKind::InvalidHashHeader),
        ("Comment: hi\n", ArmorErrorKind::ForbiddenHeader),
        ("Charset: UTF-8\n", ArmorErrorKind::ForbiddenHeader),
        ("hash: SHA256\n", ArmorErrorKind::ForbiddenHeader),
        ("Version: 1\n", ArmorErrorKind::ForbiddenHeader),
        ("Hash:SHA256\n", ArmorErrorKind::InvalidHeader),
        ("NotAHeader\n", ArmorErrorKind::InvalidHeader),
    ] {
        assert_eq!(
            armor_failure(&message(headers, body, &signature)),
            (kind, 2),
            "{headers:?}"
        );
    }
    assert_eq!(
        armor_failure(&message("Hash: SHA256\nComment: hi\n", body, &signature)),
        (ArmorErrorKind::ForbiddenHeader, 3)
    );
}

/// The signature block is an armored block like any other: its headers may
/// be anything well formed, apart from a `Hash` header that is not a list of
/// names.
#[test]
fn the_signature_block_is_armor() {
    let block = signature_block(&gnupg_text_signature());
    let input = |headers: &str| {
        let block = block.replacen("\n\n", &format!("\n{headers}\n"), 1);
        format!("-----BEGIN PGP SIGNED MESSAGE-----\n\nfoo\n{block}")
    };
    let message = cleartext(input("Comment: hi\nHash: SHA512\n").as_bytes()).unwrap();
    assert_eq!(message.signatures().len(), 1);
    assert_eq!(
        armor_failure(input("Comment: hi\nHash: SHA-512\n").as_bytes()),
        (ArmorErrorKind::InvalidHashHeader, 6)
    );
    let truncated = input("").replace("-----END PGP SIGNATURE-----\n", "");
    assert_eq!(
        armor_failure(truncated.as_bytes()).0,
        ArmorErrorKind::MissingTail
    );
}

/// The framing around a cleartext signed message: only blank lines outside
/// it, and its signatures must follow its text.
#[test]
fn malformed_framing_is_refused() {
    // Nine lines: the header line, a blank line, the text, and six lines of
    // signature block.
    let good = message("", b"foo", &gnupg_text_signature());
    assert_eq!(good.iter().filter(|&&octet| octet == b'\n').count(), 9);
    let with = |before: &[u8], after: &[u8]| [before, &good, after].concat();
    assert!(cleartext(&with(b"\n \n", b"\n\n")).is_ok());

    for (input, kind, line) in [
        (with(b"", b"text\n"), ArmorErrorKind::TextOutsideBlock, 10),
        (with(b"text\n", b""), ArmorErrorKind::TextOutsideBlock, 1),
        (with(b"", &good), ArmorErrorKind::ExtraBlock, 10),
        (
            with(b"", b"-----BEGIN PGP SIGNATURE-----\n"),
            ArmorErrorKind::ExtraBlock,
            10,
        ),
        (b"".to_vec(), ArmorErrorKind::NoBlock, 1),
        (b"\n\n".to_vec(), ArmorErrorKind::NoBlock, 3),
        (
            signature_block(&[]).into_bytes(),
            ArmorErrorKind::NotCleartext,
            1,
        ),
        (
            b"-----BEGIN PGP SIGNED MESSAGE-----\n".to_vec(),
            ArmorErrorKind::MissingSignature,
            2,
        ),
        (
            b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n".to_vec(),
            ArmorErrorKind::MissingSignature,
            3,
        ),
        (
            b"-----BEGIN PGP SIGNED MESSAGE-----\n\nfoo\nbar\n".to_vec(),
            ArmorErrorKind::MissingSignature,
            5,
        ),
        (
            b"-----BEGIN PGP SIGNED MESSAGE----- x\n".to_vec(),
            ArmorErrorKind::InvalidHeaderLine,
            1,
        ),
    ] {
        assert_eq!(
            armor_failure(&input),
            (kind, line),
            "{}",
            String::from_utf8_lossy(&input)
        );
    }

    // The armor decoder, given a cleartext signed message, says what it is.
    let error = armor::decode(&good).unwrap_err();
    assert_eq!(error.kind(), ArmorErrorKind::CleartextMessage);
}

/// A version 4 signature packet: GnuPG's text signature with its type and
/// so its meaning changed, which reads but is no longer over the text.
fn retyped(signature_type: u8) -> Vec<u8> {
    let mut data = gnupg_text_signature();
    // A legacy header of one length octet, then the version and the type.
    assert_eq!((data[0] & 0x3C, data[2]), (0x08, 4));
    data[3] = signature_type;
    data
}

/// The packets of a document's signature data: signatures of the wrong type
/// and signatures that do not read are passed over, filler packets are
/// passed over, and anything else refuses the document.
#[test]
fn signature_packets_are_kept_or_passed_over() {
    let text = gnupg_text_signature();
    let critical = vector_bytes("gnupg/critical-notation.sig");
    let binary = vector_bytes("gnupg/binary.sig");
    // A Marker packet (RFC 9580 §5.8), a Padding packet, and a packet of an
    // unknown type that is not critical, each before and after.
    let filler = [
        &[0xCA, 0x03, b'P', b'G', b'P'][..],
        &[0xD5, 0x02, 0, 0],
        &[0xFE, 0x00],
    ]
    .concat();
    let data = [
        &filler[..],
        &text,
        &critical,
        &binary,
        &retyped(0x13),
        &filler,
    ]
    .concat();

    let read = cleartext(&message("", b"foo", &data)).unwrap();
    assert_eq!(read.signatures().len(), 1);
    let skipped: Vec<_> = read.skipped().iter().map(|error| error.kind()).collect();
    assert_eq!(
        skipped,
        [
            PacketErrorKind::CriticalSubpacket,
            PacketErrorKind::MisplacedSignature,
            PacketErrorKind::MisplacedSignature,
        ]
    );
    // The offsets are in the decoded data.
    assert_eq!(
        read.skipped()[1].offset(),
        filler.len() + text.len() + critical.len()
    );

    let signatures = detached(&data).unwrap();
    let types: Vec<_> = signatures
        .signatures()
        .iter()
        .map(|signature| signature.signature_type())
        .collect();
    assert_eq!(types, [SignatureType::TEXT, SignatureType::BINARY]);
    let skipped: Vec<_> = signatures
        .skipped()
        .iter()
        .map(|error| error.kind())
        .collect();
    assert_eq!(
        skipped,
        [
            PacketErrorKind::CriticalSubpacket,
            PacketErrorKind::MisplacedSignature
        ]
    );

    // A User ID packet, a Literal Data packet, since an inline-signed
    // message is not a detached signature, and a Trust packet, which belongs
    // to a keyring.
    for packet in [
        &[0xCD, 0x01, b'x'][..],
        &[0xCB, 0x02, b'b', 0],
        &[0xCC, 0x08, b'a', b'n', b'y', b't', b'h', b'i', b'n', b'g'],
    ] {
        let data = [&text[..], packet].concat();
        let Err(DocumentError::Packet(error)) = detached(&data) else {
            panic!("refused");
        };
        assert_eq!(
            (error.kind(), error.offset()),
            (PacketErrorKind::UnexpectedType, text.len())
        );
        let Err(DocumentError::Packet(error)) = cleartext(&message("", b"foo", &data)) else {
            panic!("refused");
        };
        assert_eq!(error.kind(), PacketErrorKind::UnexpectedType);
    }

    // A framing failure: the signature cut short.
    let cut = &text[..text.len() - 1];
    let Err(DocumentError::Packet(error)) = detached(cut) else {
        panic!("refused");
    };
    assert_eq!(
        (error.kind(), error.tag()),
        (PacketErrorKind::Truncated, Some(Tag::SIGNATURE))
    );
}

/// A detached signature file reads the same armored as binary, whatever its
/// armor label says, and an input that is neither is refused.
#[test]
fn detached_signatures_armored_or_binary() {
    let data = [vector_bytes("gnupg/binary.sig"), gnupg_text_signature()].concat();
    let binary = detached(&data).unwrap();
    assert_eq!(binary.signatures().len(), 2);
    assert_eq!(binary.skipped(), []);

    let armored = signature_block(&data);
    let message_label = armored.replace("PGP SIGNATURE", "PGP MESSAGE");
    for input in [armored.clone(), format!("\n\n{armored}\n"), message_label] {
        assert_eq!(detached(input.as_bytes()).unwrap(), binary, "{input}");
    }

    let document = vector_bytes("gnupg/document.txt");
    let certificate = vector_bytes("gnupg/ed25519-signing.pgp");
    let certificate = cert::certificates(&certificate).next().unwrap().unwrap();
    for signature in binary.signatures() {
        assert_eq!(
            signature.verify(certificate.subkeys()[0].key(), Subject::Document(&document)),
            Ok(())
        );
    }

    for (input, kind) in [
        (&b""[..], ArmorErrorKind::NoBlock),
        (b"\n", ArmorErrorKind::NoBlock),
        (b"text", ArmorErrorKind::TextOutsideBlock),
    ] {
        let Err(DocumentError::Armor(error)) = detached(input) else {
            panic!("refused: {input:?}");
        };
        assert_eq!(error.kind(), kind);
    }
    // A Hash header in a detached signature's armor is held to the same rule
    // as anywhere else.
    let invalid = armored.replacen("\n\n", "\nHash: FOO\n\n", 1);
    let Err(DocumentError::Armor(error)) = detached(invalid.as_bytes()) else {
        panic!("refused");
    };
    assert_eq!(
        (error.kind(), error.line()),
        (ArmorErrorKind::InvalidHashHeader, 2)
    );
}

/// Errors say where they were found, in the armor or in the packets.
#[test]
fn errors_say_where() {
    let error = cleartext(&message("", b"-x", &[])).unwrap_err();
    assert_eq!(
        error.to_string(),
        "armor line 3: a line of signed text that begins with a dash and is not dash-escaped"
    );
    let error = detached(&[0xCD, 0x01, b'x']).unwrap_err();
    assert_eq!(
        error.to_string(),
        "User ID packet, offset 0: not a packet of the type expected"
    );
}
