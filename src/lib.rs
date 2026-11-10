//! OpenPGP signature verification in safe Rust.
//!
//! irongall is in early development. Its scope is version 4 and version 6
//! OpenPGP signatures, as specified by [RFC 9580], over cleartext-signed
//! documents and detached data, checked against certificates read from a
//! keyring, with no dependencies and no `unsafe` code. It judges what a
//! signature is worth as well as whether it verifies: which algorithms are
//! trusted, whether the signing key was in force when it signed, and whether
//! a subkey was ever granted the authority to sign.
//!
//! Verifying a Debian `InRelease` file against the archive's keyring:
//!
//! ```no_run
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! use irongall::keyring::Keyring;
//! use irongall::policy::Policy;
//! use irongall::{cert, document};
//!
//! let keyring = std::fs::read("/usr/share/keyrings/debian-archive-keyring.gpg")?;
//! let keyring: Keyring = cert::certificates(&keyring).collect::<Result<_, _>>()?;
//! let release = std::fs::read("InRelease")?;
//! let release = document::cleartext(&release)?;
//!
//! let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
//! let verified = keyring.verify(&Policy::new(), now, release.signatures(), release.text())?;
//! println!("signed by {}", verified.key().fingerprint());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The layers, each usable without the ones above it:
//!
//! - [`armor`] decodes ASCII-armored data.
//! - [`packet`] reads the packets OpenPGP data is made of.
//! - [`key`] reads public keys from their packets, and computes the
//!   fingerprints and key IDs that name them.
//! - [`signature`] reads signature packets and their subpackets, and verifies
//!   a signature with a key.
//! - [`cert`] assembles certificates from the packets of a keyring.
//! - [`document`] reads cleartext signed messages and detached signatures.
//! - [`policy`] judges what a certificate grants its keys, and what a
//!   signature that verifies is worth.
//! - [`keyring`] verifies a document's signatures against the certificates a
//!   caller trusts, under a policy.
//! - [`hash`] holds the hash functions OpenPGP is defined over.
//! - [`rsa`] verifies an RSA signature over a digest, as OpenPGP's RSA keys
//!   sign, for any format that signs the same way.
//!
//! The crate is `no_std` and needs only an allocator.
//!
//! # Conformance
//!
//! irongall verifies as RFC 9580 specifies, and refuses what the RFC permits
//! a reader to accept but does not require. Where it reads or judges
//! differently from the RFC's text or from GnuPG, it does so on purpose:
//!
//! - **Ed25519** signatures are held to libsodium's rules: S below the
//!   group order, the key and R encoded canonically and neither of small
//!   order, and the cofactorless equation. RFC 8032 accepts points of small
//!   order, and under a key of small order a fixed signature verifies over
//!   any document.
//! - **RSA** keys verify from 2048 bits, the floor RFC 9580 §12.4 sets, to
//!   8192, with an odd public exponent from 3 to 2^33 - 1.
//! - **Critical subpackets** refuse their signature unless irongall
//!   implements them or their meaning cannot change a verification
//!   (§5.2.3.7). The [`signature`] module lists them.
//! - **Malformed subpackets** of the types irongall reads refuse their
//!   signature, among them a Primary User ID whose Boolean is neither 0
//!   nor 1. A certificate's signature refused for one, or for a critical
//!   subpacket, grants nothing, as §5.2.5 requires, and still restricts what
//!   the certificate grants, as the [`policy`] module sets out. Were it
//!   passed over, anyone who handles a certificate could make a revocation
//!   go unread by damaging a subpacket in its unhashed area, which no
//!   signature covers.
//! - **`Hash` armor headers** must be well formed, and their names are not
//!   checked against the signatures, as §6.2.2.3 requires. GnuPG checks
//!   them.
//! - **Text signatures** hash a document with its line endings made CR LF
//!   (§5.2.1.2), where a line ends at a line feed, with or without a
//!   carriage return before it. A text signature verifies with any other
//!   carriage return kept, as OpenPGP.js and rPGP hash a text, or with those
//!   before a line ending or at the end of the text dropped, as GnuPG and
//!   RNP do. Sequoia and Bouncy Castle also end a line at a lone carriage
//!   return, and a text signature they make over a text that has one does
//!   not verify: read that way, a line feed could be replaced by a carriage
//!   return and the signature still hold.
//! - **Cleartext signed messages** are read as GnuPG reads them: each line
//!   loses its trailing carriage returns with the trailing spaces and tabs
//!   §7.2 names. A line beginning with a dash must be dash-escaped, and
//!   only blank lines may come before or after the message, where GnuPG
//!   keeps such a line as it is and skips text around the message.
//! - **Armor** must be laid out as §6.2 gives it, with only blank lines
//!   between blocks. A block without armor headers may lack the blank line
//!   before its data, as GnuPG, Sequoia, and RNP allow. GnuPG also allows a
//!   block with headers to lack it, and skips text around blocks.
//! - **Key flags** must grant a key the right to sign: a key whose
//!   self-signatures in force state none signs nothing (§5.2.3.29). GnuPG
//!   infers what such a key may do from its algorithm, and accepts its
//!   signatures; Sequoia, like irongall, does not.
//! - **Every user ID** in force restricts its primary key, not the primary
//!   user ID alone: the key lapses at the earliest expiration their
//!   self-signatures state, and signs only if every one of them that states
//!   key flags grants signing. RFC 9580 applies a certification's
//!   subpackets to its user ID (§5.2.3.10), and Sequoia takes a key's
//!   expiration and flags from its direct-key signature or its primary user
//!   ID alone. GnuPG and Sequoia re-sign every user ID in force when they
//!   change a key's expiration, so the user IDs agree, and where they do
//!   not, the narrowest holds.
//! - **Signatures out of place** in a certificate count over the part they
//!   are made over. RFC 9580 §10.1 places a certification after the user ID
//!   it certifies, and a subkey's binding or revocation after the subkey, but
//!   no signature covers the order of a certificate's packets, so placement
//!   does not decide what a signature is over. irongall tries such
//!   a signature over the certificate's other parts, as Sequoia does, within
//!   a bound the certificate's size sets, and a certificate that needs more
//!   grants nothing.
//! - **Old SHA-1 self-signatures**, made over a primary key before
//!   1 February 2023, grant what they state, though a policy refuses SHA-1
//!   elsewhere. RFC 9580 §9.5 forbids validating a recent signature that
//!   depends on SHA-1, and discourages validating an old one; GnuPG
//!   validates both. Many keys in use, archive signing keys among them, were
//!   self-signed over SHA-1 alone before that date. A governing
//!   self-signature made since must rest on a hash the policy accepts, or
//!   it refuses its certificate, as a governing subkey binding over such a
//!   hash refuses its subkey. A certification revocation is held to the same
//!   date, since withdrawing a self-signature can lift a restriction. What
//!   the exception risks, a chosen-prefix collision, the [`policy`] module
//!   sets out.
//! - **Ed25519 signatures over a short hash**, one under 256 bits, never
//!   verify, as RFC 9580 §5.2.3.3 and §5.2.3.4 require; GnuPG makes and
//!   verifies them. A certificate's own statement made so is still its
//!   key's, so it restricts and grants nothing: a revocation revokes, as in
//!   GnuPG, and a self-signature or binding that governs refuses its
//!   certificate or subkey.
//! - **MD5 and RIPEMD-160** are not implemented, so a signature over either
//!   verifies nothing, and a certificate's revocation made over either is
//!   passed over: which key made it cannot be established. RFC 9580 forbids
//!   making a signature over either (§9.5).
//! - **Postdated signatures**, dated later than the time of judgement and
//!   the policy's [clock skew](policy::Policy::clock_skew), are refused.
//!   GnuPG accepts them.
//! - **Expired keys** verify nothing once their authority has lapsed, not
//!   even a signature dated within it, since a signature's date is its
//!   signer's claim. GnuPG reports such a signature as made by an expired
//!   key (`EXPKEYSIG`) but still good, and apt refuses it; Sequoia accepts
//!   it, judging the key as of the signature's date. A document pinned in
//!   the past is judged as of the time it was published.
//! - **Revocations** a certificate's primary key makes are final, whatever
//!   their reason. §5.2.3.31 keeps a signature made before a key was
//!   superseded or retired valid, and irongall does not. Revocations by a
//!   designated revoker are not honored.
//!
//! The [`policy`] module sets out how a certificate and a signature are
//! judged, and the [`document`] module how signed documents are read.
//!
//! [RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580

#![no_std]
// Reading hostile bytes is this crate's job, so a panic in library code is a
// decision made where the code is written rather than a finding a fuzzer
// reports later. Each lint below names a way to panic, or to compute a wrong
// length silently; a site that genuinely cannot fail and is clearer written
// directly carries `#[expect(..., reason = "...")]` on the smallest item that
// holds it, with the reason stating the invariant. A type whose arithmetic
// operators are total, such as a field element, is instead exempted from
// `arithmetic_side_effects` by name in `clippy.toml`, since the invariant is
// the type's and not the call site's; the integer arithmetic inside its
// operators carries the `expect`. Tests are exempt: there a panic is how a
// check fails.
#![cfg_attr(
    not(test),
    deny(
        clippy::alloc_instead_of_core,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::std_instead_of_alloc,
        clippy::std_instead_of_core,
        clippy::string_slice,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::unwrap_used,
    )
)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod armor;
mod base64;
mod bignum;
pub mod cert;
pub mod document;
mod ed25519;
pub mod hash;
pub mod key;
pub mod keyring;
pub mod packet;
pub mod policy;
pub mod rsa;
pub mod signature;
mod wire;

#[cfg(test)]
mod test_support;

/// The README's example, compiled with the documentation tests so that it
/// keeps to the API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeExample;
