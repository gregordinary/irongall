# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html): while the
major version is 0, a breaking change bumps the minor version. An entry a
caller must act on is prefixed **Breaking.**

A change to what irongall accepts is recorded even when no signature of the
public API changes, since a verifier's verdicts are part of its contract.

## [Unreleased]

### Added

- `policy::Reason::UnattributedSignatures`, the reason a certificate grants
  nothing when it holds more signatures out of place than judging it tries
  to place.

### Security

- A certificate's statements over its user IDs and subkeys, such as a
  subkey's revocation or a newer binding or certification, count wherever
  they are placed: one that does not verify over the part it follows is
  tried over the certificate's other parts. The search is bounded by the
  size of the certificate's signatures, and a certificate that needs more
  grants nothing, refused as `Reason::UnattributedSignatures`. Earlier
  releases weighed such a statement only over the part it follows, which
  an unsigned change to the certificate could alter, so the certificate
  could grant what the statement withdrew.
- Verifying a document against a keyring finishes each signature's hash
  once, however many keys it is tried with, and looks up the keys its
  issuers name. Earlier releases could do work in proportion to a
  signature's size times the number of keys in the keyring.
- A subkey binding whose back-signature, in the binding's unhashed area,
  states an expiration refuses the subkey, as `Reason::UnhonoredBinding`,
  since the binding does not cover that expiration. Earlier releases
  applied it. Back-signatures in the hashed area, and those GnuPG and RNP
  make, which state no expiration, are judged as before.
- A certificate's statement that verifies restricts what the certificate
  grants whatever the parts of its packet that no signature covers hold:
  its hash prefix, octets after its material, and the lengths written for
  its material's integers. A statement whose prefix is not its hash's,
  whose packet holds octets after its material, or whose integers' lengths
  are not written as RFC 9580 requires grants nothing. Earlier releases
  passed over such a statement, so an unsigned change to the certificate
  could make it grant what a revocation or a newer self-signature
  withdrew.

### Changed

- SECURITY.md states which releases receive security fixes.
- Reading holds less memory. A document's signatures, a signature's
  subpackets and embedded signatures, and an armored block's headers are
  counted by their framing before anything is allocated for them, and
  every other list is held at its length once complete. A certificate's
  repeated user IDs and subkeys are merged without copying them, and
  `Keyring::new` combines certificates in place. On a 64-bit target, a
  document is held in at most 16 times its size, and a keyring in at most
  28 times once it is a `Keyring`, where earlier releases held them in up
  to about 50 and 130 times. A harness under `memory/` holds these
  factors.
- A signature is refused as malformed when it carries a subpacket of a type
  irongall keeps without reading whose length is not the one RFC 9580 gives
  the type (§5.2.5): Exportable Certification, Revocable, Trust Signature,
  Revocation Key, Notation Data, Signature Target, Intended Recipient
  Fingerprint, or Preferred AEAD Ciphersuites. Earlier releases read it.
- The documentation states more of what irongall does not judge: that
  anyone who handles a certificate can add user IDs until judging it needs
  more than its bound allows, that a statement over MD5 or RIPEMD-160, or
  of version 3, is passed over whatever it states, how much memory reading
  a document or a keyring holds, and the length RFC 8017 holds an RSA
  signature to, which `rsa::PublicKey::verify` does not.

## [0.1.1] - 2026-11-01

### Added

- `rsa::PublicKey`, which verifies an RSA PKCS #1 v1.5 signature over a
  digest the caller computed, for a format outside OpenPGP that signs the
  same way. It holds a key to the bounds every RSA key in irongall is held
  to, 2048 to 8192 bits with an odd exponent from 3 to 2^33 - 1, and refuses
  any other with `rsa::RsaError`. It verifies over any hash function irongall
  implements, SHA-1 included, and leaves which ones to accept to the caller.
- `hash::Digest`, a digest tagged with the function that computed it, the
  form `rsa::PublicKey::verify` takes it in.

## [0.1.0] - 2026-10-31

The first release.

### Added

- Verification of version 4 and version 6 OpenPGP signatures (RFC 9580) over
  cleartext-signed documents and detached data, binary or text, against
  certificates read from a keyring, binary or armored.
- RSA PKCS #1 v1.5 keys of 2048 to 8192 bits, Ed25519, and EdDSALegacy over
  Ed25519, with signatures over SHA2-224, SHA2-256, SHA2-384, SHA2-512,
  SHA3-256, or SHA3-512. SHA-1 computes version 4 fingerprints and key IDs.
- A policy that judges what a signature is worth: the hashes and keys it
  accepts, whether the signing key was in force when it signed and still is,
  whether a subkey was granted the right to sign, and the certificate's
  revocations and expirations.
- The layers beneath it, each usable alone: ASCII armor, packets, public keys
  with their fingerprints and key IDs, signatures and their subpackets,
  certificates, and the hash functions.

[0.1.1]: https://github.com/gregordinary/irongall/releases/tag/v0.1.1
[0.1.0]: https://github.com/gregordinary/irongall/releases/tag/v0.1.0
