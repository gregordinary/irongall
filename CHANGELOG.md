# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html): while the
major version is 0, a breaking change bumps the minor version. An entry a
caller must act on is prefixed **Breaking.**

A change to what irongall accepts is recorded even when no signature of the
public API changes, since a verifier's verdicts are part of its contract.

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

[0.1.0]: https://github.com/gregordinary/irongall/releases/tag/v0.1.0
