# Security policy

irongall decides whether a signature is good. A defect in it can mean that a
forged signature, or one its key had no authority to make, is accepted, so
security reports are handled separately from ordinary bugs.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's [private
vulnerability reporting](https://github.com/gregordinary/irongall/security/advisories/new)
for this repository, which opens a draft advisory visible only to you and the
maintainers.

Please include, as far as you can:

- The input: the certificates, and the signed document or the signature and
  the data it covers. Keys made for the report serve as well as real ones.
- The policy it was judged under, if not `Policy::new()`, and the time it was
  judged at.
- What irongall returned, and what it should have returned. If another
  implementation, such as GnuPG, Sequoia, or rPGP, judges the input
  differently, what that implementation returns.
- The commit or version of irongall.

You will get an acknowledgement within a few days. Once a fix exists, the
advisory names the reporter unless you ask otherwise.

## What is in scope

- **A signature accepted that does not verify.** A forged or altered
  signature, or one made over other data, that irongall reports as verified.
- **Authority a certificate does not grant.** A signature accepted from a key
  that had been revoked or had expired, from a subkey whose binding or
  back-signature does not hold, from a key the certificate does not grant the
  right to sign, or one dated before its key was created.
- **A policy rule that does not apply.** A hash, key, or signature type the
  policy refuses, accepted anyway, or any other rule the documentation states
  that is not enforced.
- **Panics and unbounded work on hostile input.** The library is written not
  to panic, to allocate nothing its input does not account for, and to do
  work linear in its input. The memory it holds is linear in its input too,
  by a factor that is largest for signatures: each subpacket is held apart,
  so a signature whose subpacket areas are packed with the smallest
  subpackets is held in about 17 times its size, on a 64-bit target. A
  panic, an allocation beyond that factor, or time that grows faster than
  the input is a vulnerability, since a verifier reads input from whoever
  sends it.
- **An undocumented departure.** irongall reading or judging an input
  differently from RFC 9580 where the Conformance section of the crate
  documentation does not list the difference.

## What is not in scope

- **Timing side channels.** irongall makes no constant-time claim. Everything
  it computes over, the key, the signature, and the signed data, is public.
- **Refusing what irongall does not implement.** Signing, encryption, and the
  algorithms irongall does not verify with, such as DSA, ECDSA, and Ed448, are
  refused by design.
- **The documented departures.** The differences the Conformance section lists
  are deliberate. Whether one is right is welcome as an ordinary issue.

If you are unsure which side of the line a finding falls on, report it
privately and we will work it out.

## Supported versions

Security fixes are made to the newest release, and published as a release
of their own; earlier releases are not patched, so receiving a fix means
upgrading to the newest release. While the major version is 0, a fix that
changes the public API is published as a new minor version, such as 0.2.0
after 0.1.x, and any other as a new patch version.
