# NIST CAVP SHA-3 test vectors

The byte-oriented response files of the Cryptographic Algorithm Validation
Program's SHA-3 Validation System, for SHA3-256 and SHA3-512: the
short-message, long-message and Monte Carlo tests of each. The files are
unmodified, including their CRLF line endings.

- Source: <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip>
- Retrieved: 2026-10-31
- Archive SHA2-256: `cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c`

The archive's SHA3-224 and SHA3-384 files are not included.

The Monte Carlo procedure the `*Monte.rsp` files answer is in section 6.2.3
of *The Secure Hash Algorithm-3 Validation System (SHA3VS)*, NIST, 2016. It
differs from the SHA-1 and SHA-2 one: each digest is the hash of the one
before it alone.

These vectors are a work of the United States Government and are not subject to
copyright protection in the United States.
