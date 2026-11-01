# irongall

OpenPGP signature verification in safe Rust, with no dependencies.

irongall is in early development. Its API is not yet stable, and it has not
had an independent security audit.

Its scope is version 4 and version 6 OpenPGP signatures
([RFC 9580](https://www.rfc-editor.org/rfc/rfc9580)) over cleartext-signed
documents and detached data, checked against certificates read from a keyring.
It implements its own hashing, RSA, and Ed25519 verification, contains no
`unsafe` code, and needs nothing from its platform but an allocator. It judges
what a signature is worth as well as whether it verifies: which algorithms are
trusted, whether the signing key was in force when it signed, and whether a
subkey was ever granted the authority to sign.

It verifies only. It does not sign, generate keys, or encrypt.

## Example

Verifying a Debian `InRelease` file against the archive's keyring:

```rust,no_run
use std::time::{SystemTime, UNIX_EPOCH};

use irongall::keyring::Keyring;
use irongall::policy::Policy;
use irongall::{cert, document};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keyring = std::fs::read("/usr/share/keyrings/debian-archive-keyring.gpg")?;
    let keyring: Keyring = cert::certificates(&keyring).collect::<Result<_, _>>()?;
    let release = std::fs::read("InRelease")?;
    let release = document::cleartext(&release)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let verified = keyring.verify(&Policy::new(), now, release.signatures(), release.text())?;
    println!("signed by {}", verified.key().fingerprint());
    Ok(())
}
```

The [crate documentation](https://docs.rs/irongall) describes each layer,
how a certificate and a signature are judged, and where irongall departs
from RFC 9580 or from GnuPG.

## Testing

irongall is held to the published test vectors of its primitives (NIST CAVP,
Wycheproof, RFC 8032), to GnuPG's own readings of certificates and signatures
GnuPG made, and to rPGP, an independent implementation of RFC 9580, over
certificates and signatures rPGP makes, over those altered octet by octet, and
over arbitrary input under a fuzzer. [CONTRIBUTING.md](CONTRIBUTING.md)
describes the tests.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
