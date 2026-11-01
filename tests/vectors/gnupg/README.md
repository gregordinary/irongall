# Certificates and signatures generated with GnuPG

One certificate for each family of algorithm GnuPG 2.4 generates: a signing
primary key and an encryption subkey, each bound by its self-signatures. Then a
certificate whose subkey signs, so that the subkey's binding embeds a
back-signature, and detached signatures that subkey made over `document.txt`.
Then a certificate carrying every other kind of signature a certificate holds:
a key revocation, a direct-key signature, and the revocations of a user ID and
of a subkey. Then a certificate whose primary key and subkey both sign, and
the signed documents they made: a cleartext signed message and a detached
signature file, each carrying a signature by each key. Last, a certificate
whose expiration was extended after one of its user IDs was revoked, and a
signature its key made after the expiration it was first given. Then a
certificate whose key made a text signature over a text holding carriage
returns in each place where implementations read them differently. Last of
all, two certificates whose Ed25519 keys made revocations over hashes shorter
than RFC 9580 lets an Ed25519 signature rest on: one its key revoked over
SHA-1, and one whose signing subkey its primary key revoked over SHA2-224,
with a signature each of its keys made before then, the primary key's over
SHA2-224; and a certificate made to expire a day after it was made, with a
signature its key made within that day.

The `.pgp` files are `gpg --export` output, the `.sig` files
`gpg --detach-sign` output, and the `.asc` files GnuPG's armored signed
documents. Beside each is GnuPG's own reading of it, which the tests hold
irongall's reading to:

- `.colons`, for a certificate's keys:
  `gpg --with-colons --fixed-list-mode --show-keys`.
- `.packets`, for every signature: `gpg --list-packets`.
- `.checks`, for every certificate's signatures, GnuPG's verdict on each:
  `gpg --with-colons --fixed-list-mode --check-signatures`.
- `.verify`, for every signed document, the status lines of its
  verification, `gpg --status-fd 1 --verify`, which name the key that made
  each signature and the signature's creation time, algorithms, and type.
  `gpg --list-packets` stops at a cleartext signed message's framing and does
  not list its signatures, so for those this is the only reading.

| File | Primary key | Subkey | Key version |
| --- | --- | --- | --- |
| `rsa` | RSA 2048 | RSA 2048 | 4 |
| `dsa` | DSA 2048 | Elgamal 2048 | 4 |
| `ed25519` | EdDSALegacy, Ed25519Legacy | ECDH, Curve25519Legacy | 4 |
| `nistp256` | ECDSA, NIST P-256 | ECDH, NIST P-256 | 4 |
| `brainpoolp256r1` | ECDSA, brainpoolP256r1 | ECDH, brainpoolP256r1 | 4 |
| `ed448` | EdDSALegacy, Ed448 | ECDH, X448 | 5 |
| `ed25519-signing` | EdDSALegacy, Ed25519Legacy, certifying only | EdDSALegacy, Ed25519Legacy, signing | 4 |
| `lifecycle` | EdDSALegacy, Ed25519Legacy, certifying only | EdDSALegacy, Ed25519Legacy, signing; ECDH, Curve25519Legacy | 4 |
| `documents` | EdDSALegacy, Ed25519Legacy, signing and certifying | RSA 3072, signing | 4 |
| `extended` | EdDSALegacy, Ed25519Legacy, signing and certifying | None | 4 |
| `textmode` | EdDSALegacy, Ed25519Legacy, signing and certifying | None | 4 |
| `revoked-sha1` | EdDSALegacy, Ed25519Legacy, signing and certifying | None | 4 |
| `short-hash` | EdDSALegacy, Ed25519Legacy, signing and certifying | EdDSALegacy, Ed25519Legacy, signing | 4 |
| `expired` | EdDSALegacy, Ed25519Legacy, signing and certifying, for one day | None | 4 |

| File | Signature |
| --- | --- |
| `binary.sig` | Binary, with a notation, a policy URI, and an expiration two years on |
| `text.sig` | Text |
| `critical-notation.sig` | Binary, with a notation marked critical |
| `cleartext.asc` | Cleartext signed message over `cleartext.txt`: a text signature by each key of `documents` |
| `cleartext-crlf.asc` | `cleartext.asc` with every line ending made CR LF |
| `detached.asc` | Armored, over `document.txt`: a binary signature by each key of `documents` |
| `late.sig` | Binary, over `document.txt`, by `extended` on 2028-01-01: after the expiration the key was first given, and within the one it was extended to |
| `text-crs.sig` | Text, over `text-crs.txt`, by `textmode`: a text with a carriage return in the middle of a line, two before a line feed, one before a space, and one that ends it |
| `sha224.sig` | Binary, over `document.txt`, by `short-hash`'s primary key, over SHA2-224 |
| `revoked-subkey.sig` | Binary, over `document.txt`, by `short-hash`'s subkey, the day before the subkey was revoked |
| `before-expiry.sig` | Binary, over `document.txt`, by `expired`, within the day it was made to last |

GnuPG 2.4 generates Ed448 keys as version 5 keys, which LibrePGP defines and
RFC 9580 does not, and signs with them in version 5 signatures.

Each certificate was generated in an empty home directory that was then
discarded with the secret keys, with GnuPG 2.4.4 and libgcrypt 1.10.3: the
first six rows on 2026-10-27, `ed25519-signing`, its signatures, and
`lifecycle` on 2026-10-29, `extended`, `late.sig`, `textmode`, and its
signature on 2026-10-30, and `revoked-sha1`, `short-hash`, `expired`, and
their signatures on 2026-10-31. For each of the first six rows (here, `rsa`):

```sh
opts='--batch --pinentry-mode loopback --passphrase= --faked-system-time 20260101T000000!'
gpg $opts --quick-gen-key 'irongall test, rsa <rsa@example.invalid>' rsa2048 sign never
gpg $opts --quick-add-key "$fingerprint" rsa2048 encr never
gpg --export "$fingerprint" > rsa.pgp
gpg --with-colons --fixed-list-mode --show-keys rsa.pgp > rsa.colons
```

For `ed25519-signing` and its signatures, with the same `opts`:

```sh
gpg $opts --quick-gen-key 'irongall test, ed25519-signing <ed25519-signing@example.invalid>' ed25519 cert never
gpg $opts --quick-add-key "$fingerprint" ed25519 sign never
gpg --export "$fingerprint" > ed25519-signing.pgp
gpg --with-colons --fixed-list-mode --show-keys ed25519-signing.pgp > ed25519-signing.colons
printf 'irongall test document\nsecond line\n' > document.txt
gpg $opts --detach-sign --sig-notation 'note@example.invalid=value' \
    --sig-policy-url 'https://example.invalid/policy' --default-sig-expire 2y \
    -o binary.sig document.txt
gpg $opts --detach-sign --textmode -o text.sig document.txt
gpg $opts --detach-sign --sig-notation '!critical@example.invalid=value' \
    -o critical-notation.sig document.txt
```

For `lifecycle`, each step a day after the last, so that every signature has
a creation time of its own. `opts DAY` is `opts` with the clock frozen at
midnight UTC on that day of January 2026, and `revoker` is the fingerprint of
a second key made in the same home only to be named:

```sh
gpg $(opts 01) --quick-gen-key 'irongall test, lifecycle <lifecycle@example.invalid>' ed25519 cert never
gpg $(opts 01) --quick-add-key "$fingerprint" ed25519 sign never
gpg $(opts 01) --quick-add-key "$fingerprint" cv25519 encr never
gpg $(opts 02) --quick-add-uid "$fingerprint" 'irongall test, lifecycle second <second@example.invalid>'
gpg $(opts 03) --quick-revoke-uid "$fingerprint" 'irongall test, lifecycle second <second@example.invalid>'
gpg $(opts 04) --quick-set-expire "$fingerprint" 2y
gpg $(opts 05) --quick-set-expire "$fingerprint" 1y "$signing_subkey"
printf 'key 2\nrevkey\ny\n3\n\ny\nsave\n' | gpg $(opts 06) --command-fd 0 --edit-key "$fingerprint"
printf 'addrevoker\n%s\ny\nsave\n' "$revoker" | gpg $(opts 07) --command-fd 0 --edit-key "$fingerprint"
printf 'y\n1\n\ny\n' | gpg --no-tty --pinentry-mode loopback --passphrase= \
    --faked-system-time '20260108T000000!' --command-fd 0 --gen-revoke -o revocation.asc "$fingerprint"
gpg $(opts 08) --import revocation.asc
gpg --export "$fingerprint" > lifecycle.pgp
gpg --with-colons --fixed-list-mode --show-keys lifecycle.pgp > lifecycle.colons
```

GnuPG replaces a self-signature it supersedes, so the export holds only the
newest certification of the first user ID and the newest binding of the
signing subkey.

For `documents` and its documents, on 2026-10-29, with `opts` frozen at
2026-02-01 00:00:00 UTC instead, and the `!` suffix making GnuPG sign with
exactly the key named. `cleartext.txt` carries the lines a cleartext signed
message must dash-escape, trailing whitespace, and an empty last line:

```sh
gpg $opts --quick-gen-key 'irongall test, documents <documents@example.invalid>' ed25519 sign,cert never
gpg $opts --quick-add-key "$fingerprint" rsa3072 sign never
gpg --export "$fingerprint" > documents.pgp
gpg --with-colons --fixed-list-mode --show-keys documents.pgp > documents.colons
gpg $opts --clearsign -u "$fingerprint!" -u "$subkey!" -o cleartext.asc cleartext.txt
gpg $opts --armor --detach-sign -u "$fingerprint!" -u "$subkey!" -o detached.asc document.txt
sed 's/$/\r/' cleartext.asc > cleartext-crlf.asc
```

For `extended` and `late.sig`, with `opts DAY` as for `lifecycle`:

```sh
gpg $(opts 01) --quick-gen-key 'irongall test, extended <extended@example.invalid>' ed25519 sign,cert 1y
gpg $(opts 02) --quick-add-uid "$fingerprint" 'irongall test, extended old <old@example.invalid>'
gpg $(opts 03) --quick-revoke-uid "$fingerprint" 'irongall test, extended old <old@example.invalid>'
gpg $(opts 04) --quick-set-expire "$fingerprint" 5y
gpg --export "$fingerprint" > extended.pgp
gpg --with-colons --fixed-list-mode --show-keys extended.pgp > extended.colons
gpg --batch --pinentry-mode loopback --passphrase= --faked-system-time '20280101T000000!' \
    --detach-sign -o late.sig document.txt
```

GnuPG re-signs only the user IDs that are not revoked when it changes a key's
expiration, so the revoked user ID keeps the certification of the second day,
which states the expiration of one year.

For `textmode` and `text-crs.sig`, with `opts` frozen at 2026-03-01 00:00:00
UTC instead:

```sh
gpg $opts --quick-gen-key 'irongall test, textmode <textmode@example.invalid>' ed25519 sign,cert never
gpg --export "$fingerprint" > textmode.pgp
printf 'irongall test, text mode\na lone CR\rin the middle of a line\na CR before CR LF\r\r\na CR, then a space\r \nCR LF\r\nends in a CR\r' > text-crs.txt
gpg $opts --detach-sign --textmode -o text-crs.sig text-crs.txt
```

For `revoked-sha1`, `short-hash`, and `expired` and their signatures, each
certificate in a home of its own, with `opts DAY` as for `lifecycle`, but on
that day of February 2026. `--gen-revoke` refuses batch mode, so it reads its
answers from standard input instead:

```sh
gpg $(opts 10) --quick-gen-key 'irongall test, revoked-sha1 <revoked-sha1@example.invalid>' ed25519 sign,cert never
printf 'y\n0\n\ny\n' | gpg --no-tty --pinentry-mode loopback --passphrase= \
    --faked-system-time '20260211T000000!' --cert-digest-algo SHA1 --command-fd 0 \
    --gen-revoke -o revocation.asc "$fingerprint"
gpg $(opts 11) --import revocation.asc
gpg --export "$fingerprint" > revoked-sha1.pgp
gpg --with-colons --fixed-list-mode --show-keys revoked-sha1.pgp > revoked-sha1.colons

gpg $(opts 10) --quick-gen-key 'irongall test, short-hash <short-hash@example.invalid>' ed25519 sign,cert never
gpg $(opts 10) --quick-add-key "$fingerprint" ed25519 sign never
gpg $(opts 11) --digest-algo SHA224 --detach-sign -u "$fingerprint!" -o sha224.sig document.txt
gpg $(opts 11) --detach-sign -u "$subkey!" -o revoked-subkey.sig document.txt
printf 'key 1\nrevkey\ny\n0\n\ny\nsave\n' | gpg $(opts 12) --cert-digest-algo SHA224 \
    --command-fd 0 --edit-key "$fingerprint"
gpg --export "$fingerprint" > short-hash.pgp
gpg --with-colons --fixed-list-mode --show-keys short-hash.pgp > short-hash.colons

gpg $(opts 10) --quick-gen-key 'irongall test, expired <expired@example.invalid>' ed25519 sign,cert 1d
gpg $(opts 10) --detach-sign -o before-expiry.sig document.txt
gpg --export "$fingerprint" > expired.pgp
gpg --with-colons --fixed-list-mode --show-keys expired.pgp > expired.colons
```

The `.packets` listings were made with `gpg --list-packets FILE > NAME.packets`
for every `.pgp` and `.sig` file, and for `detached.asc`: on 2026-10-31 for
`revoked-sha1.pgp`, `short-hash.pgp`, `expired.pgp`, `sha224.sig`,
`revoked-subkey.sig`, and `before-expiry.sig`, on 2026-10-30 for `extended.pgp`,
`late.sig`, `textmode.pgp`, and `text-crs.sig`, and on 2026-10-29 for the rest.
The `.checks` and `.verify` listings were made on the same days, each in an
empty home directory holding only the certificate concerned:

```sh
gpg --batch --import NAME.pgp
gpg --batch --with-colons --fixed-list-mode --check-signatures "$fingerprint" > NAME.checks
verdicts='VALIDSIG|GOODSIG|BADSIG|ERRSIG'
gpg --batch --status-fd 1 --verify cleartext.asc | grep -E "$verdicts" > cleartext.verify
gpg --batch --status-fd 1 --verify cleartext-crlf.asc | grep -E "$verdicts" > cleartext-crlf.verify
gpg --batch --status-fd 1 --verify detached.asc document.txt | grep -E "$verdicts" > detached.verify
gpg --batch --faked-system-time '20280102T000000!' --status-fd 1 --verify late.sig document.txt \
    | grep -E "$verdicts|EXPKEYSIG|KEYEXPIRED" > late.verify
gpg --batch --status-fd 1 --verify text-crs.sig text-crs.txt | grep -E "$verdicts" > text-crs.verify
gpg --batch --status-fd 1 --verify sha224.sig document.txt | grep -E "$verdicts" > sha224.verify
gpg --batch --status-fd 1 --verify revoked-subkey.sig document.txt \
    | grep -E "$verdicts|REVKEYSIG|KEYREVOKED" > revoked-subkey.verify
gpg --batch --status-fd 1 --verify before-expiry.sig document.txt \
    | grep -E "$verdicts|EXPKEYSIG|KEYEXPIRED" > before-expiry.verify
gpg --batch --with-colons --fixed-list-mode --show-keys textmode.pgp > textmode.colons
```

The last line is for `textmode` alone, whose `.colons` listing was made there
rather than in the home that generated it.

The frozen clock makes every creation time in the first seven rows 2026-01-01
00:00:00 UTC, in `documents` and its documents 2026-02-01 00:00:00 UTC, in
`textmode` and its signature 2026-03-01 00:00:00 UTC, in `revoked-sha1`,
`short-hash`, `expired`, and their signatures midnight UTC on 10, 11, or 12
February 2026, and in `late.sig` 2028-01-01 00:00:00 UTC. The keys are fresh and
random, so a regeneration produces different files.
