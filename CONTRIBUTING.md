# Contributing

irongall is maintained in spare time. This document sets out how changes are
handled, and what you need to build and test the code.

## Reporting a security issue

Report a signature irongall accepts and should not, or another security
issue, privately, through the channel [SECURITY.md](SECURITY.md) describes.
These are the reports the project most wants to receive, and they are acted
on ahead of everything else. Please do not open a public issue for one.

## Proposing a change

Open an issue before writing code, so the design can be agreed before anyone
spends time on it. A verifier's public surface is a compatibility commitment,
and its rules about what to accept are security decisions. Both are better
settled in discussion than in review.

## Building and testing

The toolchain is pinned in `rust-toolchain.toml`, so `rustup` provisions the
right version and components automatically.

```sh
cargo build
cargo test
```

The library has no dependencies. The tests compare it against established
implementations, which are dev-dependencies and never reach the library.

## Before opening a pull request

CI runs all of these, and running them locally first is faster than a round
trip.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --all-features --no-deps    # RUSTDOCFLAGS='-D warnings'
cargo +1.91 check --all-targets --all-features    # RUSTFLAGS='-D warnings'
cargo deny check licenses advisories sources
```

The fifth checks the minimum supported Rust version, which sits below the
pinned toolchain, and needs that toolchain installed. The last needs
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny).

## The public API

`public-api.txt` is committed, so any change to the public surface arrives as
a reviewable diff, and CI fails on a change the snapshot does not record.
Regenerate it with the command in the `api` job of
`.github/workflows/ci.yml`, with the nightly that job pins, and commit the
result. The snapshot is rustdoc's JSON rendering, which differs between
nightlies, so an unpinned regeneration produces a diff that is not an API
change; the job pins the `cargo-public-api` version for the same reason. A
type that gains or loses `Send` or `Sync` shows in the snapshot, and losing
one is a breaking change.

CI's `semver` job builds the newest release tag and the tree, and runs
[cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks)
between them. While `version` still names the last release, it fails on a
breaking change and lists the items it breaks. Bumping the version to the
next breaking release, 0.1.x to 0.2.0, turns it green, and each item it
listed takes a **Breaking.** entry in CHANGELOG.md.

## Fuzzing

`fuzz/` holds a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) target
for each parser that reads untrusted input, and `differential`, which runs the
differential tests' comparison over arbitrary input. The targets need a
nightly toolchain:

```sh
cd fuzz
cargo +nightly fuzz run armor -- -dict=armor.dict
```

`cargo fuzz list` names the targets. CI builds every target but runs none.
After changing a parser, run its target for a while before opening the pull
request.

## Test vectors

Vectors live under `tests/vectors/`, one directory per source. Those
published elsewhere are kept byte for byte as published, and their README
names the source, the date it was retrieved, and the digest of what was
downloaded, so the files can be checked against it. Those generated with
another implementation, such as GnuPG, keep that implementation's own reading
of them beside them, which the tests hold irongall to, and their README gives
the commands that made them. A test that reads a vector file asserts how many
cases it checked, so a parsing slip cannot pass by checking none.

The vectors are excluded from the published crate.

Some cases cannot come from a vector, because no implementation makes them on
request: a subkey binding without a back-signature, or a self-signature that
shortens a key's life. Tests make those with `test_support::forge`, which
writes the packets and signs them with keys whose secrets the tests hold. A
test of a refusal also checks the same shape with the defect removed, so that
what it shows is the refusal and not a malformed fixture.

## Differential tests

`tests/differential` holds irongall to [rPGP](https://github.com/rpgp/rpgp),
an independent implementation of RFC 9580. Both read the same octets:
certificates and signatures rPGP makes from fixed seeds, the GnuPG vectors,
and those octets altered one at a time. Both must frame the same packets and
read the same ones, what both read they must read alike, and on each
signature they must reach the same verdict.

Where the two differ on purpose, `compare.rs` names the difference: a variant
of its `Divergence` enum, with the rule behind it, whether the difference is
in a verdict or in which packets each reads. A divergence is recognized from
the input, never from either verdict, so that a defect cannot pass for one;
for a packet only one of the two reads, `form.rs` reads what the packet
holds, apart from both implementations. Any other difference fails the test.
A change that makes irongall differ from rPGP in a new way adds a variant,
and a case in `divergences.rs` that produces it.

## Code conventions

- **No `unsafe`.** The crate forbids it.
- **No panics in library code.** Reading hostile bytes is the library's job,
  so a reachable panic is a denial of service waiting for an input to find it.
  The lints at the top of `src/lib.rs` deny the common ways to panic or to
  compute a wrong length silently: indexing, unchecked arithmetic, truncating
  casts, `unwrap`, `expect`, and the panicking macros. A site that genuinely
  cannot fail, and is clearer written directly, carries
  `#[expect(lint, reason = "...")]` on the smallest item that holds it, with
  the reason stating the invariant that makes it safe. A type whose
  arithmetic operators cannot overflow, such as a field element, is exempted
  by name in `clippy.toml` instead, and the integer arithmetic inside its
  operators carries the `expect`. Tests are exempt.
- **Bounded work.** A length read from input is checked against the bytes
  remaining before anything is allocated for it. Parsing is linear in its
  input and never recurses on its structure. Judging is linear too: a
  subject hashed once for each signature over it, such as a user ID or a
  subkey, is bounded in size before any of those signatures is verified.
- **No constant-time code, and no claim of it.** Everything a verification
  computes over is public: the key, the signature, and the signed data. That
  is what makes hand-written cryptography reasonable here, and it leaves
  correctness as the thing to establish, which the vectors, the differential
  tests, and the fuzzers do.
- **`no_std` with `alloc`.** The library needs an allocator and nothing else
  from its platform.
- **Errors are typed and say where.** A parse error names the place in its
  input the problem was found. Error enums are `#[non_exhaustive]`, so a new
  kind of failure is not a breaking change.
- **Documentation is part of the change.** Public items carry rustdoc, and
  internal items carry it wherever the behavior is not obvious. Comments
  explain *why*, not *what*. A rule taken from a specification cites the
  section it comes from.
- **No emoji** in code, comments, documentation, or commit messages.

## Commit messages

Write in the imperative mood, describing the change in the repository's own
terms. A body explaining the reasoning is welcome where the reasoning is not
obvious.

## License

The project is dual-licensed under Apache-2.0 and MIT. Unless you state
otherwise, any contribution you intentionally submit for inclusion, as defined
in the Apache-2.0 license, is dual-licensed the same way, with no additional
terms or conditions.
