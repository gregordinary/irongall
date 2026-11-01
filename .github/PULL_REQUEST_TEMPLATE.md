<!-- A change is best agreed in an issue before it is written; see
     CONTRIBUTING.md. Link that issue here if there is one. -->

## What this changes

<!-- The change in the repository's own terms: what the code now does. -->

## Why

<!-- The reasoning, where it is not obvious from the change itself. -->

## Checks

<!-- CI runs all of these; running them locally first is faster than a round
     trip. See CONTRIBUTING.md. -->

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all-features`
- [ ] `cargo doc --all-features --no-deps` with `RUSTDOCFLAGS='-D warnings'`
- [ ] `cargo +1.91 check --all-targets --all-features` with `RUSTFLAGS='-D warnings'`
- [ ] `cargo deny check licenses advisories sources`, if a dependency changed
- [ ] The fuzz target of each parser the change touches has run for a while

## What it accepts

- [ ] The change accepts nothing irongall refused before, **or** the
      description says what, and why that is sound
- [ ] A new difference from rPGP is a `Divergence` variant, with a case in
      `tests/differential/divergences.rs` that produces it
- [ ] A new departure from RFC 9580 or GnuPG is listed in the Conformance
      section of the crate documentation
