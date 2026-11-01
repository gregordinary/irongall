# ed25519-speccheck test vectors

The twelve Ed25519 test vectors of ed25519-speccheck, which accompanies
Chalkias, Garillot and Nikolaenko, "Taming the many EdDSAs" (SSR 2020,
<https://eprint.iacr.org/2020/1244>). Each probes one rule on which Ed25519
verifiers differ: small-order keys and R values, the cofactored and
cofactorless equations, S of L or more, and non-canonical encodings of R and
of the key. `cases.json` is unmodified.

| Case | S | Key | R | Note |
| --- | --- | --- | --- | --- |
| 0 | zero | small order | small order | |
| 1 | below L | small order | mixed order | |
| 2 | below L | mixed order | small order | |
| 3 | below L | mixed order | mixed order | satisfies both equations |
| 4 | below L | mixed order | mixed order | satisfies the cofactored equation only |
| 5 | below L | mixed order | order L | fails the cofactored equation when 8k is reduced first |
| 6 | above L | order L | order L | |
| 7 | far above L | order L | order L | |
| 8 | below L | mixed order | small order, non-canonical | the hash taken over the canonical R |
| 9 | below L | mixed order | small order, non-canonical | the hash taken over R as encoded |
| 10 | below L | small order, non-canonical | mixed order | the hash taken over the canonical key |
| 11 | below L | small order, non-canonical | mixed order | the hash taken over the key as encoded |

A mixed-order point has a component in the small subgroup but is not itself
of small order. The table is the repository's own, in its README.

- Source: <https://github.com/novifinancial/ed25519-speccheck>, file
  `cases.json`, at commit `65519336fda78a3d016e947df6d82848aca0c9da`
- Retrieved: 2026-10-29

SHA2-256 of `cases.json`:

```text
08e47a36d9aead288664930505584f353fff113ab854f2800db1e4f5b3540450  cases.json
```

ed25519-speccheck is licensed under the Apache License, Version 2.0, a copy of
which is in `LICENSE`.
