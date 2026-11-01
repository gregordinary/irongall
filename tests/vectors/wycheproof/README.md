# Wycheproof test vectors

Project Wycheproof's vectors for the signature schemes OpenPGP signs with:
RSA PKCS #1 v1.5, for the hash functions SHA-1, SHA2-224, SHA2-256,
SHA2-384, SHA2-512, SHA3-256 and SHA3-512, and Ed25519. The files are
unmodified.

- `rsa_signature_*_test.json`: verification tests, one key size and hash
  function to each file. Each holds valid signatures and invalid ones that
  break the encoding in the ways lenient verifiers have accepted.
- `rsa_pkcs1_*_sig_gen_test.json`: valid signatures, including signatures
  with keys narrower than 2048 bits, over SHA-1, and with the public exponent
  3.
- `ed25519_test.json`: verification tests: valid signatures, and invalid
  ones with S of L or more, malformed encodings of R, and truncated or
  extended signatures. Some keys are of small order, or of mixed order, and
  Wycheproof calls their signatures acceptable.

- Source: <https://github.com/C2SP/wycheproof>, directory `testvectors_v1`, at
  commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`
- Retrieved: 2026-10-29, and the four `sha3` files 2026-10-31

SHA2-256 of each file:

```text
ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3  ed25519_test.json
d29bb1d43016e8932937554291e997dc509455373b0d3cfe89ebffaee80ec9cd  rsa_pkcs1_1024_sig_gen_test.json
251da3f00f11cba07f8e89c94363e25ea16ef4b35aaa270063e4f763c283a8bd  rsa_pkcs1_1536_sig_gen_test.json
587b3d27d3429f2118cb02818da4d08eb3f36f50c747939eb550fae4337ccbf0  rsa_pkcs1_2048_sig_gen_test.json
45153219d486fd135d35aa968a957a0c015c7829e8dc59bea5f87e6c30912677  rsa_pkcs1_3072_sig_gen_test.json
f13eadbec6c45291cb33e6b2fa0a0c2b862d0bd2eaec29f930d3b78067cd48c7  rsa_pkcs1_4096_sig_gen_test.json
81b9da6e58f8a55ccc02b96f64a1d84d93100b9767dddbc906cee52d4c7daeac  rsa_signature_2048_sha224_test.json
94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393  rsa_signature_2048_sha256_test.json
c571c105d261c0ff588a2888a529f152563fb3b77894b7620d4e4f8f934f2c1d  rsa_signature_2048_sha384_test.json
16ea24b039905d054bdb6004f5fd179374e150b7b6d73a7ba654b6d00eab12ef  rsa_signature_2048_sha512_test.json
1f9598c12de63d235788a46f518ccc6c7f7e76329d17e2d6813a86dd126b16f8  rsa_signature_2048_sha3_256_test.json
5b4bdf46ba62134e61da3189b19b16dfd7119781a5632debd902561d2b9ff60c  rsa_signature_2048_sha3_512_test.json
0f5f18cabfaad3e2792e82f7e9882f8999049b456714de924b8a5e202f61ca43  rsa_signature_3072_sha256_test.json
73499ee649d8fb703b3f0f455fa36f7682fde677c590a736958ebce05ab27dae  rsa_signature_3072_sha384_test.json
09aa3336fdb7be216180ce944ca7b2a052e1de38c210435c19506327d4a36ebd  rsa_signature_3072_sha512_test.json
6c9cd4409bbdc4037128109f22bb5e9e6ab4de3ee1a0a32cd8b3ce90b1f87024  rsa_signature_3072_sha3_256_test.json
e8b1a2d2914c9f5475b1c15cc90f6a49ccff708de8645626f49c941de77f66f9  rsa_signature_3072_sha3_512_test.json
957aca128e30bd02c8982f8ca482d6521d16683f4bbc3f193cdfd4c8f04bc667  rsa_signature_4096_sha256_test.json
bc26f16b9fc9a90628864d3d1111ef48a4bd00b9d4870bfab88ff326e309e073  rsa_signature_4096_sha384_test.json
9d6e67b1eb0d7040db411835238efd20e9302399a258bdff82de3f38e0f2855a  rsa_signature_4096_sha512_test.json
86df4075b4ce5954726abfa00cc19ebe8b608d6d99094d5e123d6a3a86568bd9  rsa_signature_8192_sha256_test.json
382c2795790021798099bc8e94d0f078ef1f78787f5c7a87aaa25b5556efacff  rsa_signature_8192_sha384_test.json
c9e5463742d192b5ff1108538841d4d302fd799604a051d09db5f496f2f851f7  rsa_signature_8192_sha512_test.json
```

Each RSA verification file has one test Wycheproof calls acceptable: a
DigestInfo without its NULL parameters. irongall refuses it, since RFC 9580
Table 24 gives the encoding with them. Of the Ed25519 tests it calls
acceptable, irongall refuses those whose key is of small order, and verifies
those whose key is of mixed order by the cofactorless equation.

Wycheproof is licensed under the Apache License, Version 2.0, a copy of which
is in `LICENSE`.
