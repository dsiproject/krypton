# Krypton Java Cryptography Architecture Provider

The Krypton library implements a curated list of cryptographic algorithms
within the Java Cryptography Architecture (JCA) framework (see
[documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)).
The goal of Krypton is to provide easy access to a wider range of cryptographic
algorithms, thereby helping to avoid cryptographic monoculture.

*Krypton is under extremely early-stage development, and many features are unimplemented*

Additionally, one of Krypton's design goals is to implement the core
cryptographic functionality in such a way that it can be easily exported
to other languages and platforms.

# Algorithm List

The following is a listing of the functionality Krypton aims to support.

## Symmetric-Key Ciphers

### Stream Ciphers

* Salsa20
* ChaCha20
* HC-256

### Block Ciphers

* Serpent
* TwoFish
* ThreeFish
* Camellia

## MACs

* Poly1305
* HMAC modes for all hashes

## Hashes

* Keccak (SHA-3)
* Skein
* BLAKE-2b
* Whirlpool
* RipeMD-160

## Elliptic Curves

* M-221
* E-222
* Curve1174
* Curve25519
* E-382
* M-383
* Curve383187
* Curve41417
* M-512
* E-521
