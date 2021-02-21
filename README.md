# common-crypto

[![github action](https://github.com/steven-joruk/common-crypto/actions/workflows/rust.yml/badge.svg)](https://github.com/steven-joruk/common-crypto/actions)
[![crates.io](https://img.shields.io/crates/v/common-crypto)](https://crates.io/crates/common-crypto)
[![docs.rs](https://docs.rs/common-crypto/badge.svg)](https://docs.rs/common-crypto)

Bindings for Apple's Common Crypto APIs.

## Example

```toml
[dependencies]
common-crypto = "0.1"
```

```rust
use common_crypto::{AES256, CryptorBuilder, Mode};

let encryptor = CryptorBuilder::<AES256>::new(Mode::CTR, b"0123456789abcdef")
    .iv(b"use random iv :)")
    .encryptor()
    .unwrap();

let mut encrypted = Vec::new();
encryptor.update(b"Hello", &mut encrypted).unwrap();

let decryptor = CryptorBuilder::<AES256>::new(Mode::CTR, b"0123456789abcdef")
    .iv(b"use random iv :)")
    .decryptor()
    .unwrap();

let mut decrypted = Vec::new();
decryptor.update(&encrypted, &mut decrypted).unwrap();

assert_eq!(decrypted, b"Hello");
```

## What's missing?

* Streaming support for CCHMac.
* CC_MD*
* CC_SHA*
* Resetting cryptors - I don't see a use case for this, so I won't implement it.
* Padding and rounds for cryptors. I want to make sure they're only configurable
  where they're actually supported.

## Contributing

Feel free to contribute in any way you like.