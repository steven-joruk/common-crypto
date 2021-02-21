# common-crypto

[![github action](https://github.com/steven-joruk/common-crypto/actions/workflows/rust.yml/badge.svg)](https://github.com/steven-joruk/common-crypto/actions)
[![crates.io](https://img.shields.io/crates/v/common-crypto)](https://crates.io/crates/common-crypto)
[![docs.rs](https://docs.rs/common-crypto/badge.svg)](https://docs.rs/common-crypto)

Bindings for Apple's Common Crypto APIs.

## Examples

```toml
[dependencies]
common-crypto = "0.2"
```

### Cryptor

```rust
let config = Config::AES256 {
    mode: Mode::CTR,
    iv: Some(b"use random iv :)"),
    key: b"0123456789abcdef0123456789abcdef",
};

let encrypted = Cryptor::encrypt(&config, b"Hello").unwrap();
let decrypted = Cryptor::decrypt(&config, encrypted).unwrap();
assert_eq!(decrypted, b"Hello");
```

### HMAC

```rust
let auth_code = HMac::sha512(b"Key", b"Input");
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