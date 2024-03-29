# common-crypto

[![github action](https://github.com/steven-joruk/common-crypto/actions/workflows/rust.yml/badge.svg)](https://github.com/steven-joruk/common-crypto/actions)
[![crates.io](https://img.shields.io/crates/v/common-crypto)](https://crates.io/crates/common-crypto)
[![docs.rs](https://docs.rs/common-crypto/badge.svg)](https://docs.rs/common-crypto)

Bindings for Apple's Common Crypto APIs.

## Examples

```toml
[dependencies]
common-crypto = "0.3"
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

### Hash

```rust
let hash = Hash::sha256(b"data");
```

```rust
let mut hasher = hash::SHA256::new();
hasher.update(b"data");
hasher.update(b"more data");
let hash = hasher.finish();
```

### HMAC

```rust
let auth_code = HMAC::sha512(b"Key", b"Input");
```

```rust
let mut hasher = hmac::SHA256::new(b"Key");
hasher.update(b"data");
hasher.update(b"more data");
let hash = hasher.finish();
```

## What's missing?

* Resetting cryptors - I don't see a use case for this, so I won't implement it
  unless someone requests it.
* Padding and rounds for cryptors. I want to make sure they're only configurable
  where they're actually supported.

## Contributing

Feel free to contribute in any way you like.
