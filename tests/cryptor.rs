use common_crypto::cryptor::*;

#[test]
fn rc4_ecb_encrypt() {
    let config = Config::RC4 { key: b"Key" };

    assert_eq!(
        Cryptor::encrypt(&config, b"Plaintext").unwrap(),
        &[0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
    );
}

#[test]
fn aes256_round_trip() {
    let config = Config::AES256 {
        mode: Mode::CTR,
        iv: Some(b"use random iv :)"),
        key: b"0123456789abcdef0123456789abcdef",
    };

    let encrypted = Cryptor::encrypt(&config, b"Hello").unwrap();
    let decrypted = Cryptor::encrypt(&config, encrypted).unwrap();
    assert_eq!(decrypted, b"Hello");
}

#[test]
fn iv_with_ecb_is_error() {
    let config = Config::AES256 {
        mode: Mode::ECB,
        iv: Some(b"use random iv :)"),
        key: b"0123456789abcdef0123456789abcdef",
    };

    assert_eq!(
        Cryptor::encrypt(&config, b"Hello").unwrap_err(),
        CryptorError::InitializationVectorPresent
    );
}

#[test]
fn iv_is_used() {
    let config = Config::AES256 {
        mode: Mode::CTR,
        iv: Some(b"use random iv :)"),
        key: b"0123456789abcdef0123456789abcdef",
    };

    let encrypted = Cryptor::encrypt(&config, b"Hello").unwrap();
    assert!(!encrypted.is_empty());

    let new_config = Config::AES256 {
        mode: Mode::CTR,
        iv: Some(b"very  random  iv"),
        key: b"0123456789abcdef0123456789abcdef",
    };

    assert_ne!(Cryptor::encrypt(&new_config, b"Hello").unwrap(), encrypted);
}
