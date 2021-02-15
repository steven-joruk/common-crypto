use common_crypto::*;

#[test]
fn small_keys() {
    fn test_min_key_size<T>()
    where
        T: Cipher,
    {
        let mut key = Vec::new();

        key.resize(T::min_key_size(), 0);
        CryptorBuilder::<T>::new(Mode::ECB, &key)
            .encryptor()
            .unwrap();

        key.resize(T::min_key_size() - 1, 0);
        assert_eq!(
            CryptorBuilder::<T>::new(Mode::ECB, &key)
                .encryptor()
                .unwrap_err(),
            CryptorError::KeySize
        );
    }

    test_min_key_size::<AES128>();
    test_min_key_size::<AES192>();
    test_min_key_size::<AES256>();
    test_min_key_size::<DES>();
    test_min_key_size::<TDES>();
    test_min_key_size::<RC4>();
    test_min_key_size::<RC2>();
    test_min_key_size::<Blowfish>();
}

#[test]
fn big_keys() {
    fn test_max_key_size<T>()
    where
        T: Cipher,
    {
        let mut key = Vec::new();

        key.resize(T::max_key_size(), 0);
        CryptorBuilder::<T>::new(Mode::ECB, &key)
            .encryptor()
            .unwrap();

        key.resize(T::max_key_size() + 1, 0);
        assert_eq!(
            CryptorBuilder::<T>::new(Mode::ECB, &key)
                .encryptor()
                .unwrap_err(),
            CryptorError::KeySize
        );
    }

    test_max_key_size::<AES128>();
    test_max_key_size::<AES192>();
    test_max_key_size::<AES256>();
    test_max_key_size::<DES>();
    test_max_key_size::<TDES>();
    test_max_key_size::<RC4>();
    test_max_key_size::<RC2>();
    test_max_key_size::<Blowfish>();
}

#[test]
fn small_buffer_is_increased() {
    let c = CryptorBuilder::<RC4>::new(Mode::CBC, b"Key")
        .encryptor()
        .unwrap();

    c.update(b"Hey", &mut Vec::new()).unwrap();
}

#[test]
fn rc4_ecb_encrypt() {
    let encryptor = CryptorBuilder::<RC4>::new(Mode::ECB, b"Key")
        .encryptor()
        .unwrap();

    let mut encrypted = Vec::new();
    encryptor.update(b"Plaintext", &mut encrypted).unwrap();

    assert_eq!(
        encrypted,
        &[0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
    );
}

#[test]
fn aes256_round_trip() {
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
}

#[test]
fn iv_is_used() {
    let mut first = Vec::new();
    CryptorBuilder::<AES128>::new(Mode::CTR, b"1234123412341234")
        .iv(b"use random iv :)")
        .pkcs7_padding()
        .encryptor()
        .unwrap()
        .update(b"Hello", &mut first)
        .unwrap();

    assert!(!first.is_empty());

    let mut second = Vec::new();
    CryptorBuilder::<AES128>::new(Mode::CTR, b"1234123412341234")
        .iv(b"one per key pls!")
        .pkcs7_padding()
        .encryptor()
        .unwrap()
        .update(b"Hello", &mut second)
        .unwrap();

    assert_ne!(first, second);
}

#[test]
fn rc4_iv_unsupported() {
    assert_eq!(
        CryptorBuilder::<RC4>::new(Mode::CBC, b"Key")
            .iv(b"1")
            .encryptor()
            .unwrap_err(),
        CryptorError::InitializationVectorPresent
    );
}

#[test]
fn ecb_iv_unsupported() {
    assert_eq!(
        CryptorBuilder::<AES128>::new(Mode::ECB, b"Key")
            .iv(b"1")
            .encryptor()
            .unwrap_err(),
        CryptorError::InitializationVectorPresent
    );
}

#[test]
fn iv_required() {
    fn test_requires_iv<T>()
    where
        T: Cipher,
    {
        let mut iv = Vec::new();
        let mut key = Vec::new();
        key.resize(T::max_key_size(), 1);

        iv.resize(T::block_size(), 1);
        CryptorBuilder::<T>::new(Mode::CBC, &key)
            .iv(&iv)
            .encryptor()
            .unwrap();

        iv.resize(T::block_size() + 1, b'A');
        assert_eq!(
            CryptorBuilder::<T>::new(Mode::CBC, &key)
                .iv(&iv)
                .encryptor()
                .unwrap_err(),
            CryptorError::InitializationVectorSize
        );

        iv.resize(T::block_size() - 1, 1);
        assert_eq!(
            CryptorBuilder::<T>::new(Mode::CBC, &key)
                .iv(&iv)
                .encryptor()
                .unwrap_err(),
            CryptorError::InitializationVectorSize
        );
    }

    test_requires_iv::<AES128>();
    test_requires_iv::<AES192>();
    test_requires_iv::<AES256>();
    test_requires_iv::<DES>();
    test_requires_iv::<TDES>();
    test_requires_iv::<RC2>();
    test_requires_iv::<Blowfish>();
}

#[test]
fn resetting_iv_required() {
    let encryptor = CryptorBuilder::<AES128>::new(Mode::CBC, b"1234123412341234")
        .iv(b"1234123412341234")
        .encryptor()
        .unwrap();

    let mut output = Vec::new();
    let finished_encryptor = encryptor.finish(&mut output).unwrap();
    let encryptor = finished_encryptor.reset(Some(b"4321432143214321")).unwrap();

    let finished_encryptor = encryptor.finish(&mut output).unwrap();
    assert_eq!(
        finished_encryptor.reset(Some(b"too small")).unwrap_err(),
        CryptorError::InitializationVectorSize
    );

    let encryptor = CryptorBuilder::<AES128>::new(Mode::CBC, b"1234123412341234")
        .iv(b"1234123412341234")
        .encryptor()
        .unwrap();
    let finished_encryptor = encryptor.finish(&mut output).unwrap();
    assert_eq!(
        finished_encryptor.reset(None).unwrap_err(),
        CryptorError::InitializationVectorMissing
    );
}

#[test]
fn resetting_iv_unsupportde() {
    let encryptor = CryptorBuilder::<AES128>::new(Mode::ECB, b"1234123412341234")
        .encryptor()
        .unwrap();

    let mut output = Vec::new();
    let finished_encryptor = encryptor.finish(&mut output).unwrap();
    assert_eq!(
        finished_encryptor
            .reset(Some(b"4321432143214321"))
            .unwrap_err(),
        CryptorError::InitializationVectorPresent
    );
}
