use common_crypto::hmac::*;

#[test]
fn sha1() {
    assert_eq!(
        &Hmac::sha1(b"123", b"abc")[..],
        &hex::decode("540b0c53d4925837bd92b3f71abe7a9d70b676c4").unwrap()
    );
}

#[test]
fn md5() {
    assert_eq!(
        &Hmac::md5(b"123", b"abc")[..],
        &hex::decode("ffb7c0fc166f7ca075dfa04d59aed232").unwrap()
    );
}

#[test]
fn sha224() {
    assert_eq!(
        &Hmac::sha224(b"123", b"abc")[..],
        &hex::decode("dcc62feedb358eacbef83bc56d756663c2d504ce9e20431972433c6e").unwrap()
    );
}

#[test]
fn sha256() {
    assert_eq!(
        &Hmac::sha256(b"123", b"abc")[..],
        &hex::decode("8f16771f9f8851b26f4d460fa17de93e2711c7e51337cb8a608a0f81e1c1b6ae").unwrap()
    );
}

#[test]
fn sha384() {
    assert_eq!(&Hmac::sha384(b"123", b"abc")[..], &hex::decode("e768b478e7798f6cf69627cbe59e8edc106d499722119beafb2ab1d959ef84c31b142e230ed3191ce55a0426bf59e797").unwrap());
}

#[test]
fn sha512() {
    assert_eq!(&Hmac::sha512(b"123", b"abc")[..], &hex::decode("58585acd673067f96bea32a1c57bf3fc3fd5a42678567e72d5cb0ab7f08ea41dcf3a41af96c53948e13184ae6fe6cd0b8b4193fc593dfb2693b00c2b0ee7a316").unwrap());
}
