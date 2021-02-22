use common_crypto::hmac::*;

macro_rules! implement_test {
    ($func_name:ident, $algorithm:ident, $result:expr) => {
        #[test]
        fn $func_name() {
            assert_eq!(
                &HMAC::$func_name(b"123", b"abc")[..],
                &hex::decode($result).unwrap()
            );

            let mut hmac = $algorithm::new(b"123");
            hmac.update(b"a");
            hmac.update(b"b");
            hmac.update(b"c");
            assert_eq!(&hmac.finish()[..], &hex::decode($result).unwrap());
        }
    };
}

implement_test!(sha1, SHA1, "540b0c53d4925837bd92b3f71abe7a9d70b676c4");

implement_test!(md5, MD5, "ffb7c0fc166f7ca075dfa04d59aed232");

implement_test!(
    sha224,
    SHA224,
    "dcc62feedb358eacbef83bc56d756663c2d504ce9e20431972433c6e"
);

implement_test!(
    sha256,
    SHA256,
    "8f16771f9f8851b26f4d460fa17de93e2711c7e51337cb8a608a0f81e1c1b6ae"
);

implement_test!(
    sha384,
    SHA384,
    "e768b478e7798f6cf69627cbe59e8edc106d499722119beafb2ab1d959ef84c31b142e230ed3191ce55a0426bf59e797"
);

implement_test!(
    sha512,
    SHA512,
    "58585acd673067f96bea32a1c57bf3fc3fd5a42678567e72d5cb0ab7f08ea41dcf3a41af96c53948e13184ae6fe6cd0b8b4193fc593dfb2693b00c2b0ee7a316"
);
