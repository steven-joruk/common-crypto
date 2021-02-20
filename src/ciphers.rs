use crate::Algorithm;

/// Details about each cipher so that you can create appropriately sized data
/// to pass to [CryptorBuilder](`crate::CryptorBuilder`) and
/// [Cryptor](`crate::Cryptor`).
pub trait Cipher: std::fmt::Debug {
    fn to_algorithm() -> Algorithm;
    fn block_size() -> usize;
    fn requires_iv() -> bool;
    fn min_key_size() -> usize;
    fn max_key_size() -> usize;
}

macro_rules! declare_cipher {
    ($name:ident, $algorithm:expr, $block_size:expr, $requires_iv:expr, $min_key:expr, $max_key:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl Cipher for $name {
            fn to_algorithm() -> Algorithm {
                $algorithm
            }

            fn block_size() -> usize {
                $block_size
            }

            fn requires_iv() -> bool {
                $requires_iv
            }

            fn min_key_size() -> usize {
                $min_key
            }

            fn max_key_size() -> usize {
                $max_key
            }
        }
    };
}

declare_cipher!(AES128, 0, 16, true, 16, 16);
declare_cipher!(AES192, 0, 16, true, 24, 24);
declare_cipher!(AES256, 0, 16, true, 32, 32);
declare_cipher!(DES, 1, 8, true, 8, 8);
declare_cipher!(TDES, 2, 8, true, 24, 24);
declare_cipher!(CAST, 3, 8, true, 5, 16);
declare_cipher!(RC4, 4, 1, false, 1, 512);
declare_cipher!(RC2, 5, 8, true, 1, 128);
declare_cipher!(Blowfish, 6, 8, true, 8, 56);
