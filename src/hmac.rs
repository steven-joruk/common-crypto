use std::ffi::c_void;

#[repr(u32)]
enum Algorithm {
    SHA1,
    MD5,
    SHA256,
    SHA384,
    SHA512,
    SHA224,
}

extern "C" {
    fn CCHmac(
        algorithm: Algorithm,
        key: *const c_void,
        key_len: usize,
        data: *const c_void,
        data_len: usize,
        out: *mut c_void,
    );
}

pub struct Hmac;

impl Hmac {
    fn generate(algorithm: Algorithm, key: &[u8], data: &[u8], hash: &mut [u8]) {
        unsafe {
            CCHmac(
                algorithm,
                key.as_ptr() as *const c_void,
                key.len(),
                data.as_ptr() as *const c_void,
                data.len(),
                hash.as_mut_ptr() as *mut c_void,
            )
        }
    }
}

macro_rules! declare_digest {
    ($name:ident, $algorithm:ident, $size:expr) => {
        impl Hmac {
            pub fn $name(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> [u8; $size] {
                let mut hash = [0u8; $size];
                Self::generate(
                    Algorithm::$algorithm,
                    key.as_ref(),
                    data.as_ref(),
                    &mut hash,
                );
                hash
            }
        }
    };
}

declare_digest!(md5, MD5, 16);
declare_digest!(sha1, SHA1, 20);
declare_digest!(sha224, SHA224, 28);
declare_digest!(sha256, SHA256, 32);
declare_digest!(sha384, SHA384, 48);
declare_digest!(sha512, SHA512, 64);
