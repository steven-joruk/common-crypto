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

#[repr(C)]
struct Context {
    ctx: [u32; 96],
}

impl Default for Context {
    fn default() -> Self {
        Self { ctx: [0u32; 96] }
    }
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

    fn CCHmacInit(ctx: *mut Context, algorithm: Algorithm, key: *const c_void, len: usize);

    fn CCHmacUpdate(ctx: *mut Context, data: *const c_void, len: usize);

    fn CCHmacFinal(ctx: *mut Context, output: *mut c_void);
}

pub struct HMAC;

impl HMAC {
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

macro_rules! implement_digest {
    ($func:ident, $algorithm:ident, $len:expr) => {
        impl HMAC {
            pub fn $func(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> [u8; $len] {
                let mut hash = [0u8; $len];

                Self::generate(
                    Algorithm::$algorithm,
                    key.as_ref(),
                    data.as_ref(),
                    &mut hash,
                );

                hash
            }
        }

        pub struct $algorithm {
            context: Context,
        }

        impl $algorithm {
            pub fn new(key: impl AsRef<[u8]>) -> Self {
                let mut context = Context::default();

                unsafe {
                    CCHmacInit(
                        &mut context,
                        Algorithm::$algorithm,
                        key.as_ref().as_ptr() as *const c_void,
                        key.as_ref().len(),
                    );
                }

                Self { context }
            }

            pub fn update(&mut self, data: impl AsRef<[u8]>) {
                unsafe {
                    CCHmacUpdate(
                        &mut self.context,
                        data.as_ref().as_ptr() as *const c_void,
                        data.as_ref().len(),
                    );
                }
            }

            pub fn finish(mut self) -> [u8; $len] {
                let mut output = [0u8; $len];

                unsafe {
                    CCHmacFinal(&mut self.context, output.as_mut_ptr() as *mut c_void);
                }

                output
            }
        }
    };
}

implement_digest!(md5, MD5, 16);
implement_digest!(sha1, SHA1, 20);
implement_digest!(sha224, SHA224, 28);
implement_digest!(sha256, SHA256, 32);
implement_digest!(sha384, SHA384, 48);
implement_digest!(sha512, SHA512, 64);
