use std::ffi::c_void;

pub struct Hash;

macro_rules! implement_hash {
    ($func:ident, $struct:ident, $ctx:ident, $one_shot:ident, $init:ident, $update:ident, $final:ident, $len:expr) => {
        extern "C" {
            fn $one_shot(data: *const c_void, len: i32, output: *mut u8) -> *mut u8;
            fn $init(ctx: *mut $ctx) -> i32;
            fn $update(ctx: *mut $ctx, data: *const c_void, len: i32) -> i32;
            fn $final(output: *mut c_void, ctx: *mut $ctx) -> i32;
        }

        impl Hash {
            pub fn $func(data: impl AsRef<[u8]>) -> [u8; $len] {
                let mut output = [0u8; $len];

                unsafe {
                    $one_shot(
                        data.as_ref().as_ptr() as *const c_void,
                        data.as_ref().len() as i32,
                        output.as_mut_ptr(),
                    );
                }

                output
            }
        }

        pub struct $struct {
            ctx: $ctx,
        }

        impl $struct {
            pub fn new() -> Self {
                let mut ctx = $ctx::default();

                unsafe {
                    $init(&mut ctx);
                }

                Self { ctx }
            }

            pub fn update(&mut self, data: impl AsRef<[u8]>) {
                unsafe {
                    $update(
                        &mut self.ctx,
                        data.as_ref().as_ptr() as *const c_void,
                        data.as_ref().len() as i32,
                    );
                }
            }

            pub fn finish(mut self) -> [u8; $len] {
                let mut output = [0u8; $len];
                unsafe { $final(output.as_mut_ptr() as *mut c_void, &mut self.ctx) };
                output
            }
        }
    };
}

#[repr(C)]
#[derive(Default)]
struct SHA1Context {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    nl: u32,
    nh: u32,
    data: [u32; 16],
    num: i32,
}
implement_hash!(
    sha1,
    SHA1,
    SHA1Context,
    CC_SHA1,
    CC_SHA1_Init,
    CC_SHA1_Update,
    CC_SHA1_Final,
    20
);

#[repr(C)]
#[derive(Default)]
struct SHA256Context {
    count: [u32; 2],
    hash: [u32; 8],
    wbuf: [u32; 16],
}

implement_hash!(
    sha224,
    SHA224,
    SHA256Context,
    CC_SHA224,
    CC_SHA224_Init,
    CC_SHA224_Update,
    CC_SHA224_Final,
    28
);

implement_hash!(
    sha256,
    SHA256,
    SHA256Context,
    CC_SHA256,
    CC_SHA256_Init,
    CC_SHA256_Update,
    CC_SHA256_Final,
    32
);

#[repr(C)]
#[derive(Default)]
struct SHA512Context {
    count: [u64; 2],
    hash: [u64; 8],
    wbuf: [u64; 16],
}

implement_hash!(
    sha384,
    SHA384,
    SHA512Context,
    CC_SHA384,
    CC_SHA384_Init,
    CC_SHA384_Update,
    CC_SHA384_Final,
    48
);

implement_hash!(
    sha512,
    SHA512,
    SHA512Context,
    CC_SHA512,
    CC_SHA512_Init,
    CC_SHA512_Update,
    CC_SHA512_Final,
    64
);

#[repr(C)]
#[derive(Default)]
struct MD2Context {
    num: i32,
    data: [u8; 16],
    cksm: [u32; 16],
    state: [u32; 16],
}

implement_hash!(
    md2,
    MD2,
    MD2Context,
    CC_MD2,
    CC_MD2_Init,
    CC_MD2_Update,
    CC_MD2_Final,
    16
);

#[repr(C)]
#[derive(Default)]
struct MD4Context {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    nl: u32,
    nh: u32,
    data: [u32; 16],
    num: i32,
}

implement_hash!(
    md4,
    MD4,
    MD4Context,
    CC_MD4,
    CC_MD4_Init,
    CC_MD4_Update,
    CC_MD4_Final,
    16
);

#[repr(C)]
#[derive(Default)]
struct MD5Context {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    nl: u32,
    nh: u32,
    data: [u32; 16],
    num: i32,
}

implement_hash!(
    md5,
    MD5,
    MD5Context,
    CC_MD5,
    CC_MD5_Init,
    CC_MD5_Update,
    CC_MD5_Final,
    16
);
