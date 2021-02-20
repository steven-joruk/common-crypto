use std::{ffi::c_void, fmt::Display, marker::PhantomData};

#[repr(C)]
#[derive(Copy, Clone)]
enum Operation {
    Encrypt = 0,
    Decrypt = 1,
}

#[repr(u32)]
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Mode {
    ECB = 1,
    CBC = 2,
    CFB = 3,
    CTR = 4,
    // kCCModeF8		= 5,
    // kCCModeLRW		= 6,
    OFB = 7,
    XTS = 8,
    RC4 = 9,
    CFB8 = 10,
}

#[repr(u32)]
#[derive(Copy, Clone)]
enum Padding {
    None = 0,
    PKCS7 = 1,
}

type Algorithm = u32;
type CCCryptorRef = *mut c_void;

extern "C" {
    fn CCCryptorCreateWithMode(
        operation: Operation,
        mode: Mode,
        algorithm: Algorithm,
        padding: Padding,
        iv: *const c_void,
        key: *const c_void,
        key_length: usize,
        tweak: *const c_void,
        tweak_length: usize,
        rounds: usize,
        options: u32,
        handle: *mut CCCryptorRef,
    ) -> Status;

    /* TODO
        fn CCCrypt(
            operation: Operation,
            algorithm: Algorithm,
            options: u32,
            key: *const c_void,
            key_length: usize,
            iv: *const c_void,
            input: *const c_void,
            input_len: usize,
            output: *mut c_void,
            output_len: usize,
            handle: *mut CCCryptorRef,
            written: *mut usize,
        ) -> Status;
    */

    fn CCCryptorRelease(handle: CCCryptorRef) -> Status;

    fn CCCryptorUpdate(
        handle: CCCryptorRef,
        input: *const c_void,
        input_len: usize,
        output: *mut c_void,
        output_len: usize,
        written: *mut usize,
    ) -> Status;

    fn CCCryptorFinal(
        handle: CCCryptorRef,
        output: *mut c_void,
        output_len: usize,
        written: *mut usize,
    ) -> Status;

    fn CCCryptorReset(handle: CCCryptorRef, iv: *const c_void) -> Status;

    fn CCCryptorGetOutputLength(handle: CCCryptorRef, input_len: usize, finishing: bool) -> usize;
}

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum CryptorError {
    Param,
    Memory,
    Alignment,
    Decode,
    Unimplemented,
    RNGFailure,
    Unspecified,
    CallSequence,
    KeySize,
    Key,
    InitializationVectorMissing,
    InitializationVectorPresent,
    InitializationVectorSize,
    Unexpected(i32),
}

impl std::error::Error for CryptorError {}

impl Display for CryptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Param => "illegal parameter value",
            Self::Memory => "memory allocation failed",
            Self::Alignment => "input size was nit aligned properly",
            Self::Decode => "input data did not encode or decrypt properly",
            Self::Unimplemented => "function not implemented for the current algorithm",
            Self::RNGFailure => "random number generated failed",
            Self::Unspecified => "an unspecified failure occurred",
            Self::CallSequence => "call sequence failure",
            Self::KeySize => "key size is invalid",
            Self::Key => "key is invalid",
            Self::InitializationVectorPresent => "ECB mode does not support initialization vectors",
            Self::InitializationVectorMissing => "the mode used requires an initialization vector",
            Self::InitializationVectorSize => {
                "the initialization vector provided is the incorrect size"
            }
            Self::Unexpected(code) => {
                let s = format!("unexpected error {}", code);
                return f.write_str(&s);
            }
        };

        f.write_str(s)
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(i32)]
enum Status {
    Success = 0,
    ParamError = -4300,
    BufferTooSmall = -4301,
    MemoryFailure = -4302,
    AlignmentError = -4303,
    DecodeError = -4304,
    Unimplemented = -4305,
    Overflow = -4306,
    RNGFailure = -4307,
    UnspecifiedError = -4308,
    CallSequenceError = -4309,
    KeySizeError = -4310,
    InvalidKey = -4311,
}

impl Into<CryptorError> for Status {
    fn into(self) -> CryptorError {
        match self {
            Status::Success => unreachable!(),
            Status::ParamError => CryptorError::Param,
            Status::MemoryFailure => CryptorError::Memory,
            Status::AlignmentError => CryptorError::Alignment,
            Status::DecodeError => CryptorError::Decode,
            Status::Unimplemented => CryptorError::Unimplemented,
            Status::RNGFailure => CryptorError::RNGFailure,
            Status::UnspecifiedError => CryptorError::Unspecified,
            Status::CallSequenceError => CryptorError::CallSequence,
            Status::KeySizeError => CryptorError::KeySize,
            Status::InvalidKey => CryptorError::Key,
            _ => CryptorError::Unexpected(self as i32),
        }
    }
}

/// Details about each cipher so that you can create appropriately sized data
/// to pass to [CryptorBuilder](`crate::cryptor::CryptorBuilder`) and
/// [Cryptor](`crate::cryptor::Cryptor`).
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

/// A way to conveniently build a [`Cryptor`].
///
/// ```
/// # use common_crypto::cryptor::{AES256, CryptorBuilder, Mode};
/// let encryptor = CryptorBuilder::<AES256>::new(Mode::CTR, b"0123456789abcdef")
///     .pkcs7_padding()
///     .iv(b"use random iv :)")
///     .encryptor()
///     .unwrap();
/// ```
pub struct CryptorBuilder<'a, T> {
    key: &'a [u8],
    padding: Padding,
    rounds: usize,
    mode: Mode,
    iv: Option<&'a [u8]>,
    _private: PhantomData<T>,
}

impl<'a, T> CryptorBuilder<'a, T>
where
    T: Cipher,
{
    /// Begins building a new [`Cryptor`]. The required key length can be found
    /// using [`Cipher::min_key_size`] and [`Cipher::max_key_size`].
    ///
    /// All Ciphers other than [`RC4`] require an [`CryptorBuilder::iv`] to be
    /// set, which differs in behaviour than the underlying `CCCryptor`
    /// behaviour.
    pub fn new(mode: Mode, key: &'a [u8]) -> Self {
        CryptorBuilder {
            key,
            padding: Padding::None,
            rounds: 0,
            mode,
            iv: None,
            _private: PhantomData,
        }
    }

    /// Builds the [`Cryptor`] configured for encrypting.
    pub fn encryptor(self) -> Result<Cryptor<T>, CryptorError> {
        self.build(Operation::Encrypt)
    }

    /// Builds the [`Cryptor`] configured for decrypting.
    pub fn decryptor(self) -> Result<Cryptor<T>, CryptorError> {
        self.build(Operation::Decrypt)
    }

    /// Enables PKCS#7 padding.
    pub fn pkcs7_padding(mut self) -> Self {
        self.padding = Padding::PKCS7;
        self
    }

    /// If you're certain you'd like to bypass using an iv for ciphers which
    /// suport it, you can provide a an appropriately sized buffer initialised
    /// with zeroes.
    pub fn iv(mut self, iv: &'a [u8]) -> Self {
        self.iv = Some(iv);
        self
    }

    /// Sets the number of rounds of encryption to use for ciphers which support
    /// it.
    // TODO: Which support it? Is it incorrect to use rounds for any of the
    // ciphers?
    pub fn rounds(mut self, rounds: usize) -> Self {
        self.rounds = rounds;
        self
    }

    fn build(self, operation: Operation) -> Result<Cryptor<T>, CryptorError> {
        let mut handle: CCCryptorRef = std::ptr::null_mut();
        let iv_ptr = iv_ptr_if_required::<T>(&self.iv, self.mode)?;

        let status = unsafe {
            CCCryptorCreateWithMode(
                operation,
                self.mode,
                T::to_algorithm(),
                self.padding,
                iv_ptr as *const c_void,
                self.key.as_ptr() as *const c_void,
                self.key.len(),
                // TODO: tweak
                std::ptr::null(),
                0,
                self.rounds,
                0,
                &mut handle as *mut *mut c_void,
            )
        };

        if status != Status::Success {
            return Err(status.into());
        }

        Ok(Cryptor {
            handle,
            mode: self.mode,
            _private: PhantomData,
        })
    }
}

fn iv_ptr_if_required<T>(iv: &Option<&[u8]>, mode: Mode) -> Result<*const u8, CryptorError>
where
    T: Cipher,
{
    let iv_ptr = match iv {
        Some(iv) => {
            if mode == Mode::ECB || !T::requires_iv() {
                return Err(CryptorError::InitializationVectorPresent);
            }

            if T::block_size() != iv.len() {
                return Err(CryptorError::InitializationVectorSize);
            }

            iv.as_ptr()
        }
        None => {
            if mode != Mode::ECB && T::requires_iv() {
                return Err(CryptorError::InitializationVectorMissing);
            }

            std::ptr::null()
        }
    };

    Ok(iv_ptr)
}

/// A cryptor supporting all of the block and stream ciphers provided by the
/// common crypto library.
#[derive(Debug)]
pub struct Cryptor<T> {
    handle: CCCryptorRef,
    mode: Mode,
    _private: PhantomData<T>,
}

impl<T> Drop for Cryptor<T> {
    fn drop(&mut self) {
        unsafe {
            CCCryptorRelease(self.handle);
        }
    }
}

impl<T> Cryptor<T>
where
    T: Cipher,
{
    /// Encrypts the data and writes to the provided buffer. The buffer will
    /// be resized as required, and will be cleared on error.
    pub fn update(
        &self,
        input: impl AsRef<[u8]>,
        output: &mut Vec<u8>,
    ) -> Result<(), CryptorError> {
        let input = input.as_ref();
        let mut written = 0usize;

        output.resize(
            unsafe { CCCryptorGetOutputLength(self.handle, input.len(), false) },
            0,
        );

        let status = unsafe {
            CCCryptorUpdate(
                self.handle,
                input.as_ptr() as *const c_void,
                input.len(),
                output.as_mut_ptr() as *mut c_void,
                output.capacity(),
                &mut written as *mut usize,
            )
        };

        if status != Status::Success {
            output.clear();
            return Err(status.into());
        }

        output.resize(written, 0);

        Ok(())
    }

    /// Finalises the encryption, returning any remaining data where
    /// appropriate. The cryptor cannot be used again until it has been
    /// [`FinishedCryptor::reset`].
    pub fn finish(self, output: &mut Vec<u8>) -> Result<FinishedCryptor<T>, CryptorError> {
        let mut written = 0usize;

        let status = unsafe {
            CCCryptorFinal(
                self.handle,
                output.as_mut_ptr() as *mut c_void,
                output.capacity(),
                &mut written as *mut usize,
            )
        };

        if status != Status::Success {
            output.clear();
            return Err(status.into());
        }

        output.resize(written, 0);

        Ok(FinishedCryptor { inner: self })
    }

    fn reset(&self, new_iv: Option<&[u8]>) -> Result<(), CryptorError> {
        let iv_ptr = iv_ptr_if_required::<T>(&new_iv, self.mode)?;

        let status = unsafe { CCCryptorReset(self.handle, iv_ptr as *const c_void) };

        if status != Status::Success {
            return Err(status.into());
        }

        Ok(())
    }
}

/// A [`Cryptor`] that has been finalised, and which can't be used again until
/// it has been reset.
pub struct FinishedCryptor<T> {
    inner: Cryptor<T>,
}

impl<T> FinishedCryptor<T>
where
    T: Cipher,
{
    /// Resets the state of the cryptor, allowing it to be reused. If you are
    /// using a cipher which requires an iv, you should now generate a new one
    /// if further encryption will be performed using the same key.
    pub fn reset(self, new_iv: Option<&[u8]>) -> Result<Cryptor<T>, CryptorError> {
        self.inner.reset(new_iv)?;
        Ok(self.inner)
    }
}
