// TODO: Note that Apple's implementation will malloc/copy keys to an aligned
// buffer if necessary.

// TODO: enum of all algorithms so that we can force iv, padding, etc. to be
// provided if required.

use std::{ffi::c_void, fmt::Display};

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
    // F8 = 5,
    // LRW = 6,
    OFB = 7,
    XTS = 8,
    /// Must be specified for RC4, and must not be specified for others.
    // RC4 = 9,
    CFB8 = 10,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Padding {
    None = 0,
    PKCS7 = 1,
}

type CCCryptorRef = *mut c_void;

extern "C" {
    fn CCCryptorCreateWithMode(
        operation: Operation,
        mode: u32,
        config: u32,
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
    InitializationVectorPresent,
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

impl From<Status> for CryptorError {
    fn from(status: Status) -> Self {
        match status {
            Status::ParamError => Self::Param,
            Status::MemoryFailure => Self::Memory,
            Status::AlignmentError => Self::Alignment,
            Status::DecodeError => Self::Decode,
            Status::Unimplemented => Self::Unimplemented,
            Status::RNGFailure => Self::RNGFailure,
            Status::UnspecifiedError => Self::Unspecified,
            Status::CallSequenceError => Self::CallSequence,
            Status::KeySizeError => Self::KeySize,
            Status::InvalidKey => Self::Key,
            _ => Self::Unexpected(status as i32),
        }
    }
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
/// The configuration for a [`Cryptor`].
///
/// ```
/// # use common_crypto::cryptor::{Config, Mode};
/// let config = Config::AES256 {
///     mode: Mode::CTR,
///     iv: Some(b"use random iv :)"),
///     key: b"aes128 key must be 32 bytes long",
/// };
/// ```
// TODO: padding, rounds
pub enum Config<'a> {
    AES128 {
        mode: Mode,
        iv: Option<&'a [u8; 16]>,
        key: &'a [u8; 16],
    },
    AES192 {
        mode: Mode,
        iv: Option<&'a [u8; 16]>,
        key: &'a [u8; 24],
    },
    AES256 {
        mode: Mode,
        iv: Option<&'a [u8; 16]>,
        key: &'a [u8; 32],
    },
    DES {
        mode: Mode,
        iv: Option<&'a [u8; 8]>,
        key: &'a [u8; 8],
    },
    TDES {
        mode: Mode,
        iv: Option<&'a [u8; 8]>,
        key: &'a [u8; 24],
    },
    CAST {
        mode: Mode,
        iv: Option<&'a [u8; 8]>,
        /// Valid key sizes are between 5 and 24.
        key: &'a [u8],
        padding: Padding,
    },
    RC4 {
        /// Valid key sizes are between 1 and 512.
        key: &'a [u8],
    },
    RC2 {
        mode: Mode,
        iv: Option<&'a [u8; 8]>,
        /// Valid key sizes are between 1 and 128.
        key: &'a [u8],
    },
    Blowfish {
        mode: Mode,
        iv: Option<&'a [u8; 8]>,
        /// Valid key sizes are between 8 and 56.
        key: &'a [u8],
    },
}

impl<'a> From<&Config<'a>> for u32 {
    fn from(config: &Config) -> Self {
        match config {
            Config::AES128 { .. } => 0,
            Config::AES192 { .. } => 0,
            Config::AES256 { .. } => 0,
            Config::DES { .. } => 1,
            Config::TDES { .. } => 2,
            Config::CAST { .. } => 3,
            Config::RC4 { .. } => 4,
            Config::RC2 { .. } => 5,
            Config::Blowfish { .. } => 6,
        }
    }
}

impl<'a> Config<'a> {
    fn padding(&self) -> Padding {
        match self {
            Config::CAST { padding, .. } => *padding,
            _ => Padding::None,
        }
    }

    fn rounds(&self) -> usize {
        0
    }

    const fn mode(&self) -> u32 {
        match self {
            Config::AES128 { mode, .. } => *mode as u32,
            Config::AES192 { mode, .. } => *mode as u32,
            Config::AES256 { mode, .. } => *mode as u32,
            Config::DES { mode, .. } => *mode as u32,
            Config::TDES { mode, .. } => *mode as u32,
            Config::CAST { mode, .. } => *mode as u32,
            Config::RC4 { .. } => 9,
            Config::RC2 { mode, .. } => *mode as u32,
            Config::Blowfish { mode, .. } => *mode as u32,
        }
    }

    fn iv_ptr(&self) -> Result<*const u8, CryptorError> {
        let (mode, ptr) = match self {
            Config::AES128 { mode, iv, .. } if iv.is_some() => (mode, iv.unwrap().as_ptr()),
            Config::AES192 { mode, iv, .. } if iv.is_some() => (mode, iv.unwrap().as_ptr()),
            Config::AES256 { mode, iv, .. } if iv.is_some() => (mode, iv.unwrap().as_ptr()),
            Config::DES { mode, iv, .. } if iv.is_some() => (mode, iv.unwrap().as_ptr()),
            Config::CAST { mode, iv, .. } if iv.is_some() => (mode, iv.unwrap().as_ptr()),
            Config::RC2 { mode, iv, .. } if iv.is_some() => (mode, iv.unwrap().as_ptr()),
            Config::Blowfish { mode, iv, .. } if iv.is_some() => (mode, iv.unwrap().as_ptr()),
            _ => return Ok(std::ptr::null()),
        };

        if mode == &Mode::ECB {
            Err(CryptorError::InitializationVectorPresent)
        } else {
            Ok(ptr)
        }
    }

    fn key(&self) -> &[u8] {
        match self {
            Config::AES128 { key, .. } => *key,
            Config::AES192 { key, .. } => *key,
            Config::AES256 { key, .. } => *key,
            Config::DES { key, .. } => *key,
            Config::TDES { key, .. } => *key,
            Config::CAST { key, .. } => *key,
            Config::RC4 { key, .. } => *key,
            Config::RC2 { key, .. } => *key,
            Config::Blowfish { key, .. } => *key,
        }
    }
}

/// A cryptor supporting all of the block and stream ciphers provided by the
/// common crypto library.
///
/// ```
/// # use common_crypto::cryptor::{Config, Cryptor};
/// let config = Config::RC4 { key: b"Key" };
/// assert_eq!(
///     Cryptor::encrypt(&config, b"Plaintext").unwrap(),
///     &[0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
/// );
/// ```

#[derive(Debug)]
pub struct Cryptor {
    handle: CCCryptorRef,
}

impl<'a> Drop for Cryptor {
    fn drop(&mut self) {
        unsafe {
            CCCryptorRelease(self.handle);
        }
    }
}

impl Cryptor {
    fn new(config: &Config<'_>, operation: Operation) -> Result<Cryptor, CryptorError> {
        let mut handle: CCCryptorRef = std::ptr::null_mut();

        let status = unsafe {
            CCCryptorCreateWithMode(
                operation,
                config.mode(),
                config.into(),
                config.padding(),
                config.iv_ptr()? as *const c_void,
                config.key().as_ptr() as *const c_void,
                config.key().len(),
                // Tweak is unsued
                std::ptr::null(),
                0,
                config.rounds(),
                0,
                &mut handle as *mut *mut c_void,
            )
        };

        if status != Status::Success {
            return Err(status.into());
        }

        Ok(Cryptor { handle })
    }

    pub fn new_encryptor(config: &Config<'_>) -> Result<Self, CryptorError> {
        Self::new(config, Operation::Encrypt)
    }

    pub fn new_decryptor(config: &Config<'_>) -> Result<Self, CryptorError> {
        Self::new(config, Operation::Decrypt)
    }

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
    /// appropriate. The cryptor cannot be used again.
    pub fn finish(self, output: &mut Vec<u8>) -> Result<(), CryptorError> {
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

        Ok(())
    }
}

impl Cryptor {
    pub fn encrypt(config: &Config<'_>, input: impl AsRef<[u8]>) -> Result<Vec<u8>, CryptorError> {
        let mut output = Vec::new();
        Cryptor::new_encryptor(config)?.update(input, &mut output)?;
        Ok(output)
    }

    pub fn decrypt(config: &Config<'_>, input: impl AsRef<[u8]>) -> Result<Vec<u8>, CryptorError> {
        let mut output = Vec::new();
        Cryptor::new_decryptor(config)?.update(input, &mut output)?;
        Ok(output)
    }
}
