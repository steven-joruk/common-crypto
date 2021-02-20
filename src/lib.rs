//! Rust bindings to Apple's Common Crypto library.
//!
//! The relevant Apple documentation is in the man pages, see `man CCCryptor`.

mod ciphers;
mod error;
mod sys;

use std::{ffi::c_void, marker::PhantomData};

pub use ciphers::{Blowfish, Cipher, AES128, AES192, AES256, CAST, DES, RC2, RC4, TDES};
pub use error::CryptorError;
pub use sys::{Algorithm, Mode};

use sys::*;

/// A way to conveniently build a [`Cryptor`].
///
/// ```
/// # use common_crypto::{AES256, CryptorBuilder, Mode};
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
