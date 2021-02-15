use std::fmt::Display;

use crate::sys::Status;

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
