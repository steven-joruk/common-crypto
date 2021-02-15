#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use std::ffi::c_void;

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(i32)]
#[non_exhaustive]
pub enum Status {
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

#[repr(C)]
#[non_exhaustive]
#[derive(Copy, Clone)]
pub enum Operation {
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
#[non_exhaustive]
#[derive(Copy, Clone)]
pub enum Padding {
    None = 0,
    PKCS7 = 1,
}

pub type Algorithm = u32;
pub type CCCryptorRef = *mut c_void;

extern "C" {
    pub fn CCCryptorCreateWithMode(
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

    pub fn CCCrypt(
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

    pub fn CCCryptorRelease(handle: CCCryptorRef) -> Status;

    pub fn CCCryptorUpdate(
        handle: CCCryptorRef,
        input: *const c_void,
        input_len: usize,
        output: *mut c_void,
        output_len: usize,
        written: *mut usize,
    ) -> Status;

    pub fn CCCryptorFinal(
        handle: CCCryptorRef,
        output: *mut c_void,
        output_len: usize,
        written: *mut usize,
    ) -> Status;

    pub fn CCCryptorReset(handle: CCCryptorRef, iv: *const c_void) -> Status;

    pub fn CCCryptorGetOutputLength(
        handle: CCCryptorRef,
        input_len: usize,
        finishing: bool,
    ) -> usize;
}
