//! Cryptography primitives and operations for aries-askar.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    unsafe_code
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

#[macro_use]
mod error;
pub use self::error::{Error, ErrorKind};

// re-export
pub use aead::generic_array;

pub mod alg;

pub mod buffer;

pub mod encrypt;

pub mod jwk;

pub mod kdf;

pub mod key;

pub mod random;

pub mod sign;

pub mod repr;
