//! Key encapsulation mechanisms (KEMs).
//!
//! Each concrete KEM is identified by a [`Kem`] value, which the caller selects
//! when encapsulating or decapsulating. Currently the supported KEMs are the
//! Diffie-Hellman based KEMs of RFC 9180, implemented in [`dhkem`].

use alloc::vec::Vec;
use core::str::FromStr;

use crate::{buffer::SecretBytes, error::Error};

pub mod dhkem;

use self::dhkem::DhKem;

/// The supported key encapsulation mechanisms. Each concrete KEM is a distinct
/// option, and the caller selects which one to apply to a key.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kem {
    /// A Diffie-Hellman based KEM
    DhKem(DhKem),
}

impl Kem {
    /// The canonical name of this KEM
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DhKem(k) => k.as_str(),
        }
    }
}

impl From<DhKem> for Kem {
    fn from(kem: DhKem) -> Self {
        Self::DhKem(kem)
    }
}

impl FromStr for Kem {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DhKem::from_str(s).map(Self::DhKem)
    }
}

/// The result of encapsulation
#[derive(Debug)]
pub struct Encapsulated {
    /// The encapsulated key (`enc`), to be sent to the recipient
    pub enc: Vec<u8>,
    /// The KEM shared secret
    pub shared_secret: SecretBytes,
}
