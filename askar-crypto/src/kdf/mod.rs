//! Key derivation function traits and implementations

use core::fmt::Debug;

#[cfg(feature = "alloc")]
use crate::buffer::SecretVec;
use crate::{
    buffer::{WriteBuffer, Writer},
    error::Error,
    key::Key,
    repr::SecretBytesCore,
};

#[cfg(feature = "argon2")]
#[cfg_attr(docsrs, doc(cfg(feature = "argon2")))]
pub mod argon2;

pub mod concat;

pub mod ecdh_1pu;

pub mod ecdh_es;

/// Key exchange trait for concrete key types.
pub trait KeyExchangeCore: 'static {
    /// The result of a key exchange.
    type ExchangeKey: Debug + SecretBytesCore;

    /// Perform a key exchange between this keypair and a public key.
    fn key_exchange(&self, public: &Self) -> Result<Self::ExchangeKey, Error>;

    /// Access the bytes of a key exchange key.
    fn access_key_exchange_bytes(
        &self,
        public: &Self,
        f: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let kex = self.key_exchange(public)?;
        kex.access_secret_bytes(f)
    }
}

/// Object-safe trait for key exchanges.
pub trait KeyExchange {
    /// Get the length of a key exchange key.
    fn key_exchange_bytes_len(&self) -> usize;

    /// Copy the bytes from a key exchange key.
    fn copy_key_exchange_bytes<'a>(
        &self,
        other: &dyn Key,
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let mut w = Writer::from_slice(buf);
        self.write_key_exchange_bytes(other, &mut w)?;
        Ok(w.into())
    }

    /// Write the bytes from a key exchange key to a buffer.
    fn write_key_exchange_bytes(
        &self,
        other: &dyn Key,
        buf: &mut dyn WriteBuffer,
    ) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    /// Get a key exchange key as an allocated buffer.
    fn key_exchange_bytes(&self, other: &dyn Key) -> Result<SecretVec, Error> {
        let mut bs = SecretVec::with_capacity(self.key_exchange_bytes_len());
        self.write_key_exchange_bytes(other, &mut bs)?;
        Ok(bs)
    }
}

impl<K: KeyExchangeCore> KeyExchange for K {
    fn key_exchange_bytes_len(&self) -> usize {
        K::ExchangeKey::SECRET_BYTES_LEN
    }

    fn write_key_exchange_bytes(
        &self,
        other: &dyn Key,
        buf: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        if let Some(other) = other.as_any().downcast_ref() {
            Self::access_key_exchange_bytes(self, other, |bs| buf.buffer_write(bs))
        } else {
            Err(err_msg!(Unsupported))
        }
    }
}
