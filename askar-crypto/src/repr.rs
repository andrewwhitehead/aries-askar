//! Traits for exposing key data representations

#[cfg(feature = "alloc")]
use crate::buffer::SecretVec;
use crate::{
    buffer::{WriteBuffer, Writer},
    error::Error,
};

/// Access public bytes of key or other buffer.
pub trait PublicBytesCore {
    /// Length of the public byte representation.
    const PUBLIC_BYTES_LEN: usize;

    /// Access a temporary slice of the key public bytes, if any.
    fn access_public_bytes(&self, f: impl FnOnce(&[u8]) -> Result<(), Error>) -> Result<(), Error>;
}

/// Create a key or buffer from a public byte array.
pub trait FromPublicBytes: PublicBytesCore + Sized {
    /// Create a new instance from a slice of public bytes.
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error>;
}

/// Object-safe access to public key data.
pub trait ToPublicBytes {
    /// Get the length of the public byte representation.
    fn public_bytes_len(&self) -> usize;

    /// Copy the bytes to a mutable array.
    fn copy_public_bytes<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let mut w = Writer::from_slice(buf);
        self.write_public_bytes(&mut w)?;
        Ok(w.into())
    }

    /// Write the bytes to a buffer.
    fn write_public_bytes(&self, buf: &mut dyn WriteBuffer) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    /// Write the key public bytes to a new allocated buffer.
    fn to_public_bytes(&self) -> Result<SecretVec, Error> {
        let mut buf = SecretVec::with_capacity(self.public_bytes_len());
        self.write_public_bytes(&mut buf)?;
        Ok(buf)
    }
}

impl<K: PublicBytesCore> ToPublicBytes for K {
    fn public_bytes_len(&self) -> usize {
        K::PUBLIC_BYTES_LEN
    }

    fn write_public_bytes(&self, out: &mut dyn WriteBuffer) -> Result<(), Error> {
        self.access_public_bytes(|data| out.buffer_write(data))
    }
}

/// Access secret bytes of key or other buffer.
pub trait SecretBytesCore {
    /// Length of the secret bytes.
    const SECRET_BYTES_LEN: usize;

    /// Access a temporary slice of the secret bytes, if any.
    fn access_secret_bytes<O>(&self, f: impl FnOnce(&[u8]) -> Result<O, Error>)
        -> Result<O, Error>;
}

/// Create a key or buffer from a secret byte array.
pub trait FromSecretBytes: SecretBytesCore + Sized {
    /// Create a new instance from a slice of secret key bytes.
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error>;
}

/// Object-safe access to secret byte data.
pub trait ToSecretBytes {
    /// Get the length of the secret byte representation.
    fn secret_bytes_len(&self) -> usize;

    /// Copy the bytes to a mutable array.
    fn copy_secret_bytes<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let mut w = Writer::from_slice(buf);
        self.write_secret_bytes(&mut w)?;
        Ok(w.into())
    }

    /// Write the bytes to a buffer.
    fn write_secret_bytes(&self, buf: &mut dyn WriteBuffer) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    /// Write the key secret bytes to a new allocated buffer.
    fn to_secret_bytes(&self) -> Result<SecretVec, Error> {
        let mut buf = SecretVec::with_capacity(self.secret_bytes_len());
        self.write_secret_bytes(&mut buf)?;
        Ok(buf)
    }
}

impl<K: SecretBytesCore> ToSecretBytes for K {
    fn secret_bytes_len(&self) -> usize {
        K::SECRET_BYTES_LEN
    }

    fn write_secret_bytes(&self, out: &mut dyn WriteBuffer) -> Result<(), Error> {
        self.access_secret_bytes(|data| out.buffer_write(data))
    }
}
