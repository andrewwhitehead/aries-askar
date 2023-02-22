//! Structures and traits for representing byte ranges in memory

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{fmt::Debug, ops::Range, panic::RefUnwindSafe};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::key::KeyGen;
use crate::repr::{FromSecretBytes, ToSecretBytes};

mod array;
pub use self::array::SecretArray;

mod hash;
pub use self::hash::HashBuffer;

#[cfg(feature = "alloc")]
mod vec;
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use self::vec::SecretVec;

mod string;
pub use self::string::HexRepr;

mod writer;
pub use self::writer::Writer;

/// Support for writing to a byte buffer
pub trait WriteBuffer: Debug {
    /// Append a slice to the buffer
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error>;
}

/// Support for writing to, accessing, and resizing a byte buffer
pub trait ResizeBuffer: WriteBuffer + AsRef<[u8]> + AsMut<[u8]> {
    /// Insert a slice at the given position in the buffer
    fn buffer_insert(&mut self, pos: usize, data: &[u8]) -> Result<(), Error>;

    /// Remove an exclusive range from the buffer
    fn buffer_remove(&mut self, range: Range<usize>) -> Result<(), Error>;

    /// Resize the buffer, truncating or padding it with zeroes
    fn buffer_resize(&mut self, len: usize) -> Result<(), Error>;

    /// Extend the buffer with `len` bytes of zeroes and return
    /// a mutable reference to the slice
    fn buffer_extend(&mut self, len: usize) -> Result<&mut [u8], Error> {
        let pos = self.as_ref().len();
        let end = pos + len;
        self.buffer_resize(end)?;
        Ok(&mut self.as_mut()[pos..end])
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl WriteBuffer for Vec<u8> {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.extend_from_slice(data);
        Ok(())
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl ResizeBuffer for Vec<u8> {
    fn buffer_insert(&mut self, pos: usize, data: &[u8]) -> Result<(), Error> {
        self.splice(pos..pos, data.iter().cloned());
        Ok(())
    }

    fn buffer_remove(&mut self, range: Range<usize>) -> Result<(), Error> {
        self.drain(range);
        Ok(())
    }

    fn buffer_resize(&mut self, len: usize) -> Result<(), Error> {
        self.resize(len, 0u8);
        Ok(())
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn test_write_buffer<B: WriteBuffer + AsRef<[u8]>>(mut w: B) {
        w.buffer_write(b"he").unwrap();
        w.buffer_write(b"y").unwrap();
        assert_eq!(w.as_ref(), b"hey");
    }

    pub(crate) fn test_resize_buffer<B: ResizeBuffer>(mut w: B) {
        w.buffer_write(b"hello").unwrap();
        w.buffer_insert(1, b"world").unwrap();
        assert_eq!(w.as_ref(), b"hworldello");
        w.buffer_resize(12).unwrap();
        assert_eq!(w.as_ref(), b"hworldello\0\0");
        w.buffer_resize(6).unwrap();
        assert_eq!(w.as_ref(), b"hworld");
        w.buffer_insert(1, b"ello").unwrap();
        assert_eq!(w.as_ref(), b"helloworld");
    }

    #[test]
    fn write_buffer_vec() {
        test_write_buffer(Vec::new());
    }

    #[test]
    fn resize_buffer_vec() {
        test_resize_buffer(Vec::new());
    }
}

/// Core trait for fixed-size buffers
pub trait FixedBufferCore:
    Clone + Debug + KeyGen + PartialEq + Eq + RefUnwindSafe + Send + Sync + for<'a> TryFrom<&'a [u8]>
{
    /// The size of the buffer in bytes
    const SIZE: usize;

    /// Create a new buffer using an initializer for the data
    fn new_with(f: impl FnOnce(&mut [u8])) -> Self;

    /// Create a new buffer using a fallible initializer for the data
    fn try_new_with<E>(f: impl FnOnce(&mut [u8]) -> Result<(), E>) -> Result<Self, E>;

    /// Create a new buffer instance from a slice of bytes.
    /// Panics if the length of the slice is incorrect.
    fn from_slice(data: &[u8]) -> Self {
        if let Ok(slf) = Self::try_from(data) {
            slf
        } else {
            panic!("Invalid length for buffer");
        }
    }

    /// Get the length of the buffer
    #[inline]
    fn len() -> usize {
        Self::SIZE
    }

    /// Check if the buffer is empty
    #[inline]
    fn is_empty() -> bool {
        Self::SIZE == 0
    }
}

impl<const L: usize> FixedBufferCore for [u8; L] {
    const SIZE: usize = L;

    #[inline]
    fn new_with(f: impl FnOnce(&mut [u8])) -> Self {
        let mut buf = [0u8; L];
        f(&mut buf);
        buf
    }

    #[inline]
    fn try_new_with<E>(f: impl FnOnce(&mut [u8]) -> Result<(), E>) -> Result<Self, E> {
        let mut buf = [0u8; L];
        f(&mut buf)?;
        Ok(buf)
    }
}

/// A trait for fixed-size byte buffers
pub trait FixedBuffer: AsRef<[u8]> + AsMut<[u8]> + FixedBufferCore {
    /// The size of the buffer in bytes
    const SIZE: usize = <Self as FixedBufferCore>::SIZE;

    /// Create a new zeroed buffer
    fn new_zeroed() -> Self;
}

impl<const L: usize> FixedBuffer for [u8; L] {
    #[inline]
    fn new_zeroed() -> Self {
        [0u8; L]
    }
}

/// A trait for fixed-size secret byte buffers
pub trait FixedSecret:
    FixedBufferCore + FromSecretBytes + ToSecretBytes + Zeroize + ZeroizeOnDrop
{
    /// The size of the buffer in bytes
    const SIZE: usize = <Self as FixedBufferCore>::SIZE;

    /// Temporarily allocate and use a buffer
    fn with_temp<R>(f: impl FnOnce(&mut [u8]) -> R) -> R;
}

// /// A trait for modifying secret buffers
// pub trait FixedSecretMut: FixedSecret {
//     type Buffer: FixedBuffer;

//     /// Temporarily allocate and use a buffer
//     fn expose_secret_mut<R>(f: impl FnOnce(&mut [u8]) -> R) -> R;
// }
