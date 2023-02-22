use std::{fmt::Display, mem, ptr, sync::Arc};

use crate::error::Error;

#[repr(C)]
pub struct ArcHandle<T: Send>(*const T);

impl<T: Send> ArcHandle<T> {
    pub fn invalid() -> Self
    where
        T: Sized,
    {
        Self(ptr::null())
    }

    pub fn create(value: T) -> Self
    where
        T: Sized,
    {
        Self::from_arc(Arc::new(value))
    }

    #[inline]
    fn from_arc(arc: Arc<T>) -> Self {
        Self(Arc::into_raw(arc))
    }

    pub fn load(&self) -> Result<Arc<T>, Error> {
        self.validate()?;
        let result = unsafe { mem::ManuallyDrop::new(Arc::from_raw(self.0)) };
        Ok((&*result).clone())
    }

    pub fn remove(&self) {
        if !self.0.is_null() {
            unsafe {
                // Drop the initial reference. There could be others outstanding.
                Arc::decrement_strong_count(self.0);
            }
        }
    }

    #[inline]
    pub fn validate(&self) -> Result<(), Error> {
        if self.0.is_null() {
            Err(err_msg!("Invalid handle"))
        } else {
            Ok(())
        }
    }
}

impl<T: Send> From<Arc<T>> for ArcHandle<T> {
    fn from(arc: Arc<T>) -> Self {
        Self::from_arc(arc)
    }
}

impl<T: Send> std::fmt::Display for ArcHandle<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Handle({:p})", self.0)
    }
}

pub trait ResourceHandle: Copy + Ord + From<usize> + Display {
    fn invalid() -> Self {
        Self::from(0)
    }

    fn next() -> Self;
}

/// Derive a new handle type having an atomically increasing sequence number
#[macro_export]
macro_rules! new_sequence_handle (($newtype:ident, $counter:ident) => (
    static $counter: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    #[repr(C)]
    pub struct $newtype(pub usize);

    impl $crate::ffi::ResourceHandle for $newtype {
        fn next() -> $newtype {
            $newtype($counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1)
        }
    }

    impl std::fmt::Display for $newtype {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}({})", stringify!($newtype), self.0)
        }
    }

    impl std::ops::Deref for $newtype {
        type Target = usize;
        fn deref(&self) -> &usize {
            &self.0
        }
    }

    impl From<usize> for $newtype {
        fn from(val: usize) -> Self {
            Self(val)
        }
    }

    impl PartialEq<usize> for $newtype {
        fn eq(&self, other: &usize) -> bool {
            self.0 == *other
        }
    }
));

#[cfg(test)]
mod tests {
    use super::ResourceHandle;
    new_sequence_handle!(TestHandle, TEST_HANDLE_CTR);

    #[test]
    fn test_handle_seq() {
        assert_eq!(TestHandle::next(), 1);
        assert_eq!(TestHandle::next(), 2);
    }
}
