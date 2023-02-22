use super::{AsKey, ConcreteKey, Key, KeyMaterial};
use crate::error::Error;

/// A trait for allocating key instances, allowing conversion to boxed types
pub trait AllocKey {
    /// The resulting allocated key type
    type Key: AsKey + Sized;

    /// Convert a key instance to the common type
    fn alloc_key<K: ConcreteKey>(&self, key: K) -> Self::Key;

    #[inline]
    /// Try to create key instance and box it
    fn try_alloc_key<K: ConcreteKey>(
        &self,
        f: impl FnOnce() -> Result<K, Error>,
    ) -> Result<Self::Key, Error> {
        f().map(|key| self.alloc_key(key))
    }
}

/// A trait for creating
pub trait AllocKeyLoader {
    /// The resulting allocated key type
    type Key: AsKey + Sized;

    /// Generate a new key from a key material generator for the given key algorithm.
    fn generate(&self, source: impl KeyMaterial) -> Result<Self::Key, Error>;

    /// Generate a new random key for the given key algorithm.
    #[cfg(feature = "getrandom")]
    fn random(&self) -> Result<Self::Key, Error> {
        self.generate(crate::random::default_rng())
    }

    /// Generate a new deterministic key for the given key algorithm.
    fn seeded(&self, seed: &[u8]) -> Result<Self::Key, Error> {
        self.generate(crate::random::RandomDet::new(seed))
    }

    /// Load a public key from its byte representation.
    fn load_public_bytes(&self, public: &[u8]) -> Result<Self::Key, Error>;

    /// Load a secret key or keypair from its byte representation.
    fn load_secret_bytes(&self, secret: &[u8]) -> Result<Self::Key, Error>;

    /// Derive the corresponding key for this key algorithm.
    fn convert_key(&self, key: &dyn Key) -> Result<Self::Key, Error>;
}

/// A placeholder type for allocating keys into a Box container
#[derive(Copy, Clone, Default, Debug)]
pub struct BoxKey;

/// A placeholder type for allocating keys into an Arc container
#[derive(Copy, Clone, Default, Debug)]
pub struct ArcKey;

#[cfg(all(feature = "alloc"))]
mod _boxed_any {
    use alloc::{boxed::Box, sync::Arc};

    use super::*;
    use crate::impl_key_by_deref;
    use crate::key::{ConcreteKey, Key};

    impl_key_by_deref!(Box<dyn Key>);

    impl AllocKey for BoxKey {
        type Key = Box<dyn Key>;

        #[inline(always)]
        fn alloc_key<K: ConcreteKey>(&self, key: K) -> Self::Key {
            Box::new(key)
        }
    }

    #[cfg(feature = "alloc")]
    impl_key_by_deref!(Arc<dyn Key>);

    impl AllocKey for ArcKey {
        type Key = Arc<dyn Key>;

        #[inline(always)]
        fn alloc_key<K: ConcreteKey>(&self, key: K) -> Self::Key {
            Arc::new(key)
        }
    }
}
