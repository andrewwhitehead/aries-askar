//! Common cryptographic key traits

use core::{any::Any, fmt::Debug, panic::RefUnwindSafe};

use crate::{
    alg::KeyAlgorithm,
    encrypt::Aead,
    error::Error,
    jwk::ToJwk,
    kdf::KeyExchange,
    repr::{ToPublicBytes, ToSecretBytes},
    sign::{CreateSignature, VerifySignature},
};

mod boxed;
pub use self::boxed::*;

mod generic;
pub use self::generic::{AsGenericKey, GenericKey};

#[macro_use]
mod macros;

/// The basic type discriminator for a key
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    /// A public-private keypair for asymmetric pairing or signing
    AsymmetricPair,
    /// A public key for asymmetric pairing or signature verification
    AsymmetricPublic,
    /// A symmetric encryption key
    Symmetric,
}

/// Base trait for all key types.
pub trait KeyCore: Debug + RefUnwindSafe + Send + Sync {
    /// Get the corresponding key algorithm.
    fn key_algorithm(&self) -> KeyAlgorithm;

    /// Get the corresponding key type.
    fn key_type(&self) -> KeyType;

    /// Try to access this key as an AEAD instance.
    fn as_aead(&self) -> Option<&dyn Aead> {
        None
    }

    /// Try to access this key as a key exchange instance.
    fn as_exchange(&self) -> Option<&dyn KeyExchange> {
        None
    }

    /// Try to access this key as a JWK encoder instance.
    fn as_jwk_encoder(&self) -> Option<&dyn ToJwk> {
        None
    }

    /// Try to access this key as a public key exporter.
    fn as_public(&self) -> Option<&dyn ToPublicBytes> {
        None
    }

    /// Try to access this key as a secret key exporter.
    fn as_secret(&self) -> Option<&dyn ToSecretBytes> {
        None
    }

    /// Try to access this key as a signature creator.
    fn as_signer(&self) -> Option<&dyn CreateSignature> {
        None
    }

    /// Try to access this key as a signature verifier.
    fn as_verifier(&self) -> Option<&dyn VerifySignature> {
        None
    }
}

/// Common trait for concrete keys and key references
pub trait AsKey {
    /// The concrete key type
    type Key: Key + ?Sized;

    /// Obtain a reference to this key as a Key trait object
    fn as_key(&self) -> &Self::Key;
}

/// The base trait for all key types
pub trait Key: KeyCore {
    /// Obtain a reference to this key as an Any trait object
    fn as_any(&self) -> &dyn Any;

    /// Obtain a reference to this key as a Key trait object
    fn as_dyn(&self) -> &(dyn Key + 'static);
}

/// A marker trait for concrete key types (not key wrappers)
pub trait ConcreteKey: KeyCore + 'static {}

impl<K: ConcreteKey> AsKey for K {
    type Key = K;

    fn as_key(&self) -> &Self::Key {
        self
    }
}

impl<K: ConcreteKey> Key for K {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_dyn(&self) -> &(dyn Key + 'static) {
        self
    }
}

/// A trait for generating raw key material, generally cryptographically random bytes.
pub trait KeyMaterial {
    /// Get the maximum length of the key material output.
    fn key_material_max_len(&self) -> Option<usize> {
        None
    }

    /// Copy key material from the generator.
    fn copy_key_material(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// Raw key generation operations.
pub trait KeyGen: Sized {
    /// Create a new key from a key material generator.
    fn generate(source: impl KeyMaterial) -> Result<Self, Error>;

    /// Generate a new random key.
    #[cfg(feature = "getrandom")]
    fn random() -> Result<Self, Error> {
        Self::generate(crate::random::default_rng())
    }

    /// Generate a new random key for the given key algorithm.
    fn seeded(seed: &[u8]) -> Result<Self, Error> {
        Self::generate(crate::random::RandomDet::new(seed))
    }
}

impl<const L: usize> KeyGen for [u8; L] {
    #[inline]
    fn generate(mut source: impl KeyMaterial) -> Result<Self, Error> {
        let mut slf = [0u8; L];
        source.copy_key_material(&mut slf)?;
        Ok(slf)
    }
}
