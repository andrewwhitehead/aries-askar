use core::{
    fmt::{self, Debug, Formatter},
    hash,
    marker::PhantomPinned,
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{FixedBufferCore, FixedSecret, HexRepr};
use crate::{
    error::Error,
    key::{KeyGen, KeyMaterial},
    repr::{FromSecretBytes, SecretBytesCore},
};

/// A secure representation for fixed-length keys
#[derive(Clone)]
#[repr(transparent)]
pub struct SecretArray<const L: usize>(
    [u8; L],
    // ensure that the type does not implement Unpin
    PhantomPinned,
);

impl<const L: usize> SecretArray<L> {
    /// Convert this array to a non-zeroing array instance
    #[inline]
    pub fn into_array(self) -> [u8; L] {
        self.0
    }

    /// Create a new zeroed secret array and access it temporarily
    #[inline]
    pub fn with_temp_array<R>(f: impl FnOnce(&mut [u8; L]) -> R) -> R {
        let mut slf = Self::default();
        f(&mut slf.0)
    }

    /// Get a hex formatter for the secret data
    pub fn as_hex(&self) -> HexRepr<&[u8]> {
        HexRepr(self.0.as_ref())
    }
}

impl<const L: usize> Default for SecretArray<L> {
    fn default() -> Self {
        Self([0; L], PhantomPinned)
    }
}

impl<const L: usize> From<&[u8; L]> for SecretArray<L> {
    #[inline(always)]
    fn from(key: &[u8; L]) -> Self {
        Self(*key, PhantomPinned)
    }
}

impl<const L: usize> From<[u8; L]> for SecretArray<L> {
    #[inline(always)]
    fn from(key: [u8; L]) -> Self {
        Self(key, PhantomPinned)
    }
}

impl<const L: usize> TryFrom<&[u8]> for SecretArray<L> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if let Ok(arr) = <&[u8; L]>::try_from(value) {
            Ok(Self::from(arr))
        } else {
            Err(err_msg!(InvalidKeyData, "Invalid length"))
        }
    }
}

impl<const L: usize> Debug for SecretArray<L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if cfg!(test) {
            f.debug_tuple("ArrayBuffer").field(&*self).finish()
        } else {
            f.debug_tuple("ArrayBuffer").field(&"<secret>").finish()
        }
    }
}

impl<const L: usize> ConstantTimeEq for SecretArray<L> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(self.0.as_ref(), other.0.as_ref())
    }
}

impl<const L: usize> PartialEq for SecretArray<L> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl<const L: usize> Eq for SecretArray<L> {}

impl<const L: usize> hash::Hash for SecretArray<L> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<const L: usize> Serialize for SecretArray<L> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de, const L: usize> Deserialize<'de> for SecretArray<L> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(KeyVisitor)
    }
}

impl<const L: usize> Zeroize for SecretArray<L> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl<const L: usize> ZeroizeOnDrop for SecretArray<L> {}

impl<const L: usize> Drop for SecretArray<L> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const L: usize> KeyGen for SecretArray<L> {
    fn generate(mut source: impl KeyMaterial) -> Result<Self, Error> {
        Self::try_new_with(|buf| source.copy_key_material(buf))
    }
}

impl<const L: usize> SecretBytesCore for SecretArray<L> {
    const SECRET_BYTES_LEN: usize = L;

    fn access_secret_bytes<O>(
        &self,
        f: impl FnOnce(&[u8]) -> Result<O, Error>,
    ) -> Result<O, Error> {
        f(&self.0)
    }
}

impl<const L: usize> FromSecretBytes for SecretArray<L> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        Self::try_from(key)
    }
}

struct KeyVisitor<const L: usize>;

impl<'de, const L: usize> de::Visitor<'de> for KeyVisitor<L> {
    type Value = SecretArray<L>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("byte array")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() != L {
            return Err(E::invalid_length(value.len(), &self));
        }
        Ok(SecretArray::from_slice(value))
    }
}

impl<const L: usize> FixedBufferCore for SecretArray<L> {
    const SIZE: usize = L;

    fn new_with(f: impl FnOnce(&mut [u8])) -> Self {
        let mut slf = Self::default();
        f(slf.0.as_mut());
        slf
    }

    fn try_new_with<E>(f: impl FnOnce(&mut [u8]) -> Result<(), E>) -> Result<Self, E> {
        let mut slf = Self::default();
        f(slf.0.as_mut())?;
        Ok(slf)
    }
}

impl<const L: usize> FixedSecret for SecretArray<L> {
    fn with_temp<R>(f: impl FnOnce(&mut [u8]) -> R) -> R {
        let mut slf = Self::default();
        f(&mut slf.0)
    }
}
