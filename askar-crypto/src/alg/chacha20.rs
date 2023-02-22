//! ChaCha20 and XChaCha20 stream ciphers with AEAD

use core::fmt::{self, Debug, Formatter};

use aead::{AeadCore, AeadInPlace, KeyInit, KeySizeUser};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{Chacha20Types, KeyAlgorithm};
use crate::{
    buffer::{FixedBuffer, FixedSecret, ResizeBuffer, SecretArray},
    encrypt::{Aead, AeadMeta, AeadParams},
    error::Error,
    generic_array::{typenum::Unsigned, GenericArray},
    jwk::{JwkEncoder, ToJwk},
    key::{ConcreteKey, KeyCore, KeyGen, KeyMaterial, KeyType},
    repr::{FromSecretBytes, SecretBytesCore},
};

/// The 'kty' value of a symmetric key JWK
pub const JWK_KEY_TYPE: &str = "oct";

/// Trait implemented by supported ChaCha20 algorithms
pub trait Chacha20Type: 'static {
    /// The AEAD implementation
    type Aead: KeyInit + AeadCore + AeadInPlace;
    /// The key representation
    type Repr: FixedSecret + for<'a> Deserialize<'a> + Serialize;
    /// The AEAD nonce
    type Nonce: FixedBuffer;
    /// The AEAD tag
    type Tag: FixedBuffer;

    /// The associated algorithm type
    const ALG_TYPE: Chacha20Types;
    /// The associated JWK algorithm name
    const JWK_ALG: &'static str;
}

type NonceSize<A> = <<A as Chacha20Type>::Aead as AeadCore>::NonceSize;

type TagSize<A> = <<A as Chacha20Type>::Aead as AeadCore>::TagSize;

/// ChaCha20-Poly1305
#[derive(Debug)]
pub struct C20P;

impl Chacha20Type for C20P {
    type Aead = ChaCha20Poly1305;
    type Repr = SecretArray<{ <ChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE }>;
    type Nonce = [u8; NonceSize::<Self>::USIZE];
    type Tag = [u8; TagSize::<Self>::USIZE];

    const ALG_TYPE: Chacha20Types = Chacha20Types::C20P;
    const JWK_ALG: &'static str = "C20P";
}

/// XChaCha20-Poly1305
#[derive(Debug)]
pub struct XC20P;

impl Chacha20Type for XC20P {
    type Aead = XChaCha20Poly1305;
    type Repr = SecretArray<{ <XChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE }>;
    type Nonce = [u8; NonceSize::<Self>::USIZE];
    type Tag = [u8; TagSize::<Self>::USIZE];

    const ALG_TYPE: Chacha20Types = Chacha20Types::XC20P;
    const JWK_ALG: &'static str = "XC20P";
}

/// A ChaCha20 symmetric encryption key
#[derive(Serialize, Deserialize, Zeroize)]
#[serde(
    transparent,
    bound(
        deserialize = "T::Repr: for<'a> Deserialize<'a>",
        serialize = "T::Repr: Serialize"
    )
)]
// SECURITY: ArrayKey is zeroized on drop
pub struct Chacha20Key<T: Chacha20Type>(T::Repr);

impl<T: Chacha20Type> Chacha20Key<T> {
    /// The length of the secret key in bytes
    pub const KEY_LENGTH: usize = T::Repr::SIZE;
    /// The length of the AEAD encryption nonce
    pub const NONCE_LENGTH: usize = NonceSize::<T>::USIZE;
    /// The length of the AEAD encryption tag
    pub const TAG_LENGTH: usize = TagSize::<T>::USIZE;
}

impl<T: Chacha20Type> Clone for Chacha20Key<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Chacha20Type> Debug for Chacha20Key<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chacha20Key")
            .field("alg", &T::JWK_ALG)
            .field("key", &self.0)
            .finish()
    }
}

impl<T: Chacha20Type> PartialEq for Chacha20Key<T> {
    fn eq(&self, other: &Self) -> bool {
        other.0 == self.0
    }
}

impl<T: Chacha20Type> Eq for Chacha20Key<T> {}

impl<T: Chacha20Type> KeyCore for Chacha20Key<T> {
    fn key_algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Chacha20(T::ALG_TYPE)
    }

    fn key_type(&self) -> KeyType {
        KeyType::Symmetric
    }

    fn as_aead(&self) -> Option<&dyn Aead> {
        Some(self)
    }

    fn as_jwk_encoder(&self) -> Option<&dyn ToJwk> {
        Some(self)
    }

    fn as_secret(&self) -> Option<&dyn crate::repr::ToSecretBytes> {
        Some(self)
    }
}
impl<T: Chacha20Type> ConcreteKey for Chacha20Key<T> {}

impl<T: Chacha20Type> KeyGen for Chacha20Key<T> {
    fn generate(rng: impl KeyMaterial) -> Result<Self, Error> {
        Ok(Chacha20Key(T::Repr::generate(rng)?))
    }
}

impl<T: Chacha20Type> SecretBytesCore for Chacha20Key<T> {
    const SECRET_BYTES_LEN: usize = Chacha20Key::<T>::KEY_LENGTH;

    fn access_secret_bytes<O>(
        &self,
        f: impl FnOnce(&[u8]) -> Result<O, Error>,
    ) -> Result<O, Error> {
        self.0.access_secret_bytes(f)
    }
}

impl<T: Chacha20Type> FromSecretBytes for Chacha20Key<T> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        Ok(Self(
            T::Repr::try_from(key).map_err(|_| err_msg!(InvalidKeyData))?,
        ))
    }
}

impl<T: Chacha20Type> AeadMeta for Chacha20Key<T> {
    type Nonce = T::Nonce;
    type Tag = T::Tag;
}

impl<T: Chacha20Type> Aead for Chacha20Key<T> {
    /// Encrypt a secret value in place, appending the verification tag
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error> {
        if nonce.len() != NonceSize::<T>::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        let nonce = GenericArray::from_slice(nonce);
        let mut tag = GenericArray::default();
        self.0.access_secret_bytes(|key| {
            let chacha = T::Aead::new(key.into());
            tag = chacha
                .encrypt_in_place_detached(nonce, aad, buffer.as_mut())
                .map_err(|_| err_msg!(Encryption, "AEAD encryption error"))?;
            Ok(())
        })?;
        let ctext_len = buffer.as_ref().len();
        buffer.buffer_write(&tag[..])?;
        Ok(ctext_len)
    }

    /// Decrypt an encrypted (verification tag appended) value in place
    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        if nonce.len() != NonceSize::<T>::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        let nonce = GenericArray::from_slice(nonce);
        let buf_len = buffer.as_ref().len();
        if buf_len < TagSize::<T>::USIZE {
            return Err(err_msg!(Invalid, "Invalid size for encrypted data"));
        }
        let tag_start = buf_len - TagSize::<T>::USIZE;
        let mut tag = GenericArray::default();
        tag.clone_from_slice(&buffer.as_ref()[tag_start..]);
        self.0.access_secret_bytes(|key| {
            let chacha = T::Aead::new(key.into());
            chacha
                .decrypt_in_place_detached(nonce, aad, &mut buffer.as_mut()[..tag_start], &tag)
                .map_err(|_| err_msg!(Encryption, "AEAD decryption error"))?;
            Ok(())
        })?;
        buffer.buffer_resize(tag_start)?;
        Ok(())
    }

    fn aead_params(&self) -> AeadParams {
        AeadParams {
            nonce_length: NonceSize::<T>::USIZE,
            tag_length: TagSize::<T>::USIZE,
        }
    }
}

impl<T: Chacha20Type> ToJwk for Chacha20Key<T> {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        if enc.is_public() {
            return Err(err_msg!(Unsupported, "Cannot export as a public key"));
        }
        if !enc.is_thumbprint() {
            enc.add_str("alg", T::JWK_ALG)?;
        }
        self.0
            .access_secret_bytes(|key| enc.add_as_base64("k", key))?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::SecretVec;
    use crate::repr::ToSecretBytes;

    #[test]
    fn encrypt_round_trip() {
        fn test_encrypt<T: Chacha20Type>() {
            let input = b"hello";
            let key = Chacha20Key::<T>::random().unwrap();
            let mut buffer = SecretVec::from_slice(input);
            let nonce = Chacha20Key::<T>::random_nonce();
            key.encrypt_in_place(&mut buffer, nonce.as_ref(), &[])
                .unwrap();
            assert_eq!(buffer.len(), input.len() + Chacha20Key::<T>::TAG_LENGTH);
            assert_ne!(&buffer[..], input);
            key.decrypt_in_place(&mut buffer, nonce.as_ref(), &[])
                .unwrap();
            assert_eq!(&buffer[..], input);
        }
        test_encrypt::<C20P>();
        test_encrypt::<XC20P>();
    }

    #[test]
    fn serialize_round_trip() {
        fn test_serialize<T: Chacha20Type>() {
            let key = Chacha20Key::<T>::random().unwrap();
            let sk = key.to_secret_bytes().unwrap();
            let bytes = serde_cbor::to_vec(&key).unwrap();
            let deser: &[u8] = serde_cbor::from_slice(bytes.as_ref()).unwrap();
            assert_eq!(deser, sk.as_ref());
        }
        test_serialize::<C20P>();
        test_serialize::<XC20P>();
    }
}
