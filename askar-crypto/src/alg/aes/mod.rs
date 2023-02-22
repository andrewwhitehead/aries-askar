//! AES key representations with AEAD support

use core::fmt::{self, Debug, Formatter};

use aead::{AeadCore, AeadInPlace, KeyInit, KeySizeUser};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{AesTypes, KeyAlgorithm};
use crate::{
    buffer::{FixedBuffer, FixedSecret, ResizeBuffer, SecretArray},
    encrypt::{Aead, AeadMeta, AeadParams},
    error::Error,
    generic_array::{typenum::Unsigned, GenericArray},
    jwk::{JwkEncoder, ToJwk},
    key::{ConcreteKey, KeyCore, KeyGen, KeyMaterial, KeyType},
    repr::{FromSecretBytes, SecretBytesCore},
};

mod cbc_hmac;
pub use cbc_hmac::{A128CbcHs256, A256CbcHs512};

mod key_wrap;
pub use key_wrap::{A128Kw, A256Kw};

/// The 'kty' value of a symmetric key JWK
pub const JWK_KEY_TYPE: &str = "oct";

/// Trait implemented by supported AES authenticated encryption algorithms
pub trait AesType: 'static {
    /// The key representation
    type Repr: FixedSecret + for<'a> Deserialize<'a> + Serialize;
    /// The AEAD nonce
    type Nonce: FixedBuffer;
    /// The AEAD tag
    type Tag: FixedBuffer;

    /// The associated algorithm type
    const ALG_TYPE: AesTypes;
    /// The associated JWK algorithm name
    const JWK_ALG: &'static str;
}

type NonceSize<A> = <A as AeadCore>::NonceSize;

type TagSize<A> = <A as AeadCore>::TagSize;

/// An AES symmetric encryption key
#[derive(Serialize, Deserialize, Zeroize)]
#[serde(
    transparent,
    bound(
        deserialize = "T::Repr: for<'a> Deserialize<'a>",
        serialize = "T::Repr: Serialize"
    )
)]
// SECURITY: ArrayKey is zeroized on drop
pub struct AesKey<T: AesType>(T::Repr);

impl<T: AesType> Clone for AesKey<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: AesType> Debug for AesKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesKey")
            .field("alg", &T::JWK_ALG)
            .field("key", &self.0)
            .finish()
    }
}

impl<T: AesType> PartialEq for AesKey<T> {
    fn eq(&self, other: &Self) -> bool {
        other.0 == self.0
    }
}

impl<T: AesType> Eq for AesKey<T> {}

impl<T: AesType> KeyCore for AesKey<T>
where
    AesKey<T>: Aead,
{
    fn key_algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Aes(T::ALG_TYPE)
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
impl<T: AesType> ConcreteKey for AesKey<T> where AesKey<T>: Aead {}

impl<T: AesType> KeyGen for AesKey<T> {
    fn generate(source: impl KeyMaterial) -> Result<Self, Error> {
        Ok(AesKey(T::Repr::generate(source)?))
    }
}

impl<T: AesType> SecretBytesCore for AesKey<T> {
    const SECRET_BYTES_LEN: usize = T::Repr::SIZE;

    fn access_secret_bytes<O>(
        &self,
        f: impl FnOnce(&[u8]) -> Result<O, Error>,
    ) -> Result<O, Error> {
        self.0.access_secret_bytes(f)
    }
}

impl<T: AesType> FromSecretBytes for AesKey<T> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        Ok(Self(
            T::Repr::try_from(key).map_err(|_| err_msg!(InvalidKeyData))?,
        ))
    }
}

impl<T: AesType> ToJwk for AesKey<T> {
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

/// 128 bit AES-GCM
pub type A128Gcm = Aes128Gcm;

impl AesType for A128Gcm {
    type Repr = SecretArray<{ <Self as KeySizeUser>::KeySize::USIZE }>;
    type Nonce = [u8; NonceSize::<Self>::USIZE];
    type Tag = [u8; TagSize::<Self>::USIZE];

    const ALG_TYPE: AesTypes = AesTypes::A128Gcm;
    const JWK_ALG: &'static str = "A128GCM";
}

/// 256 bit AES-GCM
pub type A256Gcm = Aes256Gcm;

impl AesType for A256Gcm {
    type Repr = SecretArray<{ <Self as KeySizeUser>::KeySize::USIZE }>;
    type Nonce = [u8; NonceSize::<Self>::USIZE];
    type Tag = [u8; TagSize::<Self>::USIZE];

    const ALG_TYPE: AesTypes = AesTypes::A256Gcm;
    const JWK_ALG: &'static str = "A256GCM";
}

// generic implementation applying to AesGcm
impl<T: AeadCore + AesType> AeadMeta for AesKey<T> {
    type Nonce = T::Nonce;
    type Tag = T::Tag;
}

// generic implementation applying to AesGcm
impl<T> Aead for AesKey<T>
where
    T: KeyInit + AeadInPlace + AesType,
{
    /// Encrypt a secret value in place, appending the verification tag
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error> {
        if nonce.len() != T::NonceSize::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        let mut tag = GenericArray::default();
        self.0.access_secret_bytes(|key| {
            let enc = <T as KeyInit>::new(key.into());
            tag = enc
                .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer.as_mut())
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
        if nonce.len() != T::NonceSize::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        let buf_len = buffer.as_ref().len();
        if buf_len < T::TagSize::USIZE {
            return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
        }
        let tag_start = buf_len - T::TagSize::USIZE;
        let mut tag = GenericArray::default();
        tag.clone_from_slice(&buffer.as_ref()[tag_start..]);
        self.0.access_secret_bytes(|key| {
            let enc = <T as KeyInit>::new(key.into());
            enc.decrypt_in_place_detached(
                GenericArray::from_slice(nonce),
                aad,
                &mut buffer.as_mut()[..tag_start],
                &tag,
            )
            .map_err(|_| err_msg!(Encryption, "AEAD decryption error"))?;
            Ok(())
        })?;
        buffer.buffer_resize(tag_start)?;
        Ok(())
    }

    fn aead_params(&self) -> AeadParams {
        AeadParams {
            nonce_length: T::NonceSize::USIZE,
            tag_length: T::TagSize::USIZE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alloc")]
    use crate::buffer::SecretVec;
    use crate::buffer::Writer;
    use crate::repr::ToSecretBytes;

    #[cfg(feature = "alloc")]
    #[test]
    fn encrypt_round_trip() {
        fn test_encrypt<T>()
        where
            T: AesType,
            AesKey<T>: Aead + AeadMeta,
        {
            let input = b"hello";
            let aad = b"additional data";
            let key = AesKey::<T>::random().unwrap();
            let mut buffer = SecretVec::from_slice(input);
            let params = key.aead_params();
            let pad_len = key.aead_padding(input.len());
            let nonce = AesKey::<T>::random_nonce();
            key.encrypt_in_place(&mut buffer, nonce.as_ref(), aad)
                .unwrap();
            let enc_len = buffer.len();
            assert_eq!(enc_len, input.len() + pad_len + params.tag_length);
            assert_ne!(&buffer[..], input);
            let mut dec = buffer.clone();
            key.decrypt_in_place(&mut dec, nonce.as_ref(), aad).unwrap();
            assert_eq!(&dec[..], input);

            // test tag validation
            buffer.as_mut()[enc_len - 1] = buffer.as_mut()[enc_len - 1].wrapping_add(1);
            assert!(key
                .decrypt_in_place(&mut buffer, nonce.as_ref(), aad)
                .is_err());
        }
        test_encrypt::<A128Gcm>();
        test_encrypt::<A256Gcm>();
        test_encrypt::<A128CbcHs256>();
        test_encrypt::<A256CbcHs512>();
    }

    #[test]
    fn test_random() {
        let key = AesKey::<A128CbcHs256>::random().unwrap();
        let nonce = AesKey::<A128CbcHs256>::random_nonce();
        let message = b"hello there";
        let mut buffer = [0u8; 255];
        buffer[0..message.len()].copy_from_slice(&message[..]);
        let mut writer = Writer::from_slice_position(&mut buffer, message.len());
        key.encrypt_in_place(&mut writer, &nonce, &[]).unwrap();
    }

    #[test]
    fn serialize_round_trip() {
        fn test_serialize<T: AesType>() {
            let key = AesKey::<T>::random().unwrap();
            let sk = key.to_secret_bytes().unwrap();
            let bytes = serde_cbor::to_vec(&key).unwrap();
            let deser: &[u8] = serde_cbor::from_slice(bytes.as_ref()).unwrap();
            assert_eq!(deser, sk.as_ref());
        }
        test_serialize::<A128Gcm>();
        test_serialize::<A256Gcm>();
        test_serialize::<A128CbcHs256>();
        test_serialize::<A256CbcHs512>();
        test_serialize::<A128Kw>();
        test_serialize::<A256Kw>();
    }
}
