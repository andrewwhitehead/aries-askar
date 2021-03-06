//! AES-GCM key representations with AEAD support

use core::{
    convert::TryInto,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use aead::{generic_array::ArrayLength, AeadInPlace, NewAead};
use aes_core::{Aes128, Aes256};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use block_modes::{
    block_padding::Pkcs7,
    cipher::{BlockCipher, NewBlockCipher},
    BlockMode, Cbc,
};
use digest::{BlockInput, FixedOutput, Reset, Update};
use hmac::{Hmac, Mac, NewMac};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::{AesTypes, HasKeyAlg, KeyAlg};
use crate::{
    buffer::{ArrayKey, ResizeBuffer, Writer},
    encrypt::{KeyAeadInPlace, KeyAeadMeta, KeyAeadParams},
    error::Error,
    generic_array::{
        typenum::{consts, Unsigned},
        GenericArray,
    },
    jwk::{JwkEncoder, ToJwk},
    kdf::{FromKeyDerivation, FromKeyExchange, KeyDerivation, KeyExchange},
    random::fill_random_deterministic,
    repr::{KeyGen, KeyMeta, KeySecretBytes, Seed, SeedMethod},
};

/// The 'kty' value of a symmetric key JWK
pub static JWK_KEY_TYPE: &'static str = "oct";

/// Trait implemented by supported AES authenticated encryption algorithms
pub trait AesType: 'static {
    /// The size of the key secret bytes
    type KeySize: ArrayLength<u8>;

    /// The associated algorithm type
    const ALG_TYPE: AesTypes;
    /// The associated JWK algorithm name
    const JWK_ALG: &'static str;
}

type KeyType<A> = ArrayKey<<A as AesType>::KeySize>;

type NonceSize<A> = <A as AesAead>::NonceSize;

type TagSize<A> = <A as AesAead>::TagSize;

const AES_KW_DEFAULT_IV: [u8; 8] = [166, 166, 166, 166, 166, 166, 166, 166];

/// An AES-GCM symmetric encryption key
#[derive(Serialize, Deserialize, Zeroize)]
#[serde(
    transparent,
    bound(
        deserialize = "KeyType<T>: for<'a> Deserialize<'a>",
        serialize = "KeyType<T>: Serialize"
    )
)]
// SECURITY: ArrayKey is zeroized on drop
pub struct AesKey<T: AesType>(KeyType<T>);

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

impl<T: AesType> HasKeyAlg for AesKey<T> {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::Aes(T::ALG_TYPE)
    }
}

impl<T: AesType> KeyMeta for AesKey<T> {
    type KeySize = T::KeySize;
}

impl<T: AesType> KeyGen for AesKey<T> {
    fn generate() -> Result<Self, Error> {
        Ok(AesKey(KeyType::<T>::random()))
    }

    fn from_seed(seed: Seed<'_>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        match seed {
            Seed::Bytes(ikm, SeedMethod::Preferred) | Seed::Bytes(ikm, SeedMethod::RandomDet) => {
                Ok(Self(KeyType::<T>::try_new_with(|arr| {
                    fill_random_deterministic(ikm, arr)
                })?))
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported)),
        }
    }
}

impl<T: AesType> KeySecretBytes for AesKey<T> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KeyType::<T>::SIZE {
            return Err(err_msg!(InvalidKeyData));
        }
        Ok(Self(KeyType::<T>::from_slice(key)))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        f(Some(self.0.as_ref()))
    }
}

impl<T: AesType> FromKeyDerivation for AesKey<T> {
    fn from_key_derivation<D: KeyDerivation>(mut derive: D) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Self(KeyType::<T>::try_new_with(|arr| {
            derive.derive_key_bytes(arr)
        })?))
    }
}

impl<T: AesAead> KeyAeadMeta for AesKey<T> {
    type NonceSize = NonceSize<T>;
    type TagSize = TagSize<T>;
}

impl<T: AesAead> KeyAeadInPlace for AesKey<T> {
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
        T::aes_encrypt_in_place(
            self.0.as_ref(),
            buffer,
            GenericArray::from_slice(nonce),
            aad,
        )
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
        T::aes_decrypt_in_place(
            self.0.as_ref(),
            buffer,
            GenericArray::from_slice(nonce),
            aad,
        )
    }

    fn aead_params(&self) -> KeyAeadParams {
        KeyAeadParams {
            nonce_length: NonceSize::<T>::USIZE,
            tag_length: TagSize::<T>::USIZE,
        }
    }
}

impl<T: AesType> ToJwk for AesKey<T> {
    fn encode_jwk(&self, enc: &mut JwkEncoder<'_>) -> Result<(), Error> {
        if enc.is_public() {
            return Err(err_msg!(Unsupported, "Cannot export as a public key"));
        }
        if !enc.is_thumbprint() {
            enc.add_str("alg", T::JWK_ALG)?;
        }
        enc.add_as_base64("k", self.0.as_ref())?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        Ok(())
    }
}

// for direct key agreement (not used currently)
impl<Lhs, Rhs, T> FromKeyExchange<Lhs, Rhs> for AesKey<T>
where
    Lhs: KeyExchange<Rhs> + ?Sized,
    Rhs: ?Sized,
    T: AesType,
{
    fn from_key_exchange(lhs: &Lhs, rhs: &Rhs) -> Result<Self, Error> {
        Ok(Self(KeyType::<T>::try_new_with(|arr| {
            let mut buf = Writer::from_slice(arr);
            lhs.write_key_exchange(rhs, &mut buf)?;
            if buf.position() != T::KeySize::USIZE {
                return Err(err_msg!(Usage, "Invalid length for key exchange output"));
            }
            Ok(())
        })?))
    }
}

/// 128 bit AES-GCM
pub type A128Gcm = Aes128Gcm;

impl AesType for A128Gcm {
    type KeySize = <Self as NewAead>::KeySize;

    const ALG_TYPE: AesTypes = AesTypes::A128Gcm;
    const JWK_ALG: &'static str = "A128GCM";
}

/// 256 bit AES-GCM
pub type A256Gcm = Aes256Gcm;

impl AesType for A256Gcm {
    type KeySize = <Self as NewAead>::KeySize;

    const ALG_TYPE: AesTypes = AesTypes::A256Gcm;
    const JWK_ALG: &'static str = "A256GCM";
}

/// Specialized trait for performing AEAD encryption
pub trait AesAead: AesType {
    /// Flag indicating a key-wrapping algorithm
    const KEY_WRAP: bool;
    /// The size of the nonce
    type NonceSize: ArrayLength<u8>;
    /// The size of the authentication tag
    type TagSize: ArrayLength<u8>;

    /// Perform AEAD encryption
    fn aes_encrypt_in_place(
        key: &GenericArray<u8, Self::KeySize>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
    ) -> Result<usize, Error>;

    /// Perform AEAD decryption
    fn aes_decrypt_in_place(
        key: &GenericArray<u8, Self::KeySize>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
    ) -> Result<(), Error>;

    /// Calculate padding length for a plaintext length
    fn aes_padding_length(len: usize) -> usize;
}

// Generic implementation for AesGcm<Aes, NonceSize>
impl<T> AesAead for T
where
    T: NewAead + AeadInPlace + AesType<KeySize = <T as NewAead>::KeySize>,
{
    const KEY_WRAP: bool = false;
    type NonceSize = T::NonceSize;
    type TagSize = T::TagSize;

    fn aes_encrypt_in_place(
        key: &GenericArray<u8, Self::KeySize>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
    ) -> Result<usize, Error> {
        let enc = <T as NewAead>::new(key);
        let tag = enc
            .encrypt_in_place_detached(nonce, aad, buffer.as_mut())
            .map_err(|_| err_msg!(Encryption, "AEAD encryption error"))?;
        let ctext_len = buffer.as_ref().len();
        buffer.buffer_write(&tag[..])?;
        Ok(ctext_len)
    }

    fn aes_decrypt_in_place(
        key: &GenericArray<u8, Self::KeySize>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
    ) -> Result<(), Error> {
        let buf_len = buffer.as_ref().len();
        if buf_len < Self::TagSize::USIZE {
            return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
        }
        let tag_start = buf_len - Self::TagSize::USIZE;
        let mut tag = GenericArray::default();
        tag.clone_from_slice(&buffer.as_ref()[tag_start..]);
        let enc = <T as NewAead>::new(key);
        enc.decrypt_in_place_detached(nonce, aad, &mut buffer.as_mut()[..tag_start], &tag)
            .map_err(|_| err_msg!(Encryption, "AEAD decryption error"))?;
        buffer.buffer_resize(tag_start)?;
        Ok(())
    }

    fn aes_padding_length(_len: usize) -> usize {
        0
    }
}

/// 128 bit AES-CBC with HMAC-256
pub type A128CbcHs256 = AesCbcHmac<Aes128, sha2::Sha256>;

impl AesType for A128CbcHs256 {
    type KeySize = consts::U32;
    const ALG_TYPE: AesTypes = AesTypes::A128CbcHs256;
    const JWK_ALG: &'static str = "A128CBC-HS256";
}

/// 256 bit AES-CBC with HMAC-512
pub type A256CbcHs512 = AesCbcHmac<aes_core::Aes256, sha2::Sha512>;

impl AesType for A256CbcHs512 {
    type KeySize = consts::U64;
    const ALG_TYPE: AesTypes = AesTypes::A256CbcHs512;
    const JWK_ALG: &'static str = "A256CBC-HS512";
}

/// AES-CBC-HMAC implementation
#[derive(Debug)]
pub struct AesCbcHmac<C, D>(PhantomData<(C, D)>);

impl<C, D> AesAead for AesCbcHmac<C, D>
where
    Self: AesType,
    C: BlockCipher + NewBlockCipher,
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    C::KeySize: core::ops::Shl<consts::B1>,
    <C::KeySize as core::ops::Shl<consts::B1>>::Output: ArrayLength<u8>,
{
    const KEY_WRAP: bool = false;
    type NonceSize = C::BlockSize;
    type TagSize = C::KeySize;

    fn aes_encrypt_in_place(
        key: &GenericArray<u8, Self::KeySize>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
    ) -> Result<usize, Error> {
        // this should be optimized away except when the error is thrown
        if Self::TagSize::USIZE > D::OutputSize::USIZE {
            return Err(err_msg!(
                Encryption,
                "AES-CBC-HMAC tag size exceeds maximum supported"
            ));
        }
        if aad.len() as u64 > u64::MAX / 8 {
            return Err(err_msg!(
                Encryption,
                "AES-CBC-HMAC AAD size exceeds maximum supported"
            ));
        }

        let msg_len = buffer.as_ref().len();
        let pad_len = Self::aes_padding_length(msg_len);
        buffer.buffer_extend(pad_len + Self::TagSize::USIZE)?;
        let enc_key = GenericArray::from_slice(&key[C::KeySize::USIZE..]);
        Cbc::<C, Pkcs7>::new_fix(enc_key, nonce)
            .encrypt(buffer.as_mut(), msg_len)
            .map_err(|_| err_msg!(Encryption, "AES-CBC encryption error"))?;
        let ctext_end = msg_len + pad_len;

        let mut hmac = Hmac::<D>::new_from_slice(&key[..C::KeySize::USIZE])
            .expect("Incompatible HMAC key length");
        hmac.update(aad);
        hmac.update(nonce.as_ref());
        hmac.update(&buffer.as_ref()[..ctext_end]);
        hmac.update(&((aad.len() as u64) * 8).to_be_bytes());
        let mac = hmac.finalize().into_bytes();
        buffer.as_mut()[ctext_end..(ctext_end + Self::TagSize::USIZE)]
            .copy_from_slice(&mac[..Self::TagSize::USIZE]);

        Ok(ctext_end)
    }

    fn aes_decrypt_in_place(
        key: &GenericArray<u8, Self::KeySize>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
    ) -> Result<(), Error> {
        if aad.len() as u64 > u64::MAX / 8 {
            return Err(err_msg!(
                Encryption,
                "AES-CBC-HMAC AAD size exceeds maximum supported"
            ));
        }
        let buf_len = buffer.as_ref().len();
        if buf_len < Self::TagSize::USIZE {
            return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
        }
        let ctext_end = buf_len - Self::TagSize::USIZE;
        let tag = GenericArray::<u8, Self::TagSize>::from_slice(&buffer.as_ref()[ctext_end..]);

        let mut hmac = Hmac::<D>::new_from_slice(&key[..C::KeySize::USIZE])
            .expect("Incompatible HMAC key length");
        hmac.update(aad);
        hmac.update(nonce.as_ref());
        hmac.update(&buffer.as_ref()[..ctext_end]);
        hmac.update(&((aad.len() as u64) * 8).to_be_bytes());
        let mac = hmac.finalize().into_bytes();
        let tag_match =
            subtle::ConstantTimeEq::ct_eq(tag.as_ref(), &mac[..Self::TagSize::USIZE]).unwrap_u8();

        let enc_key = GenericArray::from_slice(&key[C::KeySize::USIZE..]);
        let dec_len = Cbc::<C, Pkcs7>::new_fix(enc_key, nonce)
            .decrypt(&mut buffer.as_mut()[..ctext_end])
            .map_err(|_| err_msg!(Encryption, "AES-CBC decryption error"))?
            .len();
        buffer.buffer_resize(dec_len)?;

        if tag_match != 1 {
            Err(err_msg!(Encryption, "AEAD decryption error"))
        } else {
            Ok(())
        }
    }

    #[inline]
    fn aes_padding_length(len: usize) -> usize {
        Self::NonceSize::USIZE - (len % Self::NonceSize::USIZE)
    }
}

/// 128 bit AES Key Wrap
pub type A128Kw = AesKeyWrap<Aes128>;

impl AesType for A128Kw {
    type KeySize = <Aes128 as NewBlockCipher>::KeySize;
    const ALG_TYPE: AesTypes = AesTypes::A128Kw;
    const JWK_ALG: &'static str = "A128KW";
}

/// 256 bit AES Key Wrap
pub type A256Kw = AesKeyWrap<Aes256>;

impl AesType for A256Kw {
    type KeySize = <Aes256 as NewBlockCipher>::KeySize;
    const ALG_TYPE: AesTypes = AesTypes::A256Kw;
    const JWK_ALG: &'static str = "A256KW";
}

/// AES Key Wrap implementation
#[derive(Debug)]
pub struct AesKeyWrap<K>(PhantomData<K>);

impl<K> AesAead for AesKeyWrap<K>
where
    Self: AesType,
    K: NewBlockCipher<KeySize = Self::KeySize> + BlockCipher<BlockSize = consts::U16>,
{
    const KEY_WRAP: bool = true;
    type NonceSize = consts::U0;
    type TagSize = consts::U8;

    fn aes_encrypt_in_place(
        key: &GenericArray<u8, Self::KeySize>,
        buffer: &mut dyn ResizeBuffer,
        _nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
    ) -> Result<usize, Error> {
        if aad.len() != 0 {
            return Err(err_msg!(Unsupported, "AAD not supported"));
        }
        let mut buf_len = buffer.as_ref().len();
        if buf_len % 8 != 0 {
            return Err(err_msg!(
                Unsupported,
                "Data length must be a multiple of 8 bytes"
            ));
        }
        let blocks = buf_len / 8;

        buffer.buffer_insert(0, &[0u8; 8])?;
        buf_len += 8;

        let aes = K::new(key);
        let mut iv = AES_KW_DEFAULT_IV;
        let mut block = GenericArray::default();
        for j in 0..6 {
            for (i, chunk) in buffer.as_mut()[8..].chunks_exact_mut(8).enumerate() {
                block[0..8].copy_from_slice(iv.as_ref());
                block[8..16].copy_from_slice(chunk);
                aes.encrypt_block(&mut block);
                let t = (((blocks * j) + i + 1) as u64).to_be_bytes();
                iv.copy_from_slice(&block[0..8]);
                for (a, t) in iv.as_mut().iter_mut().zip(&t[..]) {
                    *a ^= t;
                }
                chunk.copy_from_slice(&block[8..16]);
            }
        }
        buffer.as_mut()[0..8].copy_from_slice(&iv[..]);
        Ok(buf_len)
    }

    fn aes_decrypt_in_place(
        key: &GenericArray<u8, Self::KeySize>,
        buffer: &mut dyn ResizeBuffer,
        _nonce: &GenericArray<u8, Self::NonceSize>,
        aad: &[u8],
    ) -> Result<(), Error> {
        if aad.len() != 0 {
            return Err(err_msg!(Unsupported, "AAD not supported"));
        }
        if buffer.as_ref().len() % 8 != 0 {
            return Err(err_msg!(
                Encryption,
                "Data length must be a multiple of 8 bytes"
            ));
        }
        let mut blocks = buffer.as_ref().len() / 8;
        if blocks < 1 {
            return Err(err_msg!(Encryption));
        }
        blocks -= 1;

        let aes = K::new(key);
        let mut iv = *TryInto::<&[u8; 8]>::try_into(&buffer.as_ref()[0..8]).unwrap();
        buffer.buffer_remove(0..8)?;

        let mut block = GenericArray::default();
        for j in (0..6).into_iter().rev() {
            for (i, chunk) in buffer.as_mut().chunks_exact_mut(8).enumerate().rev() {
                block[0..8].copy_from_slice(iv.as_ref());
                let t = (((blocks * j) + i + 1) as u64).to_be_bytes();
                for (a, t) in block[0..8].iter_mut().zip(&t[..]) {
                    *a ^= t;
                }
                block[8..16].copy_from_slice(chunk);
                aes.decrypt_block(&mut block);
                iv.copy_from_slice(&block[0..8]);
                chunk.copy_from_slice(&block[8..16]);
            }
        }

        if iv.ct_eq(&AES_KW_DEFAULT_IV).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(err_msg!(Encryption))
        }
    }

    fn aes_padding_length(_len: usize) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::SecretBytes;
    use crate::repr::ToSecretBytes;
    use std::string::ToString;

    #[test]
    fn encrypt_round_trip() {
        fn test_encrypt<T: AesAead>() {
            let input = b"hello";
            let aad = b"additional data";
            let key = AesKey::<T>::generate().unwrap();
            let mut buffer = SecretBytes::from_slice(input);
            let pad_len = T::aes_padding_length(input.len());
            let nonce = AesKey::<T>::random_nonce();
            key.encrypt_in_place(&mut buffer, &nonce, aad).unwrap();
            let enc_len = buffer.len();
            assert_eq!(enc_len, input.len() + pad_len + T::TagSize::USIZE);
            assert_ne!(&buffer[..], input);
            let mut dec = buffer.clone();
            key.decrypt_in_place(&mut dec, &nonce, aad).unwrap();
            assert_eq!(&dec[..], input);

            // test tag validation
            buffer.as_mut()[enc_len - 1] = buffer.as_mut()[enc_len - 1].wrapping_add(1);
            assert!(key.decrypt_in_place(&mut buffer, &nonce, aad).is_err());
        }
        test_encrypt::<A128Gcm>();
        test_encrypt::<A256Gcm>();
        test_encrypt::<A128CbcHs256>();
        test_encrypt::<A256CbcHs512>();
    }

    #[test]
    fn test_random() {
        let key = AesKey::<A128CbcHs256>::generate().unwrap();
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
            let key = AesKey::<T>::generate().unwrap();
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

    #[test]
    fn encrypt_expected_cbc_hmac_128() {
        let key_data = &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let input = b"A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience";
        let nonce = &hex!("1af38c2dc2b96ffdd86694092341bc04");
        let aad = b"The second principle of Auguste Kerckhoffs";
        let key = AesKey::<A128CbcHs256>::from_secret_bytes(key_data).unwrap();
        let mut buffer = SecretBytes::from_slice(input);
        key.encrypt_in_place(&mut buffer, &nonce[..], &aad[..])
            .unwrap();

        assert_eq!(
            buffer.as_hex().to_string(),
            "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9\
            a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c7032336\
            09d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b\
            384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade5\
            4b8851ffb598f7f80074b9473c82e2db\
            652c3fa36b0a7c5b3219fab3a30bc1c4"
        );
        key.decrypt_in_place(&mut buffer, &nonce[..], &aad[..])
            .unwrap();
        assert_eq!(buffer, &input[..]);
    }

    #[test]
    fn encrypt_expected_cbc_hmac_256() {
        let key_data = &hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
            202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        );
        let input = b"A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience";
        let nonce = &hex!("1af38c2dc2b96ffdd86694092341bc04");
        let aad = b"The second principle of Auguste Kerckhoffs";
        let key = AesKey::<A256CbcHs512>::from_secret_bytes(key_data).unwrap();
        let mut buffer = SecretBytes::from_slice(input);
        key.encrypt_in_place(&mut buffer, &nonce[..], &aad[..])
            .unwrap();

        assert_eq!(
            buffer.as_hex().to_string(),
            "4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd\
            822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b\
            36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3\
            a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950b\
            be2638d09dd7a4930930806d0703b1f6\
            4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5"
        );
        key.decrypt_in_place(&mut buffer, &nonce[..], &aad[..])
            .unwrap();
        assert_eq!(buffer, &input[..]);
    }

    #[test]
    fn encrypt_expected_cbc_hmac_1pu() {
        let key_data = &hex!(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0
            dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0"
        );
        let nonce = &hex!("000102030405060708090a0b0c0d0e0f");
        let protected = "{\"alg\":\"ECDH-1PU+A128KW\",\"enc\":\"A256CBC-HS512\",\
            \"apu\":\"QWxpY2U\",\"apv\":\"Qm9iIGFuZCBDaGFybGll\",\"epk\":{\
                \"kty\":\"OKP\",\"crv\":\"X25519\",\
                \"x\":\"k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc\"}}";
        let aad = base64::encode_config(protected, base64::URL_SAFE_NO_PAD);
        let input = b"Three is a magic number.";
        let key = AesKey::<A256CbcHs512>::from_secret_bytes(key_data).unwrap();
        let mut buffer = SecretBytes::from_slice(input);
        key.encrypt_in_place(&mut buffer, &nonce[..], aad.as_bytes())
            .unwrap();
        let ct_len = buffer.len() - key.aead_params().tag_length;
        let ctext = base64::encode_config(&buffer.as_ref()[..ct_len], base64::URL_SAFE_NO_PAD);
        let tag = base64::encode_config(&buffer.as_ref()[ct_len..], base64::URL_SAFE_NO_PAD);
        assert_eq!(ctext, "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw");
        assert_eq!(tag, "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ");
        key.decrypt_in_place(&mut buffer, &nonce[..], aad.as_bytes())
            .unwrap();
        assert_eq!(buffer, &input[..]);
    }

    #[test]
    // from RFC 3394 test vectors
    fn key_wrap_128_expected() {
        let key =
            AesKey::<A128Kw>::from_secret_bytes(&hex!("000102030405060708090a0b0c0d0e0f")).unwrap();
        let input = &hex!("00112233445566778899aabbccddeeff");
        let mut buffer = SecretBytes::from_slice(input);
        key.encrypt_in_place(&mut buffer, &[], &[]).unwrap();
        assert_eq!(
            buffer.as_hex().to_string(),
            "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
        );
        key.decrypt_in_place(&mut buffer, &[], &[]).unwrap();
        assert_eq!(buffer, &input[..]);
    }

    #[test]
    // from RFC 3394 test vectors
    fn key_wrap_256_expected() {
        let key = AesKey::<A256Kw>::from_secret_bytes(&hex!(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
        ))
        .unwrap();
        let input = &hex!("00112233445566778899aabbccddeeff");
        let mut buffer = SecretBytes::from_slice(input);
        key.encrypt_in_place(&mut buffer, &[], &[]).unwrap();
        assert_eq!(
            buffer.as_hex().to_string(),
            "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"
        );
        key.decrypt_in_place(&mut buffer, &[], &[]).unwrap();
        assert_eq!(buffer, &input[..]);
    }
}
