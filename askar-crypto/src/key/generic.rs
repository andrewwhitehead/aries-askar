//! Key material export methods

use core::fmt::Debug;
use core::ops::Deref;

use crate::buffer::{ResizeBuffer, WriteBuffer};
use crate::encrypt::{Aead, AeadParams};
use crate::error::Error;
use crate::impl_key_by_deref;
use crate::jwk::{JwkEncoder, ToJwk};
use crate::kdf::KeyExchange;
use crate::key::Key;
use crate::repr::{ToPublicBytes, ToSecretBytes};
use crate::sign::{CreateSignature, SignatureType, VerifySignature};

use super::AsKey;

/// Helper trait for accessing key traits with default implementations
pub trait AsGenericKey {
    /// Obtain a GenericKey wrapper for this key reference
    fn as_generic(&self) -> GenericKey<'_>;
}

impl<K: AsKey> AsGenericKey for K {
    fn as_generic(&self) -> GenericKey<'_> {
        GenericKey(self.as_key().as_dyn())
    }
}

/// A wrapper for keys, providing default implementations for the key traits
#[derive(Debug)]
pub struct GenericKey<'a>(&'a (dyn Key + 'static));

impl Deref for GenericKey<'_> {
    type Target = dyn Key + 'static;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl_key_by_deref!(GenericKey<'_>);

impl ToPublicBytes for GenericKey<'_> {
    fn public_bytes_len(&self) -> usize {
        self.0
            .as_public()
            .map(|key| key.public_bytes_len())
            .unwrap_or_default()
    }

    fn write_public_bytes(&self, buf: &mut dyn WriteBuffer) -> Result<(), Error> {
        self.0
            .as_public()
            .ok_or_else(|| err_msg!(Unsupported))?
            .write_public_bytes(buf)
    }
}

impl ToSecretBytes for GenericKey<'_> {
    fn secret_bytes_len(&self) -> usize {
        self.0
            .as_secret()
            .map(|key| key.secret_bytes_len())
            .unwrap_or_default()
    }

    fn write_secret_bytes(&self, buf: &mut dyn WriteBuffer) -> Result<(), Error> {
        self.0
            .as_secret()
            .ok_or_else(|| err_msg!(Unsupported))?
            .write_secret_bytes(buf)
    }
}

impl Aead for GenericKey<'_> {
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error> {
        self.0
            .as_aead()
            .ok_or_else(|| err_msg!(Unsupported))?
            .encrypt_in_place(buffer, nonce, aad)
    }

    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        self.0
            .as_aead()
            .ok_or_else(|| err_msg!(Unsupported))?
            .decrypt_in_place(buffer, nonce, aad)
    }

    fn aead_params(&self) -> AeadParams {
        self.0
            .as_aead()
            .map(|key| key.aead_params())
            .unwrap_or_default()
    }

    fn aead_padding(&self, msg_len: usize) -> usize {
        self.0
            .as_aead()
            .map(|key| key.aead_padding(msg_len))
            .unwrap_or_default()
    }
}

impl CreateSignature for GenericKey<'_> {
    fn default_signature_type(&self) -> Option<SignatureType> {
        self.0.as_signer().and_then(|s| s.default_signature_type())
    }

    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        self.0
            .as_signer()
            .ok_or_else(|| err_msg!(Unsupported))?
            .write_signature(message, sig_type, out)
    }
}

impl VerifySignature for GenericKey<'_> {
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        self.0
            .as_verifier()
            .ok_or_else(|| err_msg!(Unsupported))?
            .verify_signature(message, signature, sig_type)
    }
}

impl KeyExchange for GenericKey<'_> {
    fn key_exchange_bytes_len(&self) -> usize {
        self.0
            .as_exchange()
            .map(|key| key.key_exchange_bytes_len())
            .unwrap_or_default()
    }

    fn write_key_exchange_bytes(
        &self,
        other: &dyn Key,
        buf: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        self.0
            .as_exchange()
            .ok_or_else(|| err_msg!(Unsupported))?
            .write_key_exchange_bytes(other, buf)
    }
}

impl ToJwk for GenericKey<'_> {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        self.0
            .as_jwk_encoder()
            .ok_or_else(|| err_msg!(Unsupported))?
            .encode_jwk(enc)
    }
}
