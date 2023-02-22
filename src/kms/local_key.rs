use std::fmt::Debug;
use std::str::FromStr;
use std::{borrow::Cow, ops::Deref};

use super::enc::{Encrypted, ToDecrypt};
pub use crate::crypto::{
    alg::KeyAlgorithm,
    buffer::{SecretArray, SecretVec, WriteBuffer},
    encrypt::AeadParams,
    key::KeyMaterial,
};
use crate::{
    crypto::{
        alg::{bls::BlsKeyGen, AnyJwkLoader, BlsCurves, KeyAlgorithmLoader},
        encrypt::Aead,
        impl_key_by_deref,
        jwk::{JwkLoader, ToJwk},
        key::{AllocKey, AllocKeyLoader, AsGenericKey, ConcreteKey, Key},
        random::fill_random,
        repr::{ToPublicBytes, ToSecretBytes},
        sign::{CreateSignature, SignatureType, VerifySignature},
    },
    error::Error,
};

/// An in-memory cryptographic key
#[derive(Debug)]
pub struct LocalKey {
    pub(crate) ephemeral: bool,
    pub(crate) inner: Box<dyn Key>,
}

impl Deref for LocalKey {
    type Target = dyn Key;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl_key_by_deref!(LocalKey);

struct LocalKeyCreate(bool);

impl AllocKey for LocalKeyCreate {
    type Key = LocalKey;

    fn alloc_key<K: ConcreteKey>(&self, inner: K) -> Self::Key {
        LocalKey {
            inner: Box::new(inner),
            ephemeral: self.0,
        }
    }
}

impl LocalKey {
    /// Create a new random key or keypair
    pub fn generate(alg: KeyAlgorithm, ephemeral: bool) -> Result<Self, Error> {
        Ok(Self::factory(alg, ephemeral).random()?)
    }

    #[inline]
    fn factory(alg: KeyAlgorithm, ephemeral: bool) -> KeyAlgorithmLoader<LocalKeyCreate> {
        KeyAlgorithmLoader(LocalKeyCreate(ephemeral), alg)
    }

    /// Create a new deterministic key or keypair
    pub fn from_seed(alg: KeyAlgorithm, seed: &[u8], method: Option<&str>) -> Result<Self, Error> {
        let alloc = Self::factory(alg, false);
        match method {
            Some("bls_keygen") => Ok(alloc.generate(BlsKeyGen::new(seed)?)?),
            None | Some("") => Ok(alloc.seeded(seed)?),
            _ => Err(err_msg!(
                Unsupported,
                "Unknown seed method for key generation"
            )),
        }
    }

    /// Create a new key or keypair from key material input
    pub fn from_key_material(alg: KeyAlgorithm, source: impl KeyMaterial) -> Result<Self, Error> {
        Ok(Self::factory(alg, false).generate(source)?)
    }

    /// Import a key or keypair from a JWK in binary format
    pub fn from_jwk(alg: Option<KeyAlgorithm>, jwk: &[u8]) -> Result<Self, Error> {
        Ok(AnyJwkLoader(LocalKeyCreate(false), alg).load_jwk(jwk)?)
    }

    /// Import a public key from its compact representation
    pub fn from_public_bytes(alg: KeyAlgorithm, public: &[u8]) -> Result<Self, Error> {
        Ok(Self::factory(alg, false).load_public_bytes(public)?)
    }

    /// Import a symmetric key or public-private keypair from its compact representation
    pub fn from_secret_bytes(alg: KeyAlgorithm, secret: &[u8]) -> Result<Self, Error> {
        Ok(Self::factory(alg, false).load_secret_bytes(secret)?)
    }

    /// Export the raw bytes of the private key
    pub fn to_secret_bytes(&self) -> Result<SecretVec, Error> {
        Ok(self.inner.as_generic().to_secret_bytes()?)
    }

    /// Export the raw bytes of the public key
    pub fn to_public_bytes(&self) -> Result<SecretVec, Error> {
        Ok(self.inner.as_generic().to_public_bytes()?)
    }

    pub(crate) fn encode(&self) -> Result<SecretVec, Error> {
        Ok(self.inner.as_generic().to_jwk_secret(None)?)
    }

    /// Accessor for the key algorithm
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.inner.key_algorithm()
    }

    /// Get the public JWK representation for this key or keypair
    pub fn to_jwk_public(&self, alg: Option<KeyAlgorithm>) -> Result<String, Error> {
        Ok(self.inner.as_generic().to_jwk_public(alg)?)
    }

    /// Get the JWK representation for this private key or keypair
    pub fn to_jwk_secret(&self) -> Result<SecretVec, Error> {
        Ok(self.inner.as_generic().to_jwk_secret(None)?)
    }

    /// Get the JWK thumbprint for this key or keypair
    pub fn to_jwk_thumbprint(&self, alg: Option<KeyAlgorithm>) -> Result<String, Error> {
        Ok(self.inner.as_generic().to_jwk_thumbprint(alg)?)
    }

    /// Get the set of indexed JWK thumbprints for this key or keypair
    pub fn to_jwk_thumbprints(&self) -> Result<Vec<String>, Error> {
        let gen = self.inner.as_generic();
        if self.inner.key_algorithm() == KeyAlgorithm::Bls12_381(BlsCurves::G1G2) {
            Ok(vec![
                gen.to_jwk_thumbprint(Some(KeyAlgorithm::Bls12_381(BlsCurves::G1)))?,
                gen.to_jwk_thumbprint(Some(KeyAlgorithm::Bls12_381(BlsCurves::G2)))?,
            ])
        } else {
            Ok(vec![gen.to_jwk_thumbprint(None)?])
        }
    }

    /// Map this key or keypair to its equivalent for another key algorithm
    pub fn convert_key(&self, alg: KeyAlgorithm) -> Result<Self, Error> {
        Ok(Self::factory(alg, false).convert_key(&self.inner)?)
    }

    /// Fetch the AEAD parameter lengths
    pub fn aead_params(&self) -> Result<AeadParams, Error> {
        let params = self.inner.as_generic().aead_params();
        if params.tag_length == 0 {
            return Err(err_msg!(
                Unsupported,
                "AEAD is not supported for this key type"
            ));
        }
        Ok(params)
    }

    /// Calculate the padding required for a message
    pub fn aead_padding(&self, msg_len: usize) -> usize {
        self.inner.as_generic().aead_padding(msg_len)
    }

    /// Create a new random nonce for AEAD message encryption
    pub fn aead_random_nonce(&self) -> Result<Vec<u8>, Error> {
        let nonce_len = self.inner.as_generic().aead_params().nonce_length;
        if nonce_len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0; nonce_len];
        fill_random(&mut buf);
        Ok(buf)
    }

    /// Perform AEAD message encryption with this encryption key
    pub fn aead_encrypt(
        &self,
        message: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Encrypted, Error> {
        let gen = self.inner.as_generic();
        let params = gen.aead_params();
        let mut nonce = Cow::Borrowed(nonce);
        if nonce.is_empty() && params.nonce_length > 0 {
            nonce = Cow::Owned(self.aead_random_nonce()?);
        }
        let pad_len = gen.aead_padding(message.len());
        let mut buf =
            SecretVec::from_slice_reserve(message, pad_len + params.tag_length + nonce.len());
        let tag_pos = gen.encrypt_in_place(&mut buf, nonce.as_ref(), aad)?;
        let nonce_pos = buf.len();
        if !nonce.is_empty() {
            buf.extend_from_slice(nonce.as_ref());
        }
        Ok(Encrypted::new(buf, tag_pos, nonce_pos))
    }

    /// Perform AEAD message decryption with this encryption key
    pub fn aead_decrypt<'d>(
        &'d self,
        ciphertext: impl Into<ToDecrypt<'d>>,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<SecretVec, Error> {
        let mut buf = ciphertext.into().into_secret();
        self.inner
            .as_generic()
            .decrypt_in_place(&mut buf, nonce, aad)?;
        Ok(buf)
    }

    /// Sign a message with this private signing key
    pub fn sign_message(&self, message: &[u8], sig_type: Option<&str>) -> Result<Vec<u8>, Error> {
        let mut sig = Vec::new();
        self.inner.as_generic().write_signature(
            message,
            sig_type.map(SignatureType::from_str).transpose()?,
            &mut sig,
        )?;
        Ok(sig)
    }

    /// Verify a message signature with this private signing key or public verification key
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<&str>,
    ) -> Result<bool, Error> {
        Ok(self.inner.as_generic().verify_signature(
            message,
            signature,
            sig_type.map(SignatureType::from_str).transpose()?,
        )?)
    }

    /// Wrap another key using this key
    pub fn wrap_key(&self, key: &LocalKey, nonce: &[u8]) -> Result<Encrypted, Error> {
        let gen = self.inner.as_generic();
        let params = self.inner.as_generic().aead_params();
        let mut buf = SecretVec::with_capacity(
            key.inner.as_generic().secret_bytes_len() + params.tag_length + params.nonce_length,
        );
        key.inner.as_generic().write_secret_bytes(&mut buf)?;
        let tag_pos = gen.encrypt_in_place(&mut buf, nonce, &[])?;
        let nonce_pos = buf.len();
        buf.extend_from_slice(nonce);
        Ok(Encrypted::new(buf, tag_pos, nonce_pos))
    }

    /// Unwrap a key using this key
    pub fn unwrap_key<'d>(
        &'d self,
        alg: KeyAlgorithm,
        ciphertext: impl Into<ToDecrypt<'d>>,
        nonce: &[u8],
    ) -> Result<Self, Error> {
        let mut buf = ciphertext.into().into_secret();
        self.inner
            .as_generic()
            .decrypt_in_place(&mut buf, nonce, &[])?;
        Self::from_secret_bytes(alg, buf.as_ref())
    }
}
