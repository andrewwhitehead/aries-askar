//! AEAD encryption traits and parameters

use crate::{
    buffer::{FixedBuffer, ResizeBuffer},
    error::Error,
};

#[cfg(feature = "getrandom")]
use crate::key::KeyGen;

#[cfg(feature = "crypto_box")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto_box")))]
pub mod crypto_box;

/// Object-safe trait for key types which perform AEAD encryption
pub trait Aead {
    /// Encrypt a secret value in place, appending the verification tag and
    /// returning the length of the ciphertext
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error>;

    /// Decrypt an encrypted (verification tag appended) value in place
    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error>;

    /// Get the nonce and tag length for encryption
    fn aead_params(&self) -> AeadParams;

    /// Get the ciphertext padding required
    fn aead_padding(&self, _msg_len: usize) -> usize {
        0
    }
}

/// For concrete key types with fixed nonce and tag sizes
pub trait AeadMeta {
    /// The size of the AEAD nonce
    type Nonce: FixedBuffer;
    /// The size of the AEAD tag
    type Tag: FixedBuffer;

    /// Generate a new random nonce
    #[cfg(feature = "getrandom")]
    fn random_nonce() -> Self::Nonce {
        Self::Nonce::random().expect("Error creating random nonce")
    }
}

/// A structure combining the AEAD parameters
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AeadParams {
    /// The length of the nonce
    pub nonce_length: usize,
    /// The length of the tag
    pub tag_length: usize,
}
