//! JSON Web Key (JWK) support

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use sha2::Sha256;

#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
use crate::{
    alg::KeyAlg,
    buffer::{HashBuffer, WriteBuffer},
    error::Error,
};

mod encode;
pub use self::encode::{JwkBufferEncoder, JwkEncoder, JwkEncoderMode, JwkSerialize};

mod ops;
pub use self::ops::{KeyOps, KeyOpsSet};

mod parts;
pub use self::parts::JwkParts;

/// Support for converting a key into a JWK
pub trait ToJwk {
    /// Write the JWK representation to an encoder
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error>;

    /// Create the JWK thumbprint of the key
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_jwk_thumbprint(&self, alg: Option<KeyAlg>) -> Result<String, Error> {
        let mut v = Vec::with_capacity(43);
        write_jwk_thumbprint(self, alg, &mut v)?;
        Ok(String::from_utf8(v).unwrap())
    }

    /// Create a JWK of the public key
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_jwk_public(&self, alg: Option<KeyAlg>) -> Result<String, Error> {
        let mut v = Vec::with_capacity(128);
        let mut buf = JwkBufferEncoder::new(&mut v, JwkEncoderMode::PublicKey).alg(alg);
        self.encode_jwk(&mut buf)?;
        buf.finalize()?;
        Ok(String::from_utf8(v).unwrap())
    }

    /// Create a JWK of the secret key
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    fn to_jwk_secret(&self, alg: Option<KeyAlg>) -> Result<SecretBytes, Error> {
        let mut v = SecretBytes::with_capacity(128);
        let mut buf = JwkBufferEncoder::new(&mut v, JwkEncoderMode::SecretKey).alg(alg);
        self.encode_jwk(&mut buf)?;
        buf.finalize()?;
        Ok(v)
    }
}

/// Encode a key's JWK into a buffer
pub fn write_jwk_thumbprint<K: ToJwk + ?Sized>(
    key: &K,
    alg: Option<KeyAlg>,
    output: &mut dyn WriteBuffer,
) -> Result<(), Error> {
    let mut hasher = HashBuffer::<Sha256>::new();
    let mut buf = JwkBufferEncoder::new(&mut hasher, JwkEncoderMode::Thumbprint).alg(alg);
    key.encode_jwk(&mut buf)?;
    buf.finalize()?;
    let hash = hasher.finalize();
    let mut buf = [0u8; 43];
    let len = base64::encode_config_slice(&hash, base64::URL_SAFE_NO_PAD, &mut buf);
    output.buffer_write(&buf[..len])?;
    Ok(())
}

/// Support for loading a key instance from a JWK
pub trait FromJwk: Sized {
    /// Import the key from a JWK string reference
    fn from_jwk(jwk: &str) -> Result<Self, Error> {
        JwkParts::try_from_str(jwk).and_then(Self::from_jwk_parts)
    }

    /// Import the key from a JWK byte slice
    fn from_jwk_slice(jwk: &[u8]) -> Result<Self, Error> {
        JwkParts::from_slice(jwk).and_then(Self::from_jwk_parts)
    }

    /// Import the key from a pre-parsed JWK
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error>;
}
