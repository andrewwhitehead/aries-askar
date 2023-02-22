use std::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use digest::crypto_common::BlockSizeUser;
use hmac::{digest::Digest, Mac, SimpleHmac};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        self,
        buffer::{FixedBufferCore, SecretArray},
        generic_array::typenum::Unsigned,
        key::{KeyGen, KeyMaterial},
        repr::SecretBytesCore,
    },
    error::Error,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    transparent,
    bound(
        deserialize = "SecretArray<L>: for<'a> Deserialize<'a>",
        serialize = "SecretArray<L>: Serialize"
    )
)]
pub struct HmacKey<H, const L: usize>(SecretArray<L>, PhantomData<H>);

impl<H, const L: usize> HmacKey<H, L> {
    #[allow(dead_code)]
    pub fn from_slice(key: &[u8]) -> Result<Self, Error> {
        if key.len() != L {
            return Err(err_msg!(Encryption, "invalid length for hmac key"));
        }
        Ok(Self(SecretArray::from_slice(key), PhantomData))
    }
}

impl<H, const L: usize> Debug for HmacKey<H, L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if cfg!(test) {
            f.debug_tuple("HmacKey").field(&*self).finish()
        } else {
            f.debug_tuple("HmacKey").field(&"<secret>").finish()
        }
    }
}

impl<H, const L: usize> PartialEq for HmacKey<H, L> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<H, const L: usize> Eq for HmacKey<H, L> {}

impl<H, const L: usize> KeyGen for HmacKey<H, L> {
    fn generate(source: impl KeyMaterial) -> Result<Self, crate::crypto::Error> {
        Ok(Self(SecretArray::generate(source)?, PhantomData))
    }
}

impl<H, const L: usize> SecretBytesCore for HmacKey<H, L> {
    const SECRET_BYTES_LEN: usize = L;

    fn access_secret_bytes<O>(
        &self,
        f: impl FnOnce(&[u8]) -> Result<O, crypto::Error>,
    ) -> Result<O, crypto::Error> {
        self.0.access_secret_bytes(f)
    }
}

pub trait HmacDerive<'d> {
    type Deriver: KeyMaterial + 'd;

    fn hmac_deriver(&'d self, inputs: &'d [&'d [u8]]) -> Self::Deriver;
}

impl<'d, H, const L: usize> HmacDerive<'d> for HmacKey<H, L>
where
    H: Digest + BlockSizeUser + 'd,
{
    type Deriver = HmacDeriver<'d, H, Self>;

    fn hmac_deriver(&'d self, inputs: &'d [&'d [u8]]) -> Self::Deriver {
        HmacDeriver {
            key: self,
            inputs,
            _marker: PhantomData,
        }
    }
}

// pub trait HmacDerive {
//     type Hash: Digest + BlockSizeUser;
//     type Key: AsRef<[u8]>;

//     fn hmac_deriver<'d>(&'d self, inputs: &'d [&'d [u8]])
//         -> HmacDeriver<'d, Self::Hash, Self::Key>;
// }

// impl<H, const L: usize> HmacDerive for HmacKey<H, L>
// where
//     H: Digest + BlockSizeUser,
// {
//     type Hash = H;
//     type Key = Self;

//     #[inline]
//     fn hmac_deriver<'d>(
//         &'d self,
//         inputs: &'d [&'d [u8]],
//     ) -> HmacDeriver<'d, Self::Hash, Self::Key> {
//         HmacDeriver {
//             key: self,
//             inputs,
//             _marker: PhantomData,
//         }
//     }
// }

pub struct HmacDeriver<'d, H, K: ?Sized> {
    key: &'d K,
    inputs: &'d [&'d [u8]],
    _marker: PhantomData<H>,
}

impl<H, K> KeyMaterial for HmacDeriver<'_, H, K>
where
    K: SecretBytesCore + ?Sized,
    H: Digest + BlockSizeUser,
{
    fn key_material_max_len(&self) -> Option<usize> {
        Some(H::OutputSize::USIZE)
    }

    fn copy_key_material(&mut self, buf: &mut [u8]) -> Result<(), crypto::Error> {
        if buf.len() > H::OutputSize::USIZE {
            return Err(crypto::Error::from_msg(
                crypto::ErrorKind::Encryption,
                "invalid length for hmac output",
            ));
        }
        self.key.access_secret_bytes(|key| {
            let mut hmac = SimpleHmac::<H>::new_from_slice(key).map_err(|_| {
                crypto::Error::from_msg(
                    crypto::ErrorKind::Encryption,
                    "invalid length for hmac key",
                )
            })?;
            for msg in self.inputs {
                hmac.update(msg);
            }
            let hash = hmac.finalize().into_bytes();
            buf.copy_from_slice(&hash[..buf.len()]);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn hmac_expected() {
        let key = HmacKey::<Sha256, 32>::from_slice(&hex!(
            "c32ef97a2eed6316ae9b0d3129554358980ee6e0b21b81625229c191a3469f7e"
        ))
        .unwrap();
        let mut output = [0u8; 12];
        key.hmac_deriver(&[b"test message"])
            .copy_key_material(&mut output)
            .unwrap();
        assert_eq!(output, &hex!("4cecfbf6be721395529be686")[..]);
    }
}
