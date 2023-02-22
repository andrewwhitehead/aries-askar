//! X25519 key exchange support on Curve25519

use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
};

use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret as SecretKey};
use zeroize::Zeroizing;

use super::{ed25519::Ed25519KeyPair, KeyAlgorithm};
use crate::{
    buffer::{FixedSecret, SecretArray},
    error::Error,
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::KeyExchangeCore,
    key::{ConcreteKey, KeyCore, KeyGen, KeyMaterial, KeyType},
    repr::{FromPublicBytes, FromSecretBytes, PublicBytesCore, SecretBytesCore},
};

// FIXME: reject low-order points?
// <https://github.com/tendermint/tmkms/pull/279>
// vs. <https://cr.yp.to/ecdh.html> which indicates that all points are safe for normal D-H.

/// The length of a public key in bytes
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// The length of a secret key in bytes
pub const SECRET_KEY_LENGTH: usize = 32;
/// The length of a keypair in bytes
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

/// The 'kty' value of an X25519 JWK
pub static JWK_KEY_TYPE: &str = "OKP";
/// The 'crv' value of an X25519 JWK
pub static JWK_CURVE: &str = "X25519";

/// An X25519 public key or keypair
#[derive(Clone)]
pub struct X25519KeyPair {
    // SECURITY: SecretKey (StaticSecret) zeroizes on drop
    pub(crate) secret: Option<SecretKey>,
    pub(crate) public: PublicKey,
}

impl X25519KeyPair {
    #[inline(always)]
    pub(crate) fn new(sk: Option<SecretKey>, pk: PublicKey) -> Self {
        Self {
            secret: sk,
            public: pk,
        }
    }

    #[inline]
    pub(crate) fn from_secret_key(sk: SecretKey) -> Self {
        let public = PublicKey::from(&sk);
        Self {
            secret: Some(sk),
            public,
        }
    }

    pub(crate) fn check_public_bytes(&self, pk: &[u8]) -> Result<(), Error> {
        if self.public.as_bytes().ct_eq(pk).into() {
            Ok(())
        } else {
            Err(err_msg!(InvalidKeyData, "invalid x25519 keypair"))
        }
    }
}

impl Debug for X25519KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field(
                "secret",
                if self.secret.is_some() {
                    &"<secret>"
                } else {
                    &"None"
                },
            )
            .field("public", &self.public)
            .finish()
    }
}

impl KeyCore for X25519KeyPair {
    fn key_algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::X25519
    }

    fn key_type(&self) -> KeyType {
        if self.secret.is_some() {
            KeyType::AsymmetricPair
        } else {
            KeyType::AsymmetricPublic
        }
    }

    fn as_exchange(&self) -> Option<&dyn crate::kdf::KeyExchange> {
        Some(self)
    }

    fn as_jwk_encoder(&self) -> Option<&dyn ToJwk> {
        Some(self)
    }

    fn as_public(&self) -> Option<&dyn crate::repr::ToPublicBytes> {
        Some(self)
    }

    fn as_secret(&self) -> Option<&dyn crate::repr::ToSecretBytes> {
        Some(self)
    }
}
impl ConcreteKey for X25519KeyPair {}

impl KeyGen for X25519KeyPair {
    fn generate(source: impl KeyMaterial) -> Result<Self, Error> {
        let sk = SecretArray::<{ Self::SECRET_BYTES_LEN }>::generate(source)?;
        let sk = SecretKey::from(sk.into_array());
        let pk = PublicKey::from(&sk);
        Ok(Self::new(Some(sk), pk))
    }
}

impl SecretBytesCore for X25519KeyPair {
    const SECRET_BYTES_LEN: usize = 32;

    fn access_secret_bytes<O>(
        &self,
        f: impl FnOnce(&[u8]) -> Result<O, Error>,
    ) -> Result<O, Error> {
        if let Some(sk) = self.secret.as_ref() {
            let buf = Zeroizing::new(sk.to_bytes());
            f(buf.as_ref())
        } else {
            Err(err_msg!(Unsupported))
        }
    }
}

impl FromSecretBytes for X25519KeyPair {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != SECRET_KEY_LENGTH {
            return Err(err_msg!(InvalidKeyData));
        }
        Ok(Self::from_secret_key(SecretKey::from(
            TryInto::<[u8; SECRET_KEY_LENGTH]>::try_into(key).unwrap(),
        )))
    }
}

impl PublicBytesCore for X25519KeyPair {
    const PUBLIC_BYTES_LEN: usize = 32;

    fn access_public_bytes(&self, f: impl FnOnce(&[u8]) -> Result<(), Error>) -> Result<(), Error> {
        f(&self.public.to_bytes()[..])
    }
}

impl FromPublicBytes for X25519KeyPair {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != PUBLIC_KEY_LENGTH {
            return Err(err_msg!(InvalidKeyData));
        }
        Ok(Self::new(
            None,
            PublicKey::from(TryInto::<[u8; PUBLIC_KEY_LENGTH]>::try_into(key).unwrap()),
        ))
    }
}

impl ToJwk for X25519KeyPair {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        enc.add_str("crv", JWK_CURVE)?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        self.access_public_bytes(|buf| enc.add_as_base64("x", buf))?;
        if enc.is_secret() {
            self.access_secret_bytes(|buf| enc.add_as_base64("d", buf))?;
        }
        Ok(())
    }
}

impl FromJwk for X25519KeyPair {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        if jwk.kty != JWK_KEY_TYPE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key type"));
        }
        if jwk.crv != JWK_CURVE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key algorithm"));
        }
        let pk_arr = jwk.x.decode_base64_array::<{ Self::PUBLIC_BYTES_LEN }>()?;
        if jwk.d.is_some() {
            SecretArray::<{ Self::SECRET_BYTES_LEN }>::with_temp(|sk_arr| {
                if jwk.d.decode_base64(sk_arr)? != sk_arr.len() {
                    Err(err_msg!(InvalidKeyData))
                } else {
                    let kp = X25519KeyPair::from_secret_bytes(sk_arr)?;
                    kp.check_public_bytes(&pk_arr)?;
                    Ok(kp)
                }
            })
        } else {
            X25519KeyPair::from_public_bytes(&pk_arr)
        }
    }
}

/// An X25519 shared secret, produced by a key exchange.
pub struct X25519SharedSecret(SharedSecret);

impl Debug for X25519SharedSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519SharedSecret").finish()
    }
}

impl SecretBytesCore for X25519SharedSecret {
    const SECRET_BYTES_LEN: usize = SECRET_KEY_LENGTH;

    fn access_secret_bytes<O>(
        &self,
        f: impl FnOnce(&[u8]) -> Result<O, Error>,
    ) -> Result<O, Error> {
        f(self.0.as_bytes().as_slice())
    }
}

impl KeyExchangeCore for X25519KeyPair {
    type ExchangeKey = X25519SharedSecret;

    fn key_exchange(&self, public: &Self) -> Result<Self::ExchangeKey, Error> {
        match self.secret.as_ref() {
            Some(sk) => {
                let xk = sk.diffie_hellman(&public.public);
                Ok(X25519SharedSecret(xk))
            }
            None => Err(err_msg!(MissingSecretKey)),
        }
    }
}

impl TryFrom<&Ed25519KeyPair> for X25519KeyPair {
    type Error = Error;

    fn try_from(value: &Ed25519KeyPair) -> Result<Self, Self::Error> {
        Ok(value.to_x25519_keypair())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KeyExchange;
    #[cfg(feature = "alloc")]
    use crate::repr::{ToPublicBytes, ToSecretBytes};

    #[cfg(feature = "alloc")]
    #[test]
    fn jwk_expected() {
        // {
        //   "kty": "OKP",
        //   "d": "qL25gw-HkNJC9m4EsRzCoUx1KntjwHPzxo6a2xUcyFQ",
        //   "use": "enc",
        //   "crv": "X25519",
        //   "x": "tGskN_ae61DP4DLY31_fjkbvnKqf-ze7kA6Cj2vyQxU"
        // }
        let test_pvt_b64 = "qL25gw-HkNJC9m4EsRzCoUx1KntjwHPzxo6a2xUcyFQ";
        let test_pvt = base64::decode_config(test_pvt_b64, base64::URL_SAFE).unwrap();
        let kp =
            X25519KeyPair::from_secret_bytes(&test_pvt).expect("Error creating x25519 keypair");
        let jwk = kp
            .to_jwk_public(None)
            .expect("Error converting public key to JWK");
        let jwk = JwkParts::try_from(&jwk).expect("Error parsing JWK output");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, "tGskN_ae61DP4DLY31_fjkbvnKqf-ze7kA6Cj2vyQxU");
        assert_eq!(jwk.d, None);
        let pk_load = X25519KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(kp.to_public_bytes(), pk_load.to_public_bytes());

        let jwk = kp
            .to_jwk_secret(None)
            .expect("Error converting private key to JWK")
            .into_vec();
        let jwk = JwkParts::try_from(&jwk).expect("Error parsing JWK output");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, "tGskN_ae61DP4DLY31_fjkbvnKqf-ze7kA6Cj2vyQxU");
        assert_eq!(jwk.d, test_pvt_b64);
        let sk_load = X25519KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(
            kp.to_secret_bytes().unwrap(),
            sk_load.to_secret_bytes().unwrap()
        );
    }

    #[test]
    fn key_exchange_random() {
        let kp1 = X25519KeyPair::random().unwrap();
        let kp2 = X25519KeyPair::random().unwrap();
        assert_ne!(
            kp1.to_secret_bytes().unwrap(),
            kp2.to_secret_bytes().unwrap()
        );

        let xch1 = kp1.key_exchange_bytes(&kp2).unwrap();
        let xch2 = kp2.key_exchange_bytes(&kp1).unwrap();
        assert_eq!(xch1.len(), 32);
        assert_eq!(xch1, xch2);
    }

    #[test]
    fn round_trip_bytes() {
        let kp = X25519KeyPair::random().unwrap();
        let cmp = X25519KeyPair::from_secret_bytes(&kp.to_secret_bytes().unwrap()).unwrap();
        assert_eq!(
            kp.to_secret_bytes().unwrap(),
            cmp.to_secret_bytes().unwrap()
        );
    }
}
