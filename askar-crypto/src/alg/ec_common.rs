use core::{
    fmt::{self, Debug, Formatter},
    panic::RefUnwindSafe,
};

use ecdsa::PrimeCurve;
use elliptic_curve::{
    ecdh::SharedSecret, generic_array::GenericArray, FieldSize, ProjectiveArithmetic,
};

use super::{EcCurves, KeyAlgorithm};
use crate::{
    buffer::{FixedSecret, WriteBuffer},
    error::Error,
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::KeyExchangeCore,
    key::{ConcreteKey, KeyCore, KeyGen, KeyMaterial, KeyType},
    repr::{FromPublicBytes, FromSecretBytes, PublicBytesCore, SecretBytesCore},
    sign::{CreateSignature, SignatureType, VerifySignature},
};

/// The 'kty' value of an elliptic curve key JWK
pub const JWK_KEY_TYPE: &str = "EC";

pub type Coord<C> = GenericArray<u8, FieldSize<C>>;

// SECURITY: PublicKey contains an elliptic_curve::AffinePoint, which is always
// checked to be on the curve when loaded:
// <https://github.com/RustCrypto/elliptic-curves/blob/a38df18d221a4ca27851c4523f90ceded6bbd361/p256/src/arithmetic/affine.rs#L94>
// The identity point is rejected when converting into a elliptic_curve::PublicKey.
// This satisfies 5.6.2.3.4 ECC Partial Public-Key Validation Routine from
// NIST SP 800-56A: _Recommendation for Pair-Wise Key-Establishment Schemes
// Using Discrete Logarithm Cryptography_.

#[derive(Clone, Debug)]
pub struct EcKeyPair<C: EcKeyType> {
    // SECURITY: SecretKey zeroizes on drop
    secret: Option<C::SecretKey>,
    public: C::PublicKey,
}

impl<C: EcKeyType> EcKeyPair<C> {
    #[inline]
    pub(crate) fn from_secret_key(sk: C::SecretKey) -> Self {
        let pk = C::derive_pk(&sk);
        Self {
            secret: Some(sk),
            public: pk,
        }
    }

    /// Sign a message with the secret key
    pub fn sign(&self, message: &[u8]) -> Option<C::Signature> {
        self.secret.as_ref().map(|skey| C::sign(skey, message))
    }

    /// Verify a signature with the public key
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        C::verify_signature(&self.public, message, signature)
    }
}

impl<C: EcKeyType> KeyCore for EcKeyPair<C> {
    fn key_algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::EcCurve(C::EC_CURVE)
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

    fn as_signer(&self) -> Option<&dyn CreateSignature> {
        Some(self)
    }

    fn as_verifier(&self) -> Option<&dyn VerifySignature> {
        Some(self)
    }
}
impl<C: EcKeyType> ConcreteKey for EcKeyPair<C> where Self: KeyCore {}

impl<C: EcKeyType> KeyGen for EcKeyPair<C> {
    fn generate(mut source: impl KeyMaterial) -> Result<Self, Error> {
        C::FieldRepr::with_temp(|buf| {
            source.copy_key_material(buf)?;
            Ok(Self::from_secret_key(C::decode_sk(buf)?))
        })
    }
}

impl<C: EcKeyType> PublicBytesCore for EcKeyPair<C> {
    const PUBLIC_BYTES_LEN: usize = C::PointRepr::SIZE;

    fn access_public_bytes(&self, f: impl FnOnce(&[u8]) -> Result<(), Error>) -> Result<(), Error> {
        C::PointRepr::with_temp(|buf| {
            C::encode_pk(&self.public, &mut *buf, true);
            f(buf)
        })
    }
}

impl<C: EcKeyType> FromPublicBytes for EcKeyPair<C> {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        let pk = C::decode_pk(key)?;
        Ok(Self {
            secret: None,
            public: pk,
        })
    }
}

impl<C: EcKeyType> SecretBytesCore for EcKeyPair<C> {
    const SECRET_BYTES_LEN: usize = C::FieldRepr::SIZE;

    fn access_secret_bytes<O>(
        &self,
        f: impl FnOnce(&[u8]) -> Result<O, Error>,
    ) -> Result<O, Error> {
        if let Some(sk) = self.secret.as_ref() {
            C::FieldRepr::with_temp(|arr| {
                C::write_sk(sk, &mut arr[..]);
                f(arr)
            })
        } else {
            Err(err_msg!(Unsupported))
        }
    }
}

impl<C: EcKeyType> FromSecretBytes for EcKeyPair<C> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_secret_key(C::decode_sk(key)?))
    }
}

impl<C: EcKeyType> CreateSignature for EcKeyPair<C> {
    fn default_signature_type(&self) -> Option<SignatureType> {
        Some(C::SIGNATURE_TYPE)
    }

    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        if sig_type.map(|s| s == C::SIGNATURE_TYPE).unwrap_or(true) {
            if let Some(sig) = self.sign(message) {
                out.buffer_write(sig.as_ref())?;
                Ok(())
            } else {
                Err(err_msg!(Unsupported, "Undefined secret key"))
            }
        } else {
            Err(err_msg!(Unsupported, "Unsupported signature type"))
        }
    }
}

impl<C: EcKeyType> VerifySignature for EcKeyPair<C> {
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        if sig_type.map(|s| s == C::SIGNATURE_TYPE).unwrap_or(true) {
            Ok(self.verify_signature(message, signature))
        } else {
            Err(err_msg!(Unsupported, "Unsupported signature type"))
        }
    }
}

impl<C: EcKeyType> ToJwk for EcKeyPair<C> {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        let (x, y) = C::pk_to_coordinates(&self.public)?;
        enc.add_str("crv", C::JWK_CURVE)?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        enc.add_as_base64("x", &x[..])?;
        enc.add_as_base64("y", &y[..])?;
        if enc.is_secret() {
            self.access_secret_bytes(|buf| enc.add_as_base64("d", buf))?;
        }
        Ok(())
    }
}

impl<C: EcKeyType> FromJwk for EcKeyPair<C> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        if jwk.kty != JWK_KEY_TYPE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key type"));
        }
        if jwk.crv != C::JWK_CURVE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key algorithm"));
        }
        let mut pk_x = GenericArray::default();
        let x_len = jwk.x.decode_base64(&mut pk_x)?;
        let mut pk_y = GenericArray::default();
        let y_len = jwk.y.decode_base64(&mut pk_y)?;
        if x_len != pk_x.len() || y_len != pk_y.len() {
            return Err(err_msg!(
                InvalidKeyData,
                "Invalid public key coordinate length"
            ));
        }
        let pk = C::pk_from_coordinates(&pk_x, &pk_y)?;
        if jwk.d.is_some() {
            C::FieldRepr::with_temp(|arr| {
                if jwk.d.decode_base64(arr)? != arr.len() {
                    Err(err_msg!(InvalidKeyData, "Invalid secret key"))
                } else {
                    let kp = EcKeyPair::<C>::from_secret_bytes(arr)?;
                    if kp.public != pk {
                        Err(err_msg!(InvalidKeyData, "Invalid keypair"))
                    } else {
                        Ok(kp)
                    }
                }
            })
        } else {
            Ok(Self {
                secret: None,
                public: pk,
            })
        }
    }
}

pub struct EcSharedSecret<C: EcKeyType>(pub(crate) SharedSecret<C>);

impl<C: EcKeyType> Debug for EcSharedSecret<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcSharedSecret")
            .field("curve", &C::NAME)
            .finish()
    }
}

impl<C: EcKeyType> SecretBytesCore for EcSharedSecret<C> {
    const SECRET_BYTES_LEN: usize = C::PointRepr::SIZE;

    fn access_secret_bytes<O>(
        &self,
        f: impl FnOnce(&[u8]) -> Result<O, Error>,
    ) -> Result<O, Error> {
        f(self.0.raw_secret_bytes())
    }
}

impl<C: EcKeyType> KeyExchangeCore for EcKeyPair<C> {
    type ExchangeKey = EcSharedSecret<C>;

    fn key_exchange(&self, public: &Self) -> Result<Self::ExchangeKey, Error> {
        match self.secret.as_ref() {
            Some(sk) => Ok(C::key_exchange(sk, &public.public)),
            None => Err(err_msg!(MissingSecretKey)),
        }
    }
}

/// Common trait for concrete elliptic-curve implementations.
/// This mainly exists in order to avoid excessive bounds on
/// the trait implementations for EcKeyPair.
pub trait EcKeyType: PrimeCurve + ProjectiveArithmetic {
    const NAME: &'static str;
    const JWK_CURVE: &'static str;
    const EC_CURVE: EcCurves;
    const SIGNATURE_TYPE: SignatureType;

    type SecretKey: Clone + Debug + PartialEq + Eq + RefUnwindSafe + Send + Sync;
    type PublicKey: Clone + Debug + PartialEq + Eq + RefUnwindSafe + Send + Sync;
    type FieldRepr: FixedSecret;
    type PointRepr: FixedSecret;
    type Signature: AsRef<[u8]>;

    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Signature;

    fn verify_signature(pk: &Self::PublicKey, message: &[u8], signature: &[u8]) -> bool;

    fn derive_pk(sk: &Self::SecretKey) -> Self::PublicKey;

    fn decode_pk(pk: &[u8]) -> Result<Self::PublicKey, Error>;

    fn encode_pk(pk: &Self::PublicKey, out: &mut [u8], compress: bool);

    fn decode_sk(sk: &[u8]) -> Result<Self::SecretKey, Error>;

    fn write_sk(sk: &Self::SecretKey, out: &mut [u8]);

    fn pk_from_coordinates(x: &Coord<Self>, y: &Coord<Self>) -> Result<Self::PublicKey, Error>;

    fn pk_to_coordinates(pk: &Self::PublicKey) -> Result<(Coord<Self>, Coord<Self>), Error>;

    fn key_exchange(sk: &Self::SecretKey, pk: &Self::PublicKey) -> EcSharedSecret<Self>;
}

macro_rules! impl_ec_key_type {
    ($name:expr, $curve:ident, $eccurve:expr, $sigtype:expr, $jwk:expr) => {
        use ecdsa::{
            signature::{Signer, Verifier},
            Signature, SignatureSize, SigningKey, VerifyingKey,
        };
        use elliptic_curve::{
            generic_array::typenum::Unsigned,
            sec1::{Coordinates, EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
            FieldSize, PublicKey, SecretKey,
        };
        use $crate::alg::ec_common::Coord;
        use $crate::buffer::SecretArray;

        impl $crate::alg::ec_common::EcKeyType for $curve {
            const NAME: &'static str = $name;
            const JWK_CURVE: &'static str = $jwk;
            const EC_CURVE: $crate::alg::EcCurves = $eccurve;
            const SIGNATURE_TYPE: $crate::sign::SignatureType = $sigtype;

            type SecretKey = SecretKey<$curve>;
            type PublicKey = PublicKey<$curve>;
            type FieldRepr = SecretArray<{ FieldSize::<$curve>::USIZE }>;
            type PointRepr =
                SecretArray<{ <FieldSize<$curve> as ModulusSize>::CompressedPointSize::USIZE }>;
            type Signature = [u8; <SignatureSize<$curve> as Unsigned>::USIZE];

            fn derive_pk(sk: &Self::SecretKey) -> Self::PublicKey {
                sk.public_key()
            }

            #[inline]
            fn decode_pk(pk: &[u8]) -> Result<Self::PublicKey, $crate::error::Error> {
                PublicKey::from_sec1_bytes(pk)
                    .map_err(|_| err_msg!(InvalidKeyData, "Invalid public key"))
            }

            #[inline]
            fn encode_pk(pk: &Self::PublicKey, out: &mut [u8], compress: bool) {
                out.copy_from_slice(pk.to_encoded_point(compress).as_bytes());
            }

            #[inline]
            fn decode_sk(sk: &[u8]) -> Result<Self::SecretKey, $crate::error::Error> {
                SecretKey::from_be_bytes(sk)
                    .map_err(|_| err_msg!(InvalidKeyData, "Invalid secret key"))
            }

            #[inline]
            fn write_sk(sk: &Self::SecretKey, out: &mut [u8]) {
                const LIMB_SIZE: usize = ::elliptic_curve::bigint::Limb::BYTE_SIZE;
                let limbs = sk.as_scalar_core().as_limbs();
                debug_assert_eq!(out.len(), LIMB_SIZE * limbs.len());

                for (src, dst) in limbs
                    .iter()
                    .rev()
                    .cloned()
                    .zip(out.chunks_exact_mut(LIMB_SIZE))
                {
                    dst.copy_from_slice(&src.0.to_be_bytes());
                }
            }

            #[inline]
            fn pk_from_coordinates(
                pk_x: &Coord<Self>,
                pk_y: &Coord<Self>,
            ) -> Result<Self::PublicKey, $crate::error::Error> {
                Option::from(PublicKey::from_encoded_point(
                    &EncodedPoint::<Self>::from_affine_coordinates(pk_x, pk_y, false),
                ))
                .ok_or_else(|| err_msg!(InvalidKeyData))
            }

            #[inline]
            fn pk_to_coordinates(
                pk: &Self::PublicKey,
            ) -> Result<(Coord<Self>, Coord<Self>), $crate::error::Error> {
                let pk_enc = pk.to_encoded_point(false);
                match pk_enc.coordinates() {
                    Coordinates::Identity => {
                        return Err(err_msg!(
                            Unsupported,
                            "Cannot convert identity point to JWK"
                        ))
                    }
                    Coordinates::Uncompressed { x, y } => Ok((x.clone(), y.clone())),
                    Coordinates::Compressed { .. } | Coordinates::Compact { .. } => unreachable!(),
                }
            }

            #[inline]
            fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Signature {
                let sig: Signature<Self> = SigningKey::from(sk).sign(message);
                sig.to_bytes().as_slice().try_into().unwrap()
            }

            #[inline]
            fn verify_signature(pk: &Self::PublicKey, message: &[u8], signature: &[u8]) -> bool {
                if let Ok(sig) = <&[u8] as TryInto<Signature<$curve>>>::try_into(signature) {
                    let vk = VerifyingKey::<$curve>::from(pk);
                    vk.verify(message, &sig).is_ok()
                } else {
                    false
                }
            }

            #[inline]
            fn key_exchange(
                sk: &Self::SecretKey,
                pk: &Self::PublicKey,
            ) -> $crate::alg::ec_common::EcSharedSecret<Self> {
                let xk =
                    ::elliptic_curve::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
                $crate::alg::ec_common::EcSharedSecret(xk)
            }
        }

        #[cfg(test)]
        #[cfg(any(feature = "alloc", feature = "std_rng"))]
        mod _tests {
            use super::$curve;

            #[cfg(feature = "alloc")]
            #[test]
            fn key_exchange_random() {
                $crate::alg::ec_common::tests::key_exchange_random::<$curve>();
            }

            #[cfg(feature = "alloc")]
            #[test]
            fn round_trip_bytes() {
                $crate::alg::ec_common::tests::round_trip_bytes::<$curve>();
            }

            #[cfg(feature = "std_rng")]
            #[test]
            fn sign_verify_random() {
                $crate::alg::ec_common::tests::sign_verify_random::<$curve>();
            }
        }
    };
}

#[cfg(test)]
pub(super) mod tests {
    #[cfg(any(feature = "alloc", feature = "std_rng"))]
    use super::*;
    #[cfg(feature = "alloc")]
    use crate::generic_array::typenum::Unsigned;
    use crate::kdf::KeyExchange;
    #[cfg(feature = "alloc")]
    use crate::repr::ToSecretBytes;

    #[cfg(feature = "alloc")]
    pub fn key_exchange_random<C: EcKeyType>() {
        let kp1 = EcKeyPair::<C>::random().unwrap();
        let kp2 = EcKeyPair::<C>::random().unwrap();
        assert_ne!(
            kp1.to_secret_bytes().unwrap(),
            kp2.to_secret_bytes().unwrap()
        );

        let xch1 = kp1.key_exchange_bytes(&kp2).unwrap();
        let xch2 = kp2.key_exchange_bytes(&kp1).unwrap();
        assert_eq!(xch1.len(), FieldSize::<C>::USIZE);
        assert_eq!(xch1, xch2);
    }

    #[cfg(feature = "alloc")]
    pub fn round_trip_bytes<C: EcKeyType>() {
        let kp = EcKeyPair::<C>::random().unwrap();
        let cmp = EcKeyPair::<C>::from_secret_bytes(&kp.to_secret_bytes().unwrap()).unwrap();
        assert_eq!(
            kp.to_secret_bytes().unwrap(),
            cmp.to_secret_bytes().unwrap()
        );
    }

    #[cfg(feature = "std_rng")]
    pub fn sign_verify_random<C: EcKeyType>() {
        let test_msg = b"This is a dummy message for use with tests";
        let kp = EcKeyPair::<C>::random().unwrap();
        let sig = kp.sign(&test_msg[..]).unwrap();
        assert!(kp.verify_signature(&test_msg[..], sig.as_ref()));
        assert!(!kp.verify_signature(b"Not the message", sig.as_ref()));
        assert!(!kp.verify_signature(&test_msg[..], &[0u8; 64]));
        assert_eq!(sig.as_ref().len(), C::SIGNATURE_TYPE.signature_length());
    }
}
