use ecdsa::PrimeCurve;
use elliptic_curve::{
    bigint::{Encoding, Limb},
    ecdh::diffie_hellman,
    generic_array::{typenum::Unsigned, GenericArray},
    sec1::ModulusSize,
    Curve, FieldSize, ProjectiveArithmetic, PublicKey, SecretKey,
};

use super::{EcCurves, HasKeyAlg};
use crate::{
    alg::KeyAlg,
    buffer::{ArrayKey, WriteBuffer},
    error::Error,
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::KeyExchange,
    random::KeyMaterial,
    repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairBytes, KeypairMeta},
    sign::{KeySigVerify, KeySign, SignatureType},
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
    secret: Option<SecretKey<C>>,
    public: PublicKey<C>,
}

impl<C: EcKeyType> EcKeyPair<C> {
    #[inline]
    pub(crate) fn from_secret_key(sk: SecretKey<C>) -> Self {
        let pk = sk.public_key();
        Self {
            secret: Some(sk),
            public: pk,
        }
    }

    pub(crate) fn check_public_bytes(&self, pk: &[u8]) -> Result<(), Error> {
        if self.public == C::decode_pk(pk)? {
            Ok(())
        } else {
            Err(err_msg!(InvalidKeyData, "invalid keypair"))
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

impl<C: EcKeyType> HasKeyAlg for EcKeyPair<C> {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::EcCurve(C::EC_CURVE)
    }
}

impl<C: EcKeyType> KeyGen for EcKeyPair<C> {
    fn generate(mut rng: impl KeyMaterial) -> Result<Self, Error> {
        ArrayKey::<C::FieldSize>::temp(|buf| loop {
            rng.read_okm(buf);
            if let Ok(key) = SecretKey::from_be_bytes(buf) {
                return Ok(Self::from_secret_key(key));
            }
        })
    }
}

impl<C: EcKeyType> KeyMeta for EcKeyPair<C> {
    type KeySize = C::FieldSize;
}

impl<C: EcKeyType> KeypairMeta for EcKeyPair<C> {
    type PublicKeySize = <C::FieldSize as ModulusSize>::CompressedPointSize;
    type KeypairSize = <C::FieldSize as ModulusSize>::UncompressedPointSize;
}

impl<C: EcKeyType> KeySecretBytes for EcKeyPair<C> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_secret_key(
            SecretKey::from_be_bytes(key).map_err(|_| err_msg!(InvalidKeyData))?,
        ))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(sk) = self.secret.as_ref() {
            ArrayKey::<C::FieldSize>::temp(|arr| {
                write_sk(sk, &mut arr[..]);
                f(Some(arr))
            })
        } else {
            f(None)
        }
    }
}

impl<C: EcKeyType> KeypairBytes for EcKeyPair<C> {
    fn from_keypair_bytes(kp: &[u8]) -> Result<Self, Error> {
        let field_size = C::FieldSize::USIZE;
        let keypair_length: usize = 1 + field_size * 2;
        if kp.len() != keypair_length {
            return Err(err_msg!(InvalidKeyData));
        }
        let result = EcKeyPair::from_secret_bytes(&kp[..field_size])
            .map_err(|_| err_msg!(InvalidKeyData))?;
        result.check_public_bytes(&kp[field_size..])?;
        Ok(result)
    }

    fn with_keypair_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        let field_size = C::FieldSize::USIZE;
        if let Some(sk) = self.secret.as_ref() {
            ArrayKey::<<Self as KeypairMeta>::KeypairSize>::temp(|arr| {
                write_sk(sk, &mut arr[..field_size]);
                C::encode_pk(&self.public, &mut arr[field_size..], true);
                f(Some(&*arr))
            })
        } else {
            f(None)
        }
    }
}

impl<C: EcKeyType> KeyPublicBytes for EcKeyPair<C> {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        let pk = C::decode_pk(key)?;
        Ok(Self {
            secret: None,
            public: pk,
        })
    }

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O {
        ArrayKey::<Self::PublicKeySize>::temp(|buf| {
            C::encode_pk(&self.public, &mut *buf, true);
            f(buf)
        })
    }
}

impl<C: EcKeyType> KeySign for EcKeyPair<C> {
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

impl<C: EcKeyType> KeySigVerify for EcKeyPair<C> {
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
            self.with_secret_bytes(|buf| {
                if let Some(sk) = buf {
                    enc.add_as_base64("d", sk)
                } else {
                    Ok(())
                }
            })?;
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
        let pk_x = ArrayKey::<FieldSize<C>>::try_new_with(|arr| {
            if jwk.x.decode_base64(arr)? != arr.len() {
                Err(err_msg!(InvalidKeyData))
            } else {
                Ok(())
            }
        })?;
        let pk_y = ArrayKey::<FieldSize<C>>::try_new_with(|arr| {
            if jwk.y.decode_base64(arr)? != arr.len() {
                Err(err_msg!(InvalidKeyData))
            } else {
                Ok(())
            }
        })?;
        let pk = C::pk_from_coordinates(pk_x.as_ref(), pk_y.as_ref())?;
        if jwk.d.is_some() {
            ArrayKey::<C::FieldSize>::temp(|arr| {
                if jwk.d.decode_base64(arr)? != arr.len() {
                    Err(err_msg!(InvalidKeyData))
                } else {
                    let kp = EcKeyPair::<C>::from_secret_bytes(arr)?;
                    if kp.public != pk {
                        Err(err_msg!(InvalidKeyData))
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

impl<C: EcKeyType> KeyExchange for EcKeyPair<C> {
    fn write_key_exchange(&self, other: &Self, out: &mut dyn WriteBuffer) -> Result<(), Error> {
        match self.secret.as_ref() {
            Some(sk) => {
                let xk = diffie_hellman(sk.to_nonzero_scalar(), other.public.as_affine());
                out.buffer_write(&xk.raw_secret_bytes()[..])?;
                Ok(())
            }
            None => Err(err_msg!(MissingSecretKey)),
        }
    }
}

pub fn write_sk<C: Curve>(sk: &SecretKey<C>, out: &mut [u8]) {
    let limbs = sk.as_scalar_core().as_limbs();
    debug_assert_eq!(out.len(), Limb::BYTE_SIZE * limbs.len());

    for (src, dst) in limbs
        .iter()
        .rev()
        .cloned()
        .zip(out.chunks_exact_mut(Limb::BYTE_SIZE))
    {
        dst.copy_from_slice(&src.to_be_bytes());
    }
}

/// Common trait for concrete elliptic-curve implementations.
/// This mainly exists in order to avoid excessive bounds on
/// the trait implementations for EcKeyPair.
pub trait EcKeyType: PrimeCurve + ProjectiveArithmetic {
    const JWK_CURVE: &'static str;
    const EC_CURVE: EcCurves;
    const SIGNATURE_TYPE: SignatureType;

    type FieldSize: ModulusSize;
    type Signature: AsRef<[u8]>;

    fn sign(sk: &SecretKey<Self>, message: &[u8]) -> Self::Signature;

    fn verify_signature(pk: &PublicKey<Self>, message: &[u8], signature: &[u8]) -> bool;

    fn decode_pk(pk: &[u8]) -> Result<PublicKey<Self>, Error>;

    fn encode_pk(pk: &PublicKey<Self>, out: &mut [u8], compress: bool);

    fn pk_from_coordinates(x: &Coord<Self>, y: &Coord<Self>) -> Result<PublicKey<Self>, Error>;

    fn pk_to_coordinates(pk: &PublicKey<Self>) -> Result<(Coord<Self>, Coord<Self>), Error>;
}

macro_rules! impl_ec_key_type {
    ($curve:ident, $eccurve:expr, $sigtype:expr, $jwk:expr) => {
        use ecdsa::{
            signature::{Signer, Verifier},
            Signature, SignatureSize, SigningKey, VerifyingKey,
        };
        use elliptic_curve::{
            generic_array::typenum::Unsigned,
            sec1::{Coordinates, EncodedPoint, FromEncodedPoint, ToEncodedPoint},
            FieldSize, PublicKey, SecretKey,
        };
        use $crate::alg::ec_common::Coord;

        impl $crate::alg::ec_common::EcKeyType for $curve {
            const JWK_CURVE: &'static str = $jwk;
            const EC_CURVE: $crate::alg::EcCurves = $eccurve;
            const SIGNATURE_TYPE: $crate::sign::SignatureType = $sigtype;

            type FieldSize = FieldSize<$curve>;
            type Signature = [u8; <SignatureSize<$curve> as Unsigned>::USIZE];

            #[inline]
            fn decode_pk(pk: &[u8]) -> Result<PublicKey<Self>, $crate::error::Error> {
                PublicKey::from_sec1_bytes(pk).map_err(|_| err_msg!(InvalidKeyData))
            }

            #[inline]
            fn encode_pk(pk: &PublicKey<Self>, out: &mut [u8], compress: bool) {
                out.copy_from_slice(pk.to_encoded_point(compress).as_bytes());
            }

            #[inline]
            fn pk_from_coordinates(
                pk_x: &Coord<Self>,
                pk_y: &Coord<Self>,
            ) -> Result<PublicKey<Self>, $crate::error::Error> {
                Option::from(PublicKey::from_encoded_point(
                    &EncodedPoint::<Self>::from_affine_coordinates(pk_x, pk_y, false),
                ))
                .ok_or_else(|| err_msg!(InvalidKeyData))
            }

            #[inline]
            fn pk_to_coordinates(
                pk: &PublicKey<Self>,
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
            fn sign(sk: &SecretKey<Self>, message: &[u8]) -> Self::Signature {
                let sig: Signature<Self> = SigningKey::from(sk).sign(message);
                sig.to_bytes().as_slice().try_into().unwrap()
            }

            #[inline]
            fn verify_signature(pk: &PublicKey<Self>, message: &[u8], signature: &[u8]) -> bool {
                if let Ok(sig) = <&[u8] as TryInto<Signature<$curve>>>::try_into(signature) {
                    let vk = VerifyingKey::<$curve>::from(pk);
                    vk.verify(message, &sig).is_ok()
                } else {
                    false
                }
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

            #[cfg(feature = "alloc")]
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
    pub fn key_exchange_random<C: EcKeyType>() {
        let kp1 = EcKeyPair::<C>::random().unwrap();
        let kp2 = EcKeyPair::<C>::random().unwrap();
        assert_ne!(
            kp1.to_keypair_bytes().unwrap(),
            kp2.to_keypair_bytes().unwrap()
        );

        let xch1 = kp1.key_exchange_bytes(&kp2).unwrap();
        let xch2 = kp2.key_exchange_bytes(&kp1).unwrap();
        assert_eq!(xch1.len(), C::FieldSize::USIZE);
        assert_eq!(xch1, xch2);
    }

    #[cfg(feature = "alloc")]
    pub fn round_trip_bytes<C: EcKeyType>() {
        let kp = EcKeyPair::<C>::random().unwrap();
        let cmp = EcKeyPair::<C>::from_keypair_bytes(&kp.to_keypair_bytes().unwrap()).unwrap();
        assert_eq!(
            kp.to_keypair_bytes().unwrap(),
            cmp.to_keypair_bytes().unwrap()
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
