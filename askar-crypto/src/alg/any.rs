use alloc::{boxed::Box, sync::Arc};

#[cfg(feature = "aes")]
use super::{
    aes::{A128CbcHs256, A128Gcm, A128Kw, A256CbcHs512, A256Gcm, A256Kw, AesKey},
    AesTypes,
};

#[cfg(feature = "bls")]
use super::{
    bls::{BlsKeyPair, BlsPublicKeyType, G1, G1G2, G2},
    BlsCurves,
};

#[cfg(feature = "chacha")]
use super::{
    chacha20::{Chacha20Key, C20P, XC20P},
    Chacha20Types,
};

#[cfg(feature = "ed25519")]
use super::ed25519::{self, Ed25519KeyPair};
#[cfg(feature = "ed25519")]
use super::x25519::{self, X25519KeyPair};

#[cfg(feature = "k256")]
use super::k256::{self, K256KeyPair};

#[cfg(feature = "p256")]
use super::p256::{self, P256KeyPair};

#[cfg(feature = "p384")]
use super::p384::{self, P384KeyPair};

use super::KeyAlgorithm;
use crate::{
    error::Error,
    jwk::{FromJwk, JwkLoader, JwkParts},
    key::{AllocKey, AllocKeyLoader, ArcKey, AsKey, BoxKey, Key, KeyCore, KeyGen, KeyMaterial},
    repr::{FromPublicBytes, FromSecretBytes},
};

#[cfg(any(feature = "k256", feature = "p256"))]
use super::EcCurves;

/// A key loader which supports registered key algorithms
#[derive(Clone, Debug)]
pub struct KeyAlgorithmLoader<R: AllocKey>(pub R, pub KeyAlgorithm);

impl<R: AllocKey> AllocKeyLoader for KeyAlgorithmLoader<R> {
    type Key = R::Key;

    fn generate(&self, source: impl KeyMaterial) -> Result<Self::Key, Error> {
        generate_alloc(&self.0, self.1, source)
    }

    fn load_public_bytes(&self, public: &[u8]) -> Result<R::Key, Error> {
        load_public_bytes_alloc(&self.0, self.1, public)
    }

    fn load_secret_bytes(&self, secret: &[u8]) -> Result<R::Key, Error> {
        load_secret_bytes_alloc(&self.0, self.1, secret)
    }

    fn convert_key(&self, key: &dyn Key) -> Result<R::Key, Error> {
        convert_key_alloc(&self.0, self.1, key)
    }
}

impl KeyAlgorithm {
    /// Create a key loader returning an Arc<dyn Key>
    #[cfg_attr(docsrs, doc(cfg(feature = "any_key")))]
    pub fn arc_load(self) -> KeyAlgorithmLoader<ArcKey> {
        KeyAlgorithmLoader(ArcKey, self)
    }

    /// Create a JWK loader returning an Arc<dyn Key>
    #[cfg_attr(docsrs, doc(cfg(feature = "any_key")))]
    pub fn arc_load_jwk(self) -> AnyJwkLoader<ArcKey> {
        AnyJwkLoader(ArcKey, Some(self))
    }

    /// Create a key loader returning an Box<dyn Key>
    #[cfg_attr(docsrs, doc(cfg(feature = "any_key")))]
    pub fn box_load(self) -> KeyAlgorithmLoader<BoxKey> {
        KeyAlgorithmLoader(BoxKey, self)
    }

    /// Create a JWK loader returning an Box<dyn Key>
    #[cfg_attr(docsrs, doc(cfg(feature = "any_key")))]
    pub fn box_load_jwk(self) -> AnyJwkLoader<BoxKey> {
        AnyJwkLoader(BoxKey, Some(self))
    }
}

#[inline]
fn generate_alloc<R: AllocKey + ?Sized, S: KeyMaterial>(
    alloc: &R,
    alg: KeyAlgorithm,
    source: S,
) -> Result<R::Key, Error> {
    match alg {
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A128Gcm) => {
            alloc.try_alloc_key(|| AesKey::<A128Gcm>::generate(source))
        }
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A256Gcm) => {
            alloc.try_alloc_key(|| AesKey::<A256Gcm>::generate(source))
        }
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A128CbcHs256) => {
            alloc.try_alloc_key(|| AesKey::<A128CbcHs256>::generate(source))
        }
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A256CbcHs512) => {
            alloc.try_alloc_key(|| AesKey::<A256CbcHs512>::generate(source))
        }
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A128Kw) => {
            alloc.try_alloc_key(|| AesKey::<A128Kw>::generate(source))
        }
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A256Kw) => {
            alloc.try_alloc_key(|| AesKey::<A256Kw>::generate(source))
        }
        #[cfg(feature = "bls")]
        KeyAlgorithm::Bls12_381(BlsCurves::G1) => {
            alloc.try_alloc_key(|| BlsKeyPair::<G1>::generate(source))
        }
        #[cfg(feature = "bls")]
        KeyAlgorithm::Bls12_381(BlsCurves::G2) => {
            alloc.try_alloc_key(|| BlsKeyPair::<G2>::generate(source))
        }
        #[cfg(feature = "bls")]
        KeyAlgorithm::Bls12_381(BlsCurves::G1G2) => {
            alloc.try_alloc_key(|| BlsKeyPair::<G1G2>::generate(source))
        }
        #[cfg(feature = "chacha")]
        KeyAlgorithm::Chacha20(Chacha20Types::C20P) => {
            alloc.try_alloc_key(|| Chacha20Key::<C20P>::generate(source))
        }
        #[cfg(feature = "chacha")]
        KeyAlgorithm::Chacha20(Chacha20Types::XC20P) => {
            alloc.try_alloc_key(|| Chacha20Key::<XC20P>::generate(source))
        }
        #[cfg(feature = "ed25519")]
        KeyAlgorithm::Ed25519 => alloc.try_alloc_key(|| Ed25519KeyPair::generate(source)),
        #[cfg(feature = "ed25519")]
        KeyAlgorithm::X25519 => alloc.try_alloc_key(|| X25519KeyPair::generate(source)),
        #[cfg(feature = "k256")]
        KeyAlgorithm::EcCurve(EcCurves::Secp256k1) => {
            alloc.try_alloc_key(|| K256KeyPair::generate(source))
        }
        #[cfg(feature = "p256")]
        KeyAlgorithm::EcCurve(EcCurves::Secp256r1) => {
            alloc.try_alloc_key(|| P256KeyPair::generate(source))
        }
        #[cfg(feature = "p384")]
        KeyAlgorithm::EcCurve(EcCurves::Secp384r1) => {
            alloc.try_alloc_key(|| P384KeyPair::generate(source))
        }
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported algorithm for key generation"
        )),
    }
}

#[inline]
fn load_public_bytes_alloc<R: AllocKey + ?Sized>(
    alloc: &R,
    alg: KeyAlgorithm,
    public: &[u8],
) -> Result<R::Key, Error> {
    match alg {
        #[cfg(feature = "bls")]
        KeyAlgorithm::Bls12_381(BlsCurves::G1) => {
            alloc.try_alloc_key(|| BlsKeyPair::<G1>::from_public_bytes(public))
        }
        #[cfg(feature = "bls")]
        KeyAlgorithm::Bls12_381(BlsCurves::G2) => {
            alloc.try_alloc_key(|| BlsKeyPair::<G2>::from_public_bytes(public))
        }
        #[cfg(feature = "bls")]
        KeyAlgorithm::Bls12_381(BlsCurves::G1G2) => {
            alloc.try_alloc_key(|| BlsKeyPair::<G1G2>::from_public_bytes(public))
        }
        #[cfg(feature = "ed25519")]
        KeyAlgorithm::Ed25519 => alloc.try_alloc_key(|| Ed25519KeyPair::from_public_bytes(public)),
        #[cfg(feature = "ed25519")]
        KeyAlgorithm::X25519 => alloc.try_alloc_key(|| X25519KeyPair::from_public_bytes(public)),
        #[cfg(feature = "k256")]
        KeyAlgorithm::EcCurve(EcCurves::Secp256k1) => {
            alloc.try_alloc_key(|| K256KeyPair::from_public_bytes(public))
        }
        #[cfg(feature = "p256")]
        KeyAlgorithm::EcCurve(EcCurves::Secp256r1) => {
            alloc.try_alloc_key(|| P256KeyPair::from_public_bytes(public))
        }
        #[cfg(feature = "p384")]
        KeyAlgorithm::EcCurve(EcCurves::Secp384r1) => {
            alloc.try_alloc_key(|| P384KeyPair::from_public_bytes(public))
        }
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported algorithm for public key import"
        )),
    }
}

#[inline]
fn load_secret_bytes_alloc<R: AllocKey + ?Sized>(
    alloc: &R,
    alg: KeyAlgorithm,
    secret: &[u8],
) -> Result<R::Key, Error> {
    match alg {
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A128Gcm) => {
            alloc.try_alloc_key(|| AesKey::<A128Gcm>::from_secret_bytes(secret))
        }
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A256Gcm) => {
            alloc.try_alloc_key(|| AesKey::<A256Gcm>::from_secret_bytes(secret))
        }
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A128CbcHs256) => {
            alloc.try_alloc_key(|| AesKey::<A128CbcHs256>::from_secret_bytes(secret))
        }
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A256CbcHs512) => {
            alloc.try_alloc_key(|| AesKey::<A256CbcHs512>::from_secret_bytes(secret))
        }
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A128Kw) => {
            alloc.try_alloc_key(|| AesKey::<A128Kw>::from_secret_bytes(secret))
        }
        #[cfg(feature = "aes")]
        KeyAlgorithm::Aes(AesTypes::A256Kw) => {
            alloc.try_alloc_key(|| AesKey::<A256Kw>::from_secret_bytes(secret))
        }
        #[cfg(feature = "bls")]
        KeyAlgorithm::Bls12_381(BlsCurves::G1) => {
            alloc.try_alloc_key(|| BlsKeyPair::<G1>::from_secret_bytes(secret))
        }
        #[cfg(feature = "bls")]
        KeyAlgorithm::Bls12_381(BlsCurves::G2) => {
            alloc.try_alloc_key(|| BlsKeyPair::<G2>::from_secret_bytes(secret))
        }
        #[cfg(feature = "bls")]
        KeyAlgorithm::Bls12_381(BlsCurves::G1G2) => {
            alloc.try_alloc_key(|| BlsKeyPair::<G1G2>::from_secret_bytes(secret))
        }
        #[cfg(feature = "chacha")]
        KeyAlgorithm::Chacha20(Chacha20Types::C20P) => {
            alloc.try_alloc_key(|| Chacha20Key::<C20P>::from_secret_bytes(secret))
        }
        #[cfg(feature = "chacha")]
        KeyAlgorithm::Chacha20(Chacha20Types::XC20P) => {
            alloc.try_alloc_key(|| Chacha20Key::<XC20P>::from_secret_bytes(secret))
        }
        #[cfg(feature = "ed25519")]
        KeyAlgorithm::Ed25519 => alloc.try_alloc_key(|| Ed25519KeyPair::from_secret_bytes(secret)),
        #[cfg(feature = "ed25519")]
        KeyAlgorithm::X25519 => alloc.try_alloc_key(|| X25519KeyPair::from_secret_bytes(secret)),
        #[cfg(feature = "k256")]
        KeyAlgorithm::EcCurve(EcCurves::Secp256k1) => {
            alloc.try_alloc_key(|| K256KeyPair::from_secret_bytes(secret))
        }
        #[cfg(feature = "p256")]
        KeyAlgorithm::EcCurve(EcCurves::Secp256r1) => {
            alloc.try_alloc_key(|| P256KeyPair::from_secret_bytes(secret))
        }
        #[cfg(feature = "p384")]
        KeyAlgorithm::EcCurve(EcCurves::Secp384r1) => {
            alloc.try_alloc_key(|| P384KeyPair::from_secret_bytes(secret))
        }
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported algorithm for secret key import"
        )),
    }
}

fn assume<K: Key + 'static>(key: &dyn Key) -> &K {
    key.as_any()
        .downcast_ref()
        .expect("Error assuming key type")
}

#[inline]
fn convert_key_alloc<R: AllocKey + ?Sized>(
    alloc: &R,
    alg: KeyAlgorithm,
    key: &dyn Key,
) -> Result<R::Key, Error> {
    match (key.key_algorithm(), alg) {
        #[cfg(feature = "bls")]
        (KeyAlgorithm::Bls12_381(BlsCurves::G1G2), KeyAlgorithm::Bls12_381(BlsCurves::G1)) => {
            Ok(alloc.alloc_key(BlsKeyPair::<G1>::from(assume::<BlsKeyPair<G1G2>>(key))))
        }
        #[cfg(feature = "bls")]
        (KeyAlgorithm::Bls12_381(BlsCurves::G1G2), KeyAlgorithm::Bls12_381(BlsCurves::G2)) => {
            Ok(alloc.alloc_key(BlsKeyPair::<G2>::from(assume::<BlsKeyPair<G1G2>>(key))))
        }
        #[cfg(feature = "ed25519")]
        (KeyAlgorithm::Ed25519, KeyAlgorithm::X25519) => alloc.try_alloc_key(|| {
            <X25519KeyPair as TryFrom<_>>::try_from(assume::<Ed25519KeyPair>(key))
        }),
        #[allow(unreachable_patterns)]
        _ => Err(err_msg!(
            Unsupported,
            "Unsupported key conversion operation"
        )),
    }
}

/// A JWK loader for registered key algorithms
#[derive(Clone, Debug)]
pub struct AnyJwkLoader<R: AllocKey>(pub R, pub Option<KeyAlgorithm>);

impl<R: AllocKey> JwkLoader for AnyJwkLoader<R> {
    type Key = R::Key;

    fn load_jwk_parts(&self, jwk: JwkParts<'_>) -> Result<Self::Key, Error> {
        let key = load_jwk_alloc(&self.0, jwk)?;
        if let Some(alg) = self.1 {
            if key.as_key().key_algorithm() != alg {
                return Err(err_msg!(InvalidKeyData, "Key algorithm mismatch"));
            }
        }
        Ok(key)
    }
}

impl FromJwk for Arc<dyn Key> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        AnyJwkLoader(ArcKey, None).load_jwk_parts(jwk)
    }
}

impl FromJwk for Box<dyn Key> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        AnyJwkLoader(BoxKey, None).load_jwk_parts(jwk)
    }
}

#[inline]
fn load_jwk_alloc<R: AllocKey + ?Sized>(alloc: &R, jwk: JwkParts<'_>) -> Result<R::Key, Error> {
    match (jwk.kty.as_ref(), jwk.crv.as_ref()) {
        #[cfg(feature = "ed25519")]
        ("OKP", c) if c == ed25519::JWK_CURVE => {
            alloc.try_alloc_key(|| Ed25519KeyPair::from_jwk_parts(jwk))
        }
        #[cfg(feature = "ed25519")]
        ("OKP", c) if c == x25519::JWK_CURVE => {
            alloc.try_alloc_key(|| X25519KeyPair::from_jwk_parts(jwk))
        }
        #[cfg(feature = "bls")]
        ("OKP" | "EC", c) if c == G1::JWK_CURVE => {
            alloc.try_alloc_key(|| BlsKeyPair::<G1>::from_jwk_parts(jwk))
        }
        #[cfg(feature = "bls")]
        ("OKP" | "EC", c) if c == G2::JWK_CURVE => {
            alloc.try_alloc_key(|| BlsKeyPair::<G2>::from_jwk_parts(jwk))
        }
        #[cfg(feature = "bls")]
        ("OKP" | "EC", c) if c == G1G2::JWK_CURVE => {
            alloc.try_alloc_key(|| BlsKeyPair::<G1G2>::from_jwk_parts(jwk))
        }
        #[cfg(feature = "k256")]
        ("EC", c) if c == k256::JWK_CURVE => {
            alloc.try_alloc_key(|| K256KeyPair::from_jwk_parts(jwk))
        }
        #[cfg(feature = "p256")]
        ("EC", c) if c == p256::JWK_CURVE => {
            alloc.try_alloc_key(|| P256KeyPair::from_jwk_parts(jwk))
        }
        #[cfg(feature = "p384")]
        ("EC", c) if c == p384::JWK_CURVE => {
            alloc.try_alloc_key(|| P384KeyPair::from_jwk_parts(jwk))
        }
        // FIXME implement symmetric keys?
        _ => Err(err_msg!(Unsupported, "Unsupported JWK for key import")),
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    use crate::key::Key;

    // FIXME - add a custom key type for testing, to allow feature independence

    #[cfg(feature = "ed25519")]
    #[test]
    fn ed25519_as_any() {
        let key = KeyAlgorithm::Ed25519.box_load().random().unwrap();
        assert_eq!(key.key_algorithm(), KeyAlgorithm::Ed25519);
        assert_eq!(
            key.as_any().type_id(),
            core::any::TypeId::of::<Ed25519KeyPair>()
        );
        let _ = key.as_jwk_encoder().unwrap().to_jwk_public(None).unwrap();
    }

    #[cfg(feature = "aes")]
    #[test]
    fn key_exchange_any() {
        let alice = KeyAlgorithm::X25519.box_load().random().unwrap();
        let bob = KeyAlgorithm::X25519.box_load().random().unwrap();
        let exch_a = alice
            .as_exchange()
            .unwrap()
            .key_exchange_bytes(&bob)
            .unwrap();
        let exch_b = bob
            .as_exchange()
            .unwrap()
            .key_exchange_bytes(&alice)
            .unwrap();
        assert_eq!(exch_a, exch_b);
    }

    #[cfg(feature = "chacha")]
    #[test]
    fn key_encrypt_any() {
        use crate::buffer::SecretVec;
        let message = b"test message";
        let mut data = SecretVec::from(&message[..]);

        let key = KeyAlgorithm::Chacha20(Chacha20Types::XC20P)
            .box_load()
            .random()
            .unwrap();
        let aead = key.as_aead().unwrap();
        let nonce = [0u8; 24]; // size varies by algorithm
        aead.encrypt_in_place(&mut data, &nonce, &[]).unwrap();
        assert_ne!(data, &message[..]);
        aead.decrypt_in_place(&mut data, &nonce, &[]).unwrap();
        assert_eq!(data, &message[..]);
    }
}
