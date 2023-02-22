/// Implement the KeyCore trait body
#[macro_export]
macro_rules! impl_keycore_by_deref {
    () => {
        #[inline]
        fn key_algorithm(&self) -> $crate::alg::KeyAlgorithm {
            (&**self).key_algorithm()
        }

        #[inline]
        fn key_type(&self) -> $crate::key::KeyType {
            (&**self).key_type()
        }

        #[inline]
        fn as_aead(&self) -> Option<&dyn $crate::encrypt::Aead> {
            (&**self).as_aead()
        }

        #[inline]
        fn as_exchange(&self) -> Option<&dyn $crate::kdf::KeyExchange> {
            (&**self).as_exchange()
        }

        #[inline]
        fn as_jwk_encoder(&self) -> Option<&dyn $crate::jwk::ToJwk> {
            (&**self).as_jwk_encoder()
        }

        #[inline]
        fn as_public(&self) -> Option<&dyn $crate::repr::ToPublicBytes> {
            (&**self).as_public()
        }

        #[inline]
        fn as_secret(&self) -> Option<&dyn $crate::repr::ToSecretBytes> {
            (&**self).as_secret()
        }

        #[inline]
        fn as_signer(&self) -> Option<&dyn $crate::sign::CreateSignature> {
            (&**self).as_signer()
        }

        #[inline]
        fn as_verifier(&self) -> Option<&dyn $crate::sign::VerifySignature> {
            (&**self).as_verifier()
        }
    };
}

/// Implement the KeyCore and Key traits
#[macro_export]
macro_rules! impl_key_by_deref {
    ($name:ty) => {
        impl $crate::key::KeyCore for $name {
            $crate::impl_keycore_by_deref!();
        }

        impl $crate::key::Key for $name {
            fn as_any(&self) -> &dyn ::core::any::Any {
                (&**self).as_any()
            }

            fn as_dyn(&self) -> &(dyn $crate::key::Key + 'static) {
                (&**self).as_dyn()
            }
        }

        impl $crate::key::AsKey for $name {
            type Key = <Self as ::core::ops::Deref>::Target;

            fn as_key(&self) -> &Self::Key {
                &**self
            }
        }
    };
}
