use super::kdf::KdfMethod;

use super::pass_key::PassKey;
use crate::{
    crypto::{
        alg::chacha20::{Chacha20Key, C20P},
        buffer::{ArrayKey, ResizeBuffer, SecretBytes},
        encrypt::{KeyAeadInPlace, KeyAeadMeta},
        random::RandomDet,
        repr::{KeyGen, KeyMeta, KeySecretBytes},
    },
    error::Error,
};

pub const PREFIX_KDF: &str = "kdf";
pub const PREFIX_RAW: &str = "raw";
pub const PREFIX_NONE: &str = "none";

pub type StoreKeyType = Chacha20Key<C20P>;

type StoreKeyNonce = ArrayKey<<StoreKeyType as KeyAeadMeta>::NonceSize>;

/// Create a new raw (non-derived) store key
pub fn generate_raw_store_key(seed: Option<&[u8]>) -> Result<PassKey<'static>, Error> {
    let key = if let Some(seed) = seed {
        StoreKey::from(StoreKeyType::generate(RandomDet::new(seed))?)
    } else {
        StoreKey::from(StoreKeyType::random()?)
    };
    Ok(key.to_passkey())
}

pub fn parse_raw_store_key(raw_key: &str) -> Result<StoreKey, Error> {
    ArrayKey::<<StoreKeyType as KeyMeta>::KeySize>::temp(|key| {
        let key_len = bs58::decode(raw_key)
            .into(&mut *key)
            .map_err(|_| err_msg!(Input, "Error parsing raw key as base58 value"))?;
        if key_len != key.len() {
            Err(err_msg!(Input, "Incorrect length for encoded raw key"))
        } else {
            Ok(StoreKey::from(StoreKeyType::from_secret_bytes(&*key)?))
        }
    })
}

#[derive(Clone, Debug)]
pub struct StoreKey(pub Option<StoreKeyType>);

impl StoreKey {
    pub const fn empty() -> Self {
        Self(None)
    }

    pub fn random() -> Result<Self, Error> {
        Ok(Self(Some(StoreKeyType::random()?)))
    }

    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub fn wrap_data(&self, mut data: SecretBytes) -> Result<Vec<u8>, Error> {
        match &self.0 {
            Some(key) => {
                let nonce = StoreKeyNonce::random();
                key.encrypt_in_place(&mut data, nonce.as_ref(), &[])?;
                data.buffer_insert(0, nonce.as_ref())?;
                Ok(data.into_vec())
            }
            None => Ok(data.into_vec()),
        }
    }

    pub fn unwrap_data(&self, ciphertext: Vec<u8>) -> Result<SecretBytes, Error> {
        match &self.0 {
            Some(key) => {
                let nonce = StoreKeyNonce::from_slice(&ciphertext[..StoreKeyNonce::SIZE]);
                let mut buffer = SecretBytes::from(ciphertext);
                buffer.buffer_remove(0..StoreKeyNonce::SIZE)?;
                key.decrypt_in_place(&mut buffer, nonce.as_ref(), &[])?;
                Ok(buffer)
            }
            None => Ok(ciphertext.into()),
        }
    }

    pub fn to_passkey(&self) -> PassKey<'static> {
        if let Some(key) = self.0.as_ref() {
            PassKey::from(key.with_secret_bytes(|sk| bs58::encode(sk.unwrap()).into_string()))
        } else {
            PassKey::empty()
        }
    }
}

impl From<StoreKeyType> for StoreKey {
    fn from(data: StoreKeyType) -> Self {
        Self(Some(data))
    }
}

/// Supported methods for generating or referencing a new store key
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum StoreKeyMethod {
    // CreateManagedKey(String),
    // ExistingManagedKey(String),
    /// Derive a new wrapping key using a key derivation function
    DeriveKey(KdfMethod),
    /// Wrap using an externally-managed raw key
    RawKey,
    /// No wrapping key in effect
    Unprotected,
}

impl StoreKeyMethod {
    pub(crate) fn parse_uri(uri: &str) -> Result<Self, Error> {
        let mut prefix_and_detail = uri.splitn(2, ':');
        let prefix = prefix_and_detail.next().unwrap_or_default();
        // let detail = prefix_and_detail.next().unwrap_or_default();
        match prefix {
            PREFIX_RAW => Ok(Self::RawKey),
            PREFIX_KDF => {
                let (method, _) = KdfMethod::decode(uri)?;
                Ok(Self::DeriveKey(method))
            }
            PREFIX_NONE => Ok(Self::Unprotected),
            _ => Err(err_msg!(Unsupported, "Invalid store key method")),
        }
    }

    pub(crate) fn resolve(
        &self,
        pass_key: PassKey<'_>,
    ) -> Result<(StoreKey, StoreKeyReference), Error> {
        match self {
            // Self::CreateManagedKey(_mgr_ref) => unimplemented!(),
            // Self::ExistingManagedKey(String) => unimplemented!(),
            Self::DeriveKey(method) => {
                if !pass_key.is_none() {
                    let (key, detail) = method.derive_new_key(&*pass_key)?;
                    let key_ref = StoreKeyReference::DeriveKey(*method, detail);
                    Ok((key, key_ref))
                } else {
                    Err(err_msg!(Input, "Key derivation password not provided"))
                }
            }
            Self::RawKey => {
                let key = if !pass_key.is_empty() {
                    parse_raw_store_key(&*pass_key)?
                } else {
                    StoreKey::random()?
                };
                Ok((key, StoreKeyReference::RawKey))
            }
            Self::Unprotected => Ok((StoreKey::empty(), StoreKeyReference::Unprotected)),
        }
    }
}

impl Default for StoreKeyMethod {
    fn default() -> Self {
        Self::DeriveKey(KdfMethod::Argon2i(Default::default()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum StoreKeyReference {
    // ManagedKey(String),
    DeriveKey(KdfMethod, String),
    RawKey,
    Unprotected,
}

impl StoreKeyReference {
    pub fn parse_uri(uri: &str) -> Result<Self, Error> {
        let mut prefix_and_detail = uri.splitn(2, ':');
        let prefix = prefix_and_detail.next().unwrap_or_default();
        match prefix {
            PREFIX_RAW => Ok(Self::RawKey),
            PREFIX_KDF => {
                let (method, detail) = KdfMethod::decode(uri)?;
                Ok(Self::DeriveKey(method, detail))
            }
            PREFIX_NONE => Ok(Self::Unprotected),
            _ => Err(err_msg!(
                Unsupported,
                "Invalid store key method for reference"
            )),
        }
    }

    pub fn compare_method(&self, method: &StoreKeyMethod) -> bool {
        match self {
            // Self::ManagedKey(_keyref) => matches!(method, WrapKeyMethod::CreateManagedKey(..)),
            Self::DeriveKey(kdf_method, _detail) => {
                matches!(method, StoreKeyMethod::DeriveKey(m) if m == kdf_method)
            }
            Self::RawKey => *method == StoreKeyMethod::RawKey,
            Self::Unprotected => *method == StoreKeyMethod::Unprotected,
        }
    }

    pub fn into_uri(self) -> String {
        match self {
            // Self::ManagedKey(keyref) => keyref,
            Self::DeriveKey(method, detail) => method.encode(Some(detail.as_str())),
            Self::RawKey => PREFIX_RAW.to_string(),
            Self::Unprotected => PREFIX_NONE.to_string(),
        }
    }

    pub fn resolve(&self, pass_key: PassKey<'_>) -> Result<StoreKey, Error> {
        match self {
            // Self::ManagedKey(_key_ref) => unimplemented!(),
            Self::DeriveKey(method, detail) => {
                if !pass_key.is_none() {
                    method.derive_key(&*pass_key, detail)
                } else {
                    Err(err_msg!(Input, "Key derivation password not provided"))
                }
            }
            Self::RawKey => {
                if !pass_key.is_empty() {
                    parse_raw_store_key(&*pass_key)
                } else {
                    Err(err_msg!(Input, "Encoded raw key not provided"))
                }
            }
            Self::Unprotected => Ok(StoreKey::empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn protection_method_parse() {
        let parse = StoreKeyMethod::parse_uri;
        assert_eq!(parse("none"), Ok(StoreKeyMethod::Unprotected));
        assert_eq!(parse("raw"), Ok(StoreKeyMethod::RawKey));
        assert_eq!(
            parse("kdf:argon2i"),
            Ok(StoreKeyMethod::DeriveKey(KdfMethod::Argon2i(
                Default::default()
            )))
        );
        assert_eq!(
            parse("other:method:etc").unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn derived_key_wrap() {
        let input = b"test data";
        let pass = PassKey::from("pass");
        let (key, key_ref) = StoreKeyMethod::DeriveKey(KdfMethod::Argon2i(Default::default()))
            .resolve(pass.as_ref())
            .expect("Error deriving new key");
        assert!(!key.is_empty());
        let wrapped = key
            .wrap_data((&input[..]).into())
            .expect("Error wrapping input");
        assert_ne!(wrapped, &input[..]);
        let unwrapped = key.unwrap_data(wrapped).expect("Error unwrapping data");
        assert_eq!(unwrapped, &input[..]);
        let key_uri = key_ref.into_uri();
        assert!(key_uri.starts_with("kdf:argon2i:13:mod?salt="));
    }

    #[test]
    fn derived_key_unwrap_expected() {
        let input = b"test data";
        let wrapped = Vec::from(hex!(
            "c29c66fde50b30b8a077da1ea9bcf4dfeb5fabea12050973aed0e8251f20fad8205cfd2dec"
        ));
        let pass = PassKey::from("pass");
        let key_ref = StoreKeyReference::parse_uri(
            "kdf:argon2i:13:mod?salt=a553cfb9c558b5c11c78efcfa06f3e29",
        )
        .expect("Error parsing derived key ref");
        let key = key_ref.resolve(pass).expect("Error deriving existing key");
        let unwrapped = key.unwrap_data(wrapped).expect("Error unwrapping data");
        assert_eq!(unwrapped, &input[..]);
    }

    #[test]
    fn derived_key_check_bad_password() {
        let wrapped = Vec::from(hex!(
            "c29c66fde50b30b8a077da1ea9bcf4dfeb5fabea12050973aed0e8251f20fad8205cfd2dec"
        ));
        let key_ref = StoreKeyReference::parse_uri(
            "kdf:argon2i:13:mod?salt=a553cfb9c558b5c11c78efcfa06f3e29",
        )
        .expect("Error parsing derived key ref");
        let check_bad_pass = key_ref
            .resolve("not my pass".into())
            .expect("Error deriving comparison key");
        let unwrapped_err = check_bad_pass.unwrap_data(wrapped);
        assert!(unwrapped_err.is_err());
    }

    #[test]
    fn raw_key_seed_lengths() {
        // 'short' is less than 32 bytes
        let _ = generate_raw_store_key(Some(b"short key"))
            .expect("Error creating raw key from short seed");
        // 'long' is greater than 32 bytes
        let _ = generate_raw_store_key(Some(
            b"long key long key long key long key long key long key long key",
        ))
        .expect("Error creating raw key from long seed");
    }

    #[test]
    fn raw_key_wrap() {
        let input = b"test data";
        let raw_key = generate_raw_store_key(None).unwrap();

        let (key, key_ref) = StoreKeyMethod::RawKey
            .resolve(raw_key.as_ref())
            .expect("Error resolving raw key");
        assert!(!key.is_empty());
        let wrapped = key
            .wrap_data((&input[..]).into())
            .expect("Error wrapping input");
        assert_ne!(wrapped, &input[..]);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref = StoreKeyReference::parse_uri(&key_uri).expect("Error parsing raw key URI");
        let key = key_ref.resolve(raw_key).expect("Error resolving raw key");

        let unwrapped = key.unwrap_data(wrapped).expect("Error unwrapping data");
        assert_eq!(unwrapped, &input[..]);

        let check_no_key = key_ref.resolve(None.into());
        assert!(check_no_key.is_err());

        let check_bad_key = key_ref.resolve("not the key".into());
        assert!(check_bad_key.is_err());
    }

    #[test]
    fn unprotected_wrap() {
        let input = b"test data";
        let (key, key_ref) = StoreKeyMethod::Unprotected
            .resolve(None.into())
            .expect("Error resolving unprotected");
        assert!(key.is_empty());
        let wrapped = key
            .wrap_data((&input[..]).into())
            .expect("Error wrapping unprotected");
        assert_eq!(wrapped, &input[..]);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref =
            StoreKeyReference::parse_uri(&key_uri).expect("Error parsing unprotected key ref");
        let key = key_ref
            .resolve(None.into())
            .expect("Error resolving unprotected key ref");

        let unwrapped = key
            .unwrap_data(wrapped)
            .expect("Error unwrapping unprotected");
        assert_eq!(unwrapped, &input[..]);
    }
}
