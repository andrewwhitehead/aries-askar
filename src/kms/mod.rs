//! Support for cryptographic key management and operations

use std::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

use zeroize::Zeroize;

use crate::error::Error;

mod enc;
pub use enc::{Encrypted, SecretVec, ToDecrypt};

mod envelope;
pub use self::envelope::{
    crypto_box, crypto_box_open, crypto_box_random_nonce, crypto_box_seal, crypto_box_seal_open,
    derive_key_ecdh_1pu, derive_key_ecdh_es,
};

mod entry;
pub use self::entry::{KeyEntry, KeyParams};

mod local_key;
pub use self::local_key::{KeyAlgorithm, LocalKey};

/// Supported categories of KMS entries
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub(crate) enum KmsCategory {
    /// A stored key or keypair
    CryptoKey,
    // future options: Mnemonic, Entropy
}

impl KmsCategory {
    /// Get a reference to a string representing the `KmsCategory`
    pub fn as_str(&self) -> &str {
        match self {
            Self::CryptoKey => "cryptokey",
        }
    }
}

impl AsRef<str> for KmsCategory {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for KmsCategory {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "cryptokey" => Self::CryptoKey,
            _ => return Err(err_msg!("Unknown KMS category: {}", s)),
        })
    }
}

impl Display for KmsCategory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
