use core::{
    fmt::{self, Debug, Display, Formatter},
    ops::{BitAnd, BitOr},
};

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, SerializeSeq, Serializer},
};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

static OPS: &[KeyOps] = &[
    KeyOps::Encrypt,
    KeyOps::Decrypt,
    KeyOps::Sign,
    KeyOps::Verify,
    KeyOps::WrapKey,
    KeyOps::UnwrapKey,
    KeyOps::DeriveKey,
    KeyOps::DeriveBits,
];

/// Supported JWK key operations
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[repr(usize)]
pub enum KeyOps {
    /// Allows encryption
    Encrypt = 1 << 0,
    /// Allows decryption
    Decrypt = 1 << 1,
    /// Allows signature creation
    Sign = 1 << 2,
    /// Allows signature verification
    Verify = 1 << 3,
    /// Allows key wrapping
    WrapKey = 1 << 4,
    /// Allows key unwrapping
    UnwrapKey = 1 << 5,
    /// Allows key derivation
    DeriveKey = 1 << 6,
    /// Allows derivation of bytes
    DeriveBits = 1 << 7,
}

impl Display for KeyOps {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl KeyOps {
    /// String representation of the key operation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::WrapKey => "wrapKey",
            Self::UnwrapKey => "unwrapKey",
            Self::DeriveKey => "deriveKey",
            Self::DeriveBits => "deriveBits",
        }
    }

    /// Parse a key operation from a string reference
    pub fn try_from_str(key: &str) -> Option<Self> {
        match key {
            "sign" => Some(Self::Sign),
            "verify" => Some(Self::Verify),
            "encrypt" => Some(Self::Encrypt),
            "decrypt" => Some(Self::Decrypt),
            "wrapKey" => Some(Self::WrapKey),
            "unwrapKey" => Some(Self::UnwrapKey),
            "deriveKey" => Some(Self::DeriveKey),
            "deriveBits" => Some(Self::DeriveBits),
            _ => None,
        }
    }
}

impl BitOr<Self> for KeyOps {
    type Output = KeyOpsSet;

    fn bitor(self, rhs: Self) -> Self::Output {
        KeyOpsSet {
            value: self as usize | rhs as usize,
        }
    }
}

/// A set of key operations
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct KeyOpsSet {
    value: usize,
}

impl KeyOpsSet {
    /// Create a new, empty operation set
    pub const fn new() -> Self {
        Self { value: 0 }
    }

    /// Check if an operation set is empty
    pub fn is_empty(&self) -> bool {
        self.value == 0
    }
}

impl Default for KeyOpsSet {
    fn default() -> Self {
        Self::new()
    }
}

impl BitOr<Self> for KeyOpsSet {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        KeyOpsSet {
            value: self.value | rhs.value,
        }
    }
}

impl BitOr<KeyOps> for KeyOpsSet {
    type Output = KeyOpsSet;

    fn bitor(self, rhs: KeyOps) -> Self::Output {
        KeyOpsSet {
            value: self.value | rhs as usize,
        }
    }
}

impl BitAnd<KeyOps> for KeyOpsSet {
    type Output = bool;

    fn bitand(self, rhs: KeyOps) -> Self::Output {
        self.value & rhs as usize != 0
    }
}

impl BitAnd<Self> for KeyOpsSet {
    type Output = bool;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.value & rhs.value != 0
    }
}

impl Debug for KeyOpsSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut vals = &mut f.debug_set();
        for op in self {
            vals = vals.entry(&op.as_str());
        }
        vals.finish()
    }
}

impl From<KeyOps> for KeyOpsSet {
    fn from(op: KeyOps) -> Self {
        Self { value: op as usize }
    }
}

impl IntoIterator for &KeyOpsSet {
    type IntoIter = KeyOpsIter;
    type Item = KeyOps;

    fn into_iter(self) -> Self::IntoIter {
        KeyOpsIter {
            index: 0,
            value: *self,
        }
    }
}

#[derive(Debug)]
pub struct KeyOpsIter {
    index: usize,
    value: KeyOpsSet,
}

impl Iterator for KeyOpsIter {
    type Item = KeyOps;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < OPS.len() {
            let op = OPS[self.index];
            self.index += 1;
            if self.value & op {
                return Some(op);
            }
        }
        None
    }
}

struct KeyOpsVisitor;

impl<'de> Visitor<'de> for KeyOpsVisitor {
    type Value = KeyOpsSet;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of key operations")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut ops = KeyOpsSet::new();
        while let Some(op) = seq.next_element()? {
            if let Some(op) = KeyOps::try_from_str(op) {
                if ops & op {
                    return Err(serde::de::Error::duplicate_field(op.as_str()));
                } else {
                    ops = ops | op;
                }
            }
        }
        Ok(ops)
    }
}

impl<'de> Deserialize<'de> for KeyOpsSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(KeyOpsVisitor)
    }
}

impl Serialize for KeyOpsSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(None)?;
        for op in self {
            seq.serialize_element(op.as_str())?;
        }
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariants() {
        assert!(KeyOpsSet::new().is_empty());
        assert!(!KeyOpsSet::from(KeyOps::Decrypt).is_empty());
        assert_eq!(KeyOpsSet::new(), KeyOpsSet::new());
        assert_ne!(KeyOpsSet::from(KeyOps::Decrypt), KeyOpsSet::new());
        assert_ne!(KeyOps::Decrypt, KeyOps::Encrypt);
        assert_ne!(
            KeyOpsSet::from(KeyOps::Decrypt),
            KeyOpsSet::from(KeyOps::Encrypt)
        );
        assert_eq!(
            KeyOps::Decrypt | KeyOps::Encrypt,
            KeyOps::Encrypt | KeyOps::Decrypt
        );
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", KeyOps::Decrypt | KeyOps::Encrypt),
            "{\"encrypt\", \"decrypt\"}"
        );
    }
}
