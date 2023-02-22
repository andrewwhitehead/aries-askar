use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use serde::{
    de::{Deserialize, Deserializer, MapAccess, Visitor},
    ser::{Serialize, SerializeMap, Serializer},
};

use super::ops::{KeyOps, KeyOpsSet};
use crate::error::Error;

/// A parsed JWK
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct JwkParts<'a> {
    /// Key type
    pub kty: JwkAttr<'a>,
    /// Key ID
    pub kid: JwkAttr<'a>,
    /// Key algorithm
    pub alg: JwkAttr<'a>,
    /// Curve type
    pub crv: JwkAttr<'a>,
    /// Curve key public x coordinate
    pub x: JwkAttr<'a>,
    /// Curve key public y coordinate
    pub y: JwkAttr<'a>,
    /// Curve key private key bytes
    pub d: JwkAttr<'a>,
    /// Used by symmetric keys like AES
    pub k: JwkAttr<'a>,
    /// Recognized key operations
    pub key_ops: Option<KeyOpsSet>,
}

impl<'de> TryFrom<&'de [u8]> for JwkParts<'de> {
    type Error = Error;

    fn try_from(jwk: &'de [u8]) -> Result<Self, Self::Error> {
        let (parts, _read) =
            serde_json_core::from_slice(jwk).map_err(err_map!(Invalid, "Error parsing JWK"))?;
        Ok(parts)
    }
}

impl<'de> TryFrom<&'de str> for JwkParts<'de> {
    type Error = Error;

    fn try_from(jwk: &'de str) -> Result<Self, Self::Error> {
        Self::try_from(jwk.as_bytes())
    }
}

#[cfg(feature = "alloc")]
impl<'de> TryFrom<&'de alloc::string::String> for JwkParts<'de> {
    type Error = Error;

    fn try_from(jwk: &'de alloc::string::String) -> Result<Self, Self::Error> {
        Self::try_from(jwk.as_bytes())
    }
}

#[cfg(feature = "alloc")]
impl<'de> TryFrom<&'de alloc::vec::Vec<u8>> for JwkParts<'de> {
    type Error = Error;

    fn try_from(jwk: &'de alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(jwk.as_slice())
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[repr(transparent)]
pub struct JwkAttr<'a>(Option<&'a str>);

impl JwkAttr<'_> {
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }

    pub fn as_opt_str(&self) -> Option<&str> {
        self.0
    }

    pub fn decode_base64(&self, output: &mut [u8]) -> Result<usize, Error> {
        if let Some(s) = self.as_opt_str() {
            let max_input = (output.len() * 4 + 2) / 3; // ceil(4*n/3)
            if s.len() > max_input {
                Err(err_msg!(Invalid, "Base64 length exceeds max"))
            } else {
                base64::decode_config_slice(s, base64::URL_SAFE_NO_PAD, output)
                    .map_err(|_| err_msg!(Invalid, "Base64 decoding error"))
            }
        } else {
            Err(err_msg!(Invalid, "Empty attribute"))
        }
    }

    pub fn decode_base64_exact(&self, output: &mut [u8]) -> Result<(), Error> {
        let len = self.decode_base64(output)?;
        if len == output.len() {
            Ok(())
        } else {
            Err(err_msg!(InvalidKeyData, "Invalid length"))
        }
    }

    pub fn decode_base64_array<const L: usize>(&self) -> Result<[u8; L], Error> {
        let mut buf = [0u8; L];
        self.decode_base64_exact(&mut buf)?;
        Ok(buf)
    }
}

impl Debug for JwkAttr<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => f.write_str("None"),
            Some(s) => f.write_fmt(format_args!("{:?}", s)),
        }
    }
}

impl AsRef<str> for JwkAttr<'_> {
    fn as_ref(&self) -> &str {
        self.as_opt_str().unwrap_or_default()
    }
}

impl<'o> From<&'o str> for JwkAttr<'o> {
    fn from(s: &'o str) -> Self {
        Self(Some(s))
    }
}

impl<'o> From<Option<&'o str>> for JwkAttr<'o> {
    fn from(s: Option<&'o str>) -> Self {
        Self(s.map(Into::into))
    }
}

impl PartialEq<Option<&str>> for JwkAttr<'_> {
    fn eq(&self, other: &Option<&str>) -> bool {
        self.as_opt_str() == *other
    }
}

impl PartialEq<&str> for JwkAttr<'_> {
    fn eq(&self, other: &&str) -> bool {
        match self.0 {
            None => false,
            Some(s) => (*other) == s,
        }
    }
}

struct JwkMapVisitor<'de>(PhantomData<&'de ()>);

impl<'de> Visitor<'de> for JwkMapVisitor<'de> {
    type Value = JwkParts<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object representing a JWK")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut kty = None;
        let mut kid = None;
        let mut alg = None;
        let mut crv = None;
        let mut x = None;
        let mut y = None;
        let mut d = None;
        let mut k = None;
        let mut key_ops = None;

        while let Some(key) = access.next_key::<&str>()? {
            match key {
                "kty" => kty = Some(access.next_value()?),
                "kid" => kid = Some(access.next_value()?),
                "alg" => alg = Some(access.next_value()?),
                "crv" => crv = Some(access.next_value()?),
                "x" => x = Some(access.next_value()?),
                "y" => y = Some(access.next_value()?),
                "d" => d = Some(access.next_value()?),
                "k" => k = Some(access.next_value()?),
                "use" => {
                    let ops = match access.next_value()? {
                        "enc" => {
                            KeyOps::Encrypt | KeyOps::Decrypt | KeyOps::WrapKey | KeyOps::UnwrapKey
                        }
                        "sig" => KeyOps::Sign | KeyOps::Verify,
                        _ => KeyOpsSet::new(),
                    };
                    if !ops.is_empty() {
                        key_ops = Some(key_ops.unwrap_or_default() | ops);
                    }
                }
                "key_ops" => key_ops = Some(access.next_value()?),
                _ => (),
            }
        }

        if kty.is_some() {
            Ok(JwkParts {
                kty: kty.into(),
                kid: kid.into(),
                alg: alg.into(),
                crv: crv.into(),
                x: x.into(),
                y: y.into(),
                d: d.into(),
                k: k.into(),
                key_ops,
            })
        } else {
            Err(serde::de::Error::missing_field("kty"))
        }
    }
}

impl<'de> Deserialize<'de> for JwkParts<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(JwkMapVisitor(PhantomData))
    }
}

impl Serialize for JwkParts<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        if let Some(alg) = self.alg.as_opt_str() {
            map.serialize_entry("alg", alg)?;
        }
        if let Some(crv) = self.crv.as_opt_str() {
            map.serialize_entry("crv", crv)?;
        }
        if let Some(d) = self.d.as_opt_str() {
            map.serialize_entry("d", d)?;
        }
        if let Some(k) = self.k.as_opt_str() {
            map.serialize_entry("k", k)?;
        }
        if let Some(kid) = self.kid.as_opt_str() {
            map.serialize_entry("kid", kid)?;
        }
        if let Some(kty) = self.kty.as_opt_str() {
            map.serialize_entry("kty", kty)?;
        }
        if let Some(x) = self.x.as_opt_str() {
            map.serialize_entry("x", x)?;
        }
        if let Some(y) = self.y.as_opt_str() {
            map.serialize_entry("y", y)?;
        }
        if let Some(ops) = self.key_ops {
            map.serialize_entry("key_ops", &ops)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample_okp() {
        let jwk = r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "key_ops": ["sign", "verify"],
            "kid": "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"
        }"#;
        let parts = JwkParts::try_from(jwk).unwrap();
        assert_eq!(parts.kty, "OKP");
        assert_eq!(
            parts.kid,
            Some("FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ")
        );
        assert_eq!(parts.crv, Some("Ed25519"));
        assert_eq!(parts.x, Some("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"));
        assert_eq!(parts.y, None);
        assert_eq!(parts.d, Some("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"));
        assert_eq!(parts.k, None);
        assert_eq!(parts.key_ops, Some(KeyOps::Sign | KeyOps::Verify));

        // check serialization
        let mut buf = [0u8; 512];
        let len = serde_json_core::to_slice(&parts, &mut buf[..]).unwrap();
        let parts_2 = JwkParts::try_from(&buf[..len]).unwrap();
        assert_eq!(parts_2, parts);
    }
}
