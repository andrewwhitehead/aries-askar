//! Elliptic curve ECDH and ECDSA support on curve secp256k1

use super::ec_common;
use crate::{
    alg::{ec_common::EcKeyPair, EcCurves},
    sign::SignatureType,
};

pub use k256::Secp256k1;

/// The 'crv' value of a K-256 key JWK
pub const JWK_CURVE: &str = "secp256k1";

/// The 'kty' value of a K-256 key JWK
pub const JWK_KEY_TYPE: &str = ec_common::JWK_KEY_TYPE;

impl_ec_key_type!(
    Secp256k1,
    EcCurves::Secp256k1,
    SignatureType::ES256K,
    JWK_CURVE
);

/// A K-256 (secp256r1) public key or keypair
pub type K256KeyPair = EcKeyPair<Secp256k1>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repr::KeySecretBytes;
    #[cfg(feature = "alloc")]
    use crate::{
        jwk::{FromJwk, JwkParts, ToJwk},
        repr::{KeypairBytes, ToPublicBytes},
    };

    #[cfg(feature = "alloc")]
    #[test]
    fn jwk_expected() {
        // from https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/
        // {"kty":"EC",
        // "crv":"secp256k1",
        // "d": "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw",
        // "kid": "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
        // "kty": "EC",
        // "x": "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
        // "y": "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
        // }
        let test_pvt_b64 = "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw";
        let test_pub_b64 = (
            "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
            "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
        );
        let test_pvt = base64::decode_config(test_pvt_b64, base64::URL_SAFE).unwrap();
        let sk = K256KeyPair::from_secret_bytes(&test_pvt).expect("Error creating signing key");

        let jwk = sk.to_jwk_public(None).expect("Error converting key to JWK");
        let jwk = JwkParts::try_from_str(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64.0);
        assert_eq!(jwk.y, test_pub_b64.1);
        assert_eq!(jwk.d, None);
        let pk_load = K256KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(sk.to_public_bytes(), pk_load.to_public_bytes());

        let jwk = sk.to_jwk_secret(None).expect("Error converting key to JWK");
        let jwk = JwkParts::from_slice(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64.0);
        assert_eq!(jwk.y, test_pub_b64.1);
        assert_eq!(jwk.d, test_pvt_b64);
        let sk_load = K256KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(
            sk.to_keypair_bytes().unwrap(),
            sk_load.to_keypair_bytes().unwrap()
        );
    }

    #[test]
    fn sign_verify_expected() {
        let test_msg = b"This is a dummy message for use with tests";
        let test_sig = &hex!(
            "a2a3affbe18cda8c5a7b6375f05b304c2303ab8beb21428709a43a519f8f946f
            6ffa7966afdb337e9b1f70bb575282e71d4fe5bbe6bfa97b229d6bd7e97df1e5"
        );
        let test_pvt = base64::decode_config(
            "jv_VrhPomm6_WOzb74xF4eMI0hu9p0W1Zlxi0nz8AFs",
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        let kp = K256KeyPair::from_secret_bytes(&test_pvt).unwrap();
        let sig = kp.sign(&test_msg[..]).unwrap();
        assert_eq!(sig, &test_sig[..]);
        assert!(kp.verify_signature(&test_msg[..], &sig[..]));
        assert!(!kp.verify_signature(b"Not the message", &sig[..]));
        assert!(!kp.verify_signature(&test_msg[..], &[0u8; 64]));
    }
}
