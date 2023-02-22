//! Elliptic curve ECDH and ECDSA support on curve secp256r1

use super::ec_common;
use crate::{
    alg::{ec_common::EcKeyPair, EcCurves},
    sign::SignatureType,
};

pub use p256::NistP256;

/// The 'crv' value of a P-256 key JWK
pub const JWK_CURVE: &str = "P-256";

/// The 'kty' value of a P-256 key JWK
pub const JWK_KEY_TYPE: &str = ec_common::JWK_KEY_TYPE;

impl_ec_key_type!(
    "p256",
    NistP256,
    EcCurves::Secp256r1,
    SignatureType::ES256,
    JWK_CURVE
);
/// A P-256 (secp256r1) public key or keypair
pub type P256KeyPair = EcKeyPair<NistP256>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repr::FromSecretBytes;
    #[cfg(feature = "alloc")]
    use crate::{
        jwk::{FromJwk, JwkParts, ToJwk},
        repr::{ToPublicBytes, ToSecretBytes},
    };

    #[cfg(feature = "alloc")]
    #[test]
    fn jwk_expected() {
        // from JWS RFC https://tools.ietf.org/html/rfc7515
        // {"kty":"EC",
        // "crv":"P-256",
        // "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        // "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        // "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
        // }
        let test_pvt_b64 = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";
        let test_pub_b64 = (
            "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        );
        let test_pvt = base64::decode_config(test_pvt_b64, base64::URL_SAFE).unwrap();
        let sk = P256KeyPair::from_secret_bytes(&test_pvt).expect("Error creating signing key");

        let jwk = sk.to_jwk_public(None).expect("Error converting key to JWK");
        let jwk = JwkParts::try_from(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64.0);
        assert_eq!(jwk.y, test_pub_b64.1);
        assert_eq!(jwk.d, None);
        let pk_load = P256KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(sk.to_public_bytes(), pk_load.to_public_bytes());

        let jwk = sk
            .to_jwk_secret(None)
            .expect("Error converting key to JWK")
            .into_vec();
        let jwk = JwkParts::try_from(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64.0);
        assert_eq!(jwk.y, test_pub_b64.1);
        assert_eq!(jwk.d, test_pvt_b64);
        let sk_load = P256KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(
            sk.to_secret_bytes().unwrap(),
            sk_load.to_secret_bytes().unwrap()
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn jwk_thumbprint() {
        let pk = P256KeyPair::from_jwk(
            r#"{
                "kty": "EC",
                "crv": "P-256",
                "x": "tDeeYABgKEAbWicYPCEEI8sP4SRIhHKcHDW7VqrB4LA",
                "y": "J08HOoIZ0rX2Me3bNFZUltfxIk1Hrc8FsLu8VaSxsMI"
            }"#,
        )
        .unwrap();
        assert_eq!(
            pk.to_jwk_thumbprint(None).unwrap(),
            "8fm8079s3nu4FLV_7dVJoJ69A8XCXn7Za2mtaWCnxR4"
        );
    }

    #[test]
    fn sign_verify_expected() {
        let test_msg = b"This is a dummy message for use with tests";
        let test_sig = &hex!(
            "241f765f19d4e6148452f2249d2fa69882244a6ad6e70aadb8848a6409d20712
            4e85faf9587100247de7bdace13a3073b47ec8a531ca91c1375b2b6134344413"
        );
        let test_pvt = base64::decode_config(
            "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        let kp = P256KeyPair::from_secret_bytes(&test_pvt).unwrap();
        let sig = kp.sign(&test_msg[..]).unwrap();
        assert_eq!(sig, &test_sig[..]);
        assert!(kp.verify_signature(&test_msg[..], &sig[..]));
        assert!(!kp.verify_signature(b"Not the message", &sig[..]));
        assert!(!kp.verify_signature(&test_msg[..], &[0u8; 64]));
    }
}
