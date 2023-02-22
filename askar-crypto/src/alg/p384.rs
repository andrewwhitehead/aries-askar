//! Elliptic curve ECDH and ECDSA support on curve secp384r1

use super::ec_common;
use crate::{
    alg::{ec_common::EcKeyPair, EcCurves},
    sign::SignatureType,
};

pub use p384::NistP384;

/// The 'crv' value of a P-384 key JWK
pub const JWK_CURVE: &str = "P-384";

/// The 'kty' value of a P-384 key JWK
pub const JWK_KEY_TYPE: &str = ec_common::JWK_KEY_TYPE;

impl_ec_key_type!(
    "p384",
    NistP384,
    EcCurves::Secp384r1,
    SignatureType::ES384,
    JWK_CURVE
);

/// A P-384 (secp384r1) public key or keypair
pub type P384KeyPair = EcKeyPair<NistP384>;

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
        // from: https://connect2id.com/products/server/docs/config/jwk-set
        // {"kty": "EC",
        // "crv": "P-384",
        // "kid": "9nHY",
        // "d": "3zS7ECyMqZlENI9Xk6TqptEbZtoso3LmO4Hc9zs-VytU3Sgd8yHw2uUePAkGv_Fu",
        // "x": "JPKhjhE0Bj579Mgj3Cn3ERGA8fKVYoGOaV9BPKhtnEobphf8w4GSeigMesL-038W",
        // "y": "UbJa1QRX7fo9LxSlh7FOH5ABT5lEtiQeQUcX9BW0bpJFlEVGqwec80tYLdOIl59M"}
        let test_pvt_b64 = "3zS7ECyMqZlENI9Xk6TqptEbZtoso3LmO4Hc9zs-VytU3Sgd8yHw2uUePAkGv_Fu";
        let test_pub_b64 = (
            "JPKhjhE0Bj579Mgj3Cn3ERGA8fKVYoGOaV9BPKhtnEobphf8w4GSeigMesL-038W",
            "UbJa1QRX7fo9LxSlh7FOH5ABT5lEtiQeQUcX9BW0bpJFlEVGqwec80tYLdOIl59M",
        );
        let test_pvt = base64::decode_config(test_pvt_b64, base64::URL_SAFE).unwrap();
        let sk = P384KeyPair::from_secret_bytes(&test_pvt).expect("Error creating signing key");

        let jwk = sk.to_jwk_public(None).expect("Error converting key to JWK");
        let jwk = JwkParts::try_from(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64.0);
        assert_eq!(jwk.y, test_pub_b64.1);
        assert_eq!(jwk.d, None);
        let pk_load = P384KeyPair::from_jwk_parts(jwk).unwrap();
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
        let sk_load = P384KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(
            sk.to_secret_bytes().unwrap(),
            sk_load.to_secret_bytes().unwrap()
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn jwk_thumbprint() {
        let pk = P384KeyPair::from_jwk(
            r#"{
                "kty": "EC",
                "crv": "P-384",
                "x": "JPKhjhE0Bj579Mgj3Cn3ERGA8fKVYoGOaV9BPKhtnEobphf8w4GSeigMesL-038W",
                "y": "UbJa1QRX7fo9LxSlh7FOH5ABT5lEtiQeQUcX9BW0bpJFlEVGqwec80tYLdOIl59M"
            }"#,
        )
        .unwrap();
        assert_eq!(
            pk.to_jwk_thumbprint(None).unwrap(),
            "UMwnrC5x2WbX68PQyjxwcK7o5_DqQQiGysnByE5im0Y"
        );
    }

    #[test]
    fn sign_verify_expected() {
        let test_msg = b"This is a dummy message for use with tests";
        let test_sig = &hex!(
            "db6331628eaa7da84abe72b485333e116956efa616e5897abd67c038e87af89a
            85ba42c9a34c7801153d705036dd852267b7f6ab286c8d60d6a2a46beaa30c3e
            8339a0c9840b14084574bf25051e583b316e2b85f8adace602bf1169e67969c2"
        );
        let test_pvt = base64::decode_config(
            "3zS7ECyMqZlENI9Xk6TqptEbZtoso3LmO4Hc9zs-VytU3Sgd8yHw2uUePAkGv_Fu",
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        let kp = P384KeyPair::from_secret_bytes(&test_pvt).unwrap();
        let sig = kp.sign(&test_msg[..]).unwrap();
        assert_eq!(sig, &test_sig[..]);
        assert!(kp.verify_signature(&test_msg[..], &sig[..]));
        assert!(!kp.verify_signature(b"Not the message", &sig[..]));
        assert!(!kp.verify_signature(&test_msg[..], &[0u8; 64]));
    }
}
