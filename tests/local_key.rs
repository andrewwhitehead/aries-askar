#![allow(clippy::bool_assert_comparison)]

use aries_askar::kms::{KeyAlg, LocalKey};

const ERR_CREATE_KEYPAIR: &str = "Error creating keypair";
const ERR_SIGN: &str = "Error signing message";
const ERR_VERIFY: &str = "Error verifying signature";

#[test]
pub fn localkey_sign_verify() {
    let keypair = LocalKey::generate(KeyAlg::Ed25519, true).expect(ERR_CREATE_KEYPAIR);

    let message = b"message".to_vec();
    let sig = keypair.sign_message(&message, None).expect(ERR_SIGN);

    assert_eq!(
        keypair
            .verify_signature(&message, &sig, None)
            .expect(ERR_VERIFY),
        true
    );

    assert_eq!(
        keypair
            .verify_signature(b"bad input", &sig, None)
            .expect(ERR_VERIFY),
        false
    );

    assert_eq!(
        keypair.verify_signature(
            // [0u8; 64]
            b"xt19s1sp2UZCGhy9rNyb1FtxdKiDGZZPNFnc1KiM9jYYEuHxuwNeFf1oQKsn8zv6yvYBGhXa83288eF4MqN1oDq",
            &sig,None
        ).expect(ERR_VERIFY),
        false
    );

    assert_eq!(
        keypair
            .verify_signature(&message, b"bad sig", None)
            .expect(ERR_VERIFY),
        false
    );

    assert_eq!(
        keypair
            .verify_signature(&message, &sig, Some("invalid type"))
            .is_err(),
        true
    );
}
