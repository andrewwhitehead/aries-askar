use aries_askar::{
    future::block_on,
    kms::{KeyAlg, LocalKey},
    Store, StoreKeyMethod,
};

const KEM_ALGS: [(KeyAlg, &str); 3] = [
    (KeyAlg::X25519, "DHKEM-X25519-HKDF-SHA256"),
    (
        KeyAlg::EcCurve(aries_askar::crypto::alg::EcCurves::Secp256r1),
        "DHKEM-P256-HKDF-SHA256",
    ),
    (
        KeyAlg::EcCurve(aries_askar::crypto::alg::EcCurves::Secp384r1),
        "DHKEM-P384-HKDF-SHA384",
    ),
];

fn public_key(key: &LocalKey, alg: KeyAlg) -> LocalKey {
    let bytes = key.to_public_bytes().expect("Error exporting public key");
    LocalKey::from_public_bytes(alg, bytes.as_ref()).expect("Error loading public key")
}

#[test]
fn localkey_kem() {
    for (alg, kem) in KEM_ALGS {
        let recip = LocalKey::generate_with_rng(alg, true).expect("Error creating keypair");
        let recip_pk = public_key(&recip, alg);

        let (enc, secret) = recip_pk.kem_encap(kem).expect("Error in encap");
        assert_eq!(recip.kem_decap(kem, &enc).expect("Error in decap"), secret);

        let sender = LocalKey::generate_with_rng(alg, true).expect("Error creating keypair");
        let sender_pk = public_key(&sender, alg);
        let (enc, secret) = recip_pk
            .kem_auth_encap(kem, &sender)
            .expect("Error in auth encap");
        assert_eq!(
            recip
                .kem_auth_decap(kem, &enc, &sender_pk)
                .expect("Error in auth decap"),
            secret
        );

        // a different sender key results in a different secret
        let other = public_key(
            &LocalKey::generate_with_rng(alg, true).expect("Error creating keypair"),
            alg,
        );
        assert_ne!(
            recip
                .kem_auth_decap(kem, &enc, &other)
                .expect("Error in auth decap"),
            secret
        );

        // the KEM must match the key type, and be known
        assert!(
            recip_pk.kem_encap("DHKEM-P256-HKDF-SHA256").is_err()
                == (kem != "DHKEM-P256-HKDF-SHA256")
        );
        assert!(recip_pk.kem_encap("unknown-kem").is_err());

        // tampered or invalid encapsulated keys
        let mut bad_enc = enc.clone();
        bad_enc.truncate(enc.len() - 1);
        assert!(recip.kem_decap(kem, &bad_enc).is_err());
    }
}

#[test]
fn localkey_kem_unsupported_alg() {
    let key = LocalKey::generate_with_rng(KeyAlg::Ed25519, true).expect("Error creating keypair");
    assert!(key.kem_encap("DHKEM-X25519-HKDF-SHA256").is_err());
    assert!(key
        .kem_decap("DHKEM-X25519-HKDF-SHA256", &[0u8; 32])
        .is_err());
}

#[test]
// decapsulation with a recipient key held in the store
fn stored_key_kem() {
    block_on(async {
        let pass_key = Store::new_raw_key(None).expect("Error creating raw store key");
        let db = Store::provision(
            "sqlite://:memory:",
            StoreKeyMethod::RawKey,
            pass_key,
            None,
            true,
        )
        .await
        .expect("Error opening test store instance");

        let alg = KeyAlg::EcCurve(aries_askar::crypto::alg::EcCurves::Secp256r1);
        let recip = LocalKey::generate_with_rng(alg, false).expect("Error creating keypair");
        let recip_pk = public_key(&recip, alg);
        let kem = "DHKEM-P256-HKDF-SHA256";
        let (enc, secret) = recip_pk.kem_encap(kem).expect("Error in encap");

        let mut conn = db.session(None).await.expect("Error creating session");
        conn.insert_key("recipient", &recip, None, None, None, None)
            .await
            .expect("Error inserting key");
        let stored = conn
            .fetch_key("recipient", false)
            .await
            .expect("Error fetching key")
            .expect("Row required")
            .load_local_key()
            .expect("Error loading key");
        assert_eq!(stored.kem_decap(kem, &enc).expect("Error in decap"), secret);

        drop(conn);
        db.close().await.expect("Error closing test store instance");
    })
}
