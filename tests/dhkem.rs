use aries_askar::{
    future::block_on,
    kms::{KeyAlg, LocalKey},
    Store, StoreKeyMethod,
};

const DHKEM_ALGS: [KeyAlg; 3] = [
    KeyAlg::X25519,
    KeyAlg::EcCurve(aries_askar::crypto::alg::EcCurves::Secp256r1),
    KeyAlg::EcCurve(aries_askar::crypto::alg::EcCurves::Secp384r1),
];

fn public_key(key: &LocalKey, alg: KeyAlg) -> LocalKey {
    let bytes = key.to_public_bytes().expect("Error exporting public key");
    LocalKey::from_public_bytes(alg, bytes.as_ref()).expect("Error loading public key")
}

#[test]
fn localkey_dhkem() {
    for alg in DHKEM_ALGS {
        let recip = LocalKey::generate_with_rng(alg, true).expect("Error creating keypair");
        let recip_pk = public_key(&recip, alg);

        let (enc, secret) = recip_pk.dhkem_encap().expect("Error in encap");
        assert_eq!(recip.dhkem_decap(&enc).expect("Error in decap"), secret);

        let sender = LocalKey::generate_with_rng(alg, true).expect("Error creating keypair");
        let sender_pk = public_key(&sender, alg);
        let (enc, secret) = recip_pk
            .dhkem_auth_encap(&sender)
            .expect("Error in auth encap");
        assert_eq!(
            recip
                .dhkem_auth_decap(&enc, &sender_pk)
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
                .dhkem_auth_decap(&enc, &other)
                .expect("Error in auth decap"),
            secret
        );

        // tampered or invalid encapsulated keys
        let mut bad_enc = enc.clone();
        bad_enc.truncate(enc.len() - 1);
        assert!(recip.dhkem_decap(&bad_enc).is_err());
    }
}

#[test]
fn localkey_dhkem_unsupported_alg() {
    let key = LocalKey::generate_with_rng(KeyAlg::Ed25519, true).expect("Error creating keypair");
    assert!(key.dhkem_encap().is_err());
    assert!(key.dhkem_decap(&[0u8; 32]).is_err());
}

#[test]
// decapsulation with a recipient key held in the store
fn stored_key_dhkem() {
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
        let (enc, secret) = recip_pk.dhkem_encap().expect("Error in encap");

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
        assert_eq!(stored.dhkem_decap(&enc).expect("Error in decap"), secret);

        drop(conn);
        db.close().await.expect("Error closing test store instance");
    })
}
