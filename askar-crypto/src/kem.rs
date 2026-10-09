//! Diffie-Hellman based key encapsulation mechanisms (DHKEM), as defined for
//! Hybrid Public Key Encryption (HPKE) in [RFC 9180 section 4.1].
//!
//! This provides the `Encap`, `Decap`, `AuthEncap` and `AuthDecap` operations
//! of the KEM. The output is the KEM shared secret, which is the input to the
//! HPKE key schedule (not implemented here).
//!
//! [RFC 9180 section 4.1]: https://www.rfc-editor.org/rfc/rfc9180.html#name-dh-based-kem-dhkem

use alloc::vec::Vec;

use hkdf::hmac::EagerHash;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384};
use subtle::ConstantTimeEq;

use crate::{
    buffer::{SecretBytes, WriteBuffer},
    error::Error,
    kdf::KeyExchange,
    random::KeyMaterial,
    repr::KeyGen,
};

const HPKE_VERSION: &[u8] = b"HPKE-v1";

/// The supported DH-based KEM algorithms
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DhKem {
    /// DHKEM(P-256, HKDF-SHA256)
    P256HkdfSha256,
    /// DHKEM(P-384, HKDF-SHA384)
    P384HkdfSha384,
    /// DHKEM(X25519, HKDF-SHA256)
    X25519HkdfSha256,
}

impl DhKem {
    /// The KEM identifier registered for HPKE
    pub const fn kem_id(&self) -> u16 {
        match self {
            Self::P256HkdfSha256 => 0x0010,
            Self::P384HkdfSha384 => 0x0011,
            Self::X25519HkdfSha256 => 0x0020,
        }
    }

    /// The length in bytes of the shared secret produced by this KEM (`Nsecret`)
    pub const fn secret_length(&self) -> usize {
        match self {
            Self::P256HkdfSha256 | Self::X25519HkdfSha256 => 32,
            Self::P384HkdfSha384 => 48,
        }
    }

    /// The length in bytes of an encapsulated key (`Nenc`)
    pub const fn enc_length(&self) -> usize {
        match self {
            Self::P256HkdfSha256 => 65,
            Self::P384HkdfSha384 => 97,
            Self::X25519HkdfSha256 => 32,
        }
    }

    fn suite_id(&self) -> [u8; 5] {
        let id = self.kem_id().to_be_bytes();
        [b'K', b'E', b'M', id[0], id[1]]
    }
}

/// Trait implemented by key types which can be used with a DH-based KEM
pub trait DhKemKey: KeyExchange + KeyGen + Sized {
    /// The KEM algorithm associated with this key type
    const KEM: DhKem;

    /// Write the public key in the form defined by `SerializePublicKey`
    /// (the uncompressed point for NIST curves, or the raw public key bytes
    /// for X25519)
    fn write_kem_public(&self, out: &mut dyn WriteBuffer) -> Result<(), Error>;

    /// Load a public key from the form defined by `DeserializePublicKey`
    fn from_kem_public(bytes: &[u8]) -> Result<Self, Error>;
}

/// The result of encapsulation
#[derive(Debug)]
pub struct Encapsulated {
    /// The encapsulated key (`enc`), to be sent to the recipient
    pub enc: Vec<u8>,
    /// The KEM shared secret
    pub shared_secret: SecretBytes,
}

fn serialize_public<K: DhKemKey>(key: &K) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(K::KEM.enc_length());
    key.write_kem_public(&mut buf)?;
    if buf.len() != K::KEM.enc_length() {
        return Err(err_msg!(Unsupported, "Unexpected public key length"));
    }
    Ok(buf)
}

fn deserialize_public<K: DhKemKey>(enc: &[u8]) -> Result<K, Error> {
    if enc.len() != K::KEM.enc_length() {
        return Err(err_msg!(Invalid, "Invalid encapsulated key length"));
    }
    K::from_kem_public(enc)
}

/// Perform the Diffie-Hellman operation, rejecting the all-zero result which
/// can be produced by an X25519 public key of small order
fn dh<K: DhKemKey>(sk: &K, pk: &K) -> Result<SecretBytes, Error> {
    let secret = sk.key_exchange_bytes(pk)?;
    if secret.iter().fold(0u8, |acc, b| acc | b).ct_eq(&0).into() {
        return Err(err_msg!(Encryption, "Invalid public key for key exchange"));
    }
    Ok(secret)
}

fn labeled_extract<H: EagerHash>(
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<Hkdf<H>, Error> {
    let mut labeled_ikm =
        SecretBytes::with_capacity(HPKE_VERSION.len() + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.buffer_write(HPKE_VERSION)?;
    labeled_ikm.buffer_write(suite_id)?;
    labeled_ikm.buffer_write(label)?;
    labeled_ikm.buffer_write(ikm)?;
    // the salt is empty
    Ok(Hkdf::<H>::new(None, labeled_ikm.as_ref()))
}

fn labeled_expand<H: EagerHash>(
    prk: &Hkdf<H>,
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<SecretBytes, Error> {
    let mut labeled_info =
        Vec::with_capacity(2 + HPKE_VERSION.len() + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(len as u16).to_be_bytes());
    labeled_info.extend_from_slice(HPKE_VERSION);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    let mut out = SecretBytes::new_with(len, |_| ());
    prk.expand(&labeled_info, out.as_mut())
        .map_err(|_| err_msg!(Unexpected, "Error expanding key material"))?;
    Ok(out)
}

fn extract_and_expand_hash<H: EagerHash>(
    kem: DhKem,
    dh: &[u8],
    kem_context: &[u8],
) -> Result<SecretBytes, Error> {
    let suite_id = kem.suite_id();
    let eae_prk = labeled_extract::<H>(&suite_id, b"eae_prk", dh)?;
    labeled_expand(
        &eae_prk,
        &suite_id,
        b"shared_secret",
        kem_context,
        kem.secret_length(),
    )
}

/// `ExtractAndExpand` from RFC 9180
fn extract_and_expand(kem: DhKem, dh: &[u8], kem_context: &[u8]) -> Result<SecretBytes, Error> {
    match kem {
        DhKem::P256HkdfSha256 | DhKem::X25519HkdfSha256 => {
            extract_and_expand_hash::<Sha256>(kem, dh, kem_context)
        }
        DhKem::P384HkdfSha384 => extract_and_expand_hash::<Sha384>(kem, dh, kem_context),
    }
}

fn encap_inner<K: DhKemKey>(
    recip_pk: &K,
    ephem_sk: &K,
    sender_sk: Option<&K>,
) -> Result<Encapsulated, Error> {
    let mut dh_out = dh(ephem_sk, recip_pk)?;
    let enc = serialize_public(ephem_sk)?;
    let mut kem_context = enc.clone();
    kem_context.extend_from_slice(&serialize_public(recip_pk)?);
    if let Some(sender_sk) = sender_sk {
        dh_out.buffer_write(dh(sender_sk, recip_pk)?.as_ref())?;
        kem_context.extend_from_slice(&serialize_public(sender_sk)?);
    }
    let shared_secret = extract_and_expand(K::KEM, dh_out.as_ref(), &kem_context)?;
    Ok(Encapsulated { enc, shared_secret })
}

fn decap_inner<K: DhKemKey>(
    enc: &[u8],
    recip_sk: &K,
    sender_pk: Option<&K>,
) -> Result<SecretBytes, Error> {
    let ephem_pk = deserialize_public::<K>(enc)?;
    let mut dh_out = dh(recip_sk, &ephem_pk)?;
    let mut kem_context = enc.to_vec();
    kem_context.extend_from_slice(&serialize_public(recip_sk)?);
    if let Some(sender_pk) = sender_pk {
        dh_out.buffer_write(dh(recip_sk, sender_pk)?.as_ref())?;
        kem_context.extend_from_slice(&serialize_public(sender_pk)?);
    }
    extract_and_expand(K::KEM, dh_out.as_ref(), &kem_context)
}

/// Encapsulate a new shared secret for the recipient public key (`Encap`)
/// using an ephemeral key generated from the provided random source
pub fn encap_with_rng<K: DhKemKey>(
    recip_pk: &K,
    rng: impl KeyMaterial,
) -> Result<Encapsulated, Error> {
    let ephem_sk = K::generate(rng)?;
    encap_inner(recip_pk, &ephem_sk, None)
}

/// Encapsulate a new shared secret for the recipient public key (`Encap`)
#[cfg(feature = "getrandom")]
#[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
pub fn encap<K: DhKemKey>(recip_pk: &K) -> Result<Encapsulated, Error> {
    encap_with_rng(recip_pk, crate::random::default_rng())
}

/// Recover the shared secret from an encapsulated key using the recipient
/// secret key (`Decap`)
pub fn decap<K: DhKemKey>(enc: &[u8], recip_sk: &K) -> Result<SecretBytes, Error> {
    decap_inner(enc, recip_sk, None)
}

/// Encapsulate a new shared secret for the recipient public key, authenticated
/// by the sender secret key (`AuthEncap`), using an ephemeral key generated
/// from the provided random source
pub fn auth_encap_with_rng<K: DhKemKey>(
    recip_pk: &K,
    sender_sk: &K,
    rng: impl KeyMaterial,
) -> Result<Encapsulated, Error> {
    let ephem_sk = K::generate(rng)?;
    encap_inner(recip_pk, &ephem_sk, Some(sender_sk))
}

/// Encapsulate a new shared secret for the recipient public key, authenticated
/// by the sender secret key (`AuthEncap`)
#[cfg(feature = "getrandom")]
#[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
pub fn auth_encap<K: DhKemKey>(recip_pk: &K, sender_sk: &K) -> Result<Encapsulated, Error> {
    auth_encap_with_rng(recip_pk, sender_sk, crate::random::default_rng())
}

/// Recover the shared secret from an encapsulated key using the recipient
/// secret key and sender public key (`AuthDecap`)
pub fn auth_decap<K: DhKemKey>(
    enc: &[u8],
    recip_sk: &K,
    sender_pk: &K,
) -> Result<SecretBytes, Error> {
    decap_inner(enc, recip_sk, Some(sender_pk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repr::KeySecretBytes;

    struct Vector {
        sk_r: &'static [u8],
        pk_r: &'static [u8],
        sk_e: &'static [u8],
        enc: &'static [u8],
        sk_s: &'static [u8],
        pk_s: &'static [u8],
        base: &'static [u8],
        auth: Option<&'static [u8]>,
    }

    fn check_vector<K: DhKemKey + KeySecretBytes>(v: &Vector) {
        let sk_r = K::from_secret_bytes(v.sk_r).unwrap();
        let pk_r = K::from_kem_public(v.pk_r).unwrap();
        let sk_e = K::from_secret_bytes(v.sk_e).unwrap();
        let sk_s = K::from_secret_bytes(v.sk_s).unwrap();
        let pk_s = K::from_kem_public(v.pk_s).unwrap();

        // public key serialization
        assert_eq!(serialize_public(&sk_r).unwrap(), v.pk_r);
        assert_eq!(serialize_public(&sk_s).unwrap(), v.pk_s);

        // base mode
        let res = encap_inner(&pk_r, &sk_e, None).unwrap();
        assert_eq!(res.enc, v.enc);
        assert_eq!(res.shared_secret, v.base);
        assert_eq!(decap(v.enc, &sk_r).unwrap(), v.base);

        // auth mode
        if let Some(auth) = v.auth {
            let res = encap_inner(&pk_r, &sk_e, Some(&sk_s)).unwrap();
            assert_eq!(res.enc, v.enc);
            assert_eq!(res.shared_secret, auth);
            assert_eq!(auth_decap(v.enc, &sk_r, &pk_s).unwrap(), auth);
            // the sender key must match
            assert_ne!(auth_decap(v.enc, &sk_r, &pk_r).unwrap(), auth);
        }
    }

    fn check_round_trip<K: DhKemKey>() {
        let sk_r = K::random().unwrap();
        let pk_r = K::from_kem_public(&serialize_public(&sk_r).unwrap()).unwrap();
        let sk_s = K::random().unwrap();
        let pk_s = K::from_kem_public(&serialize_public(&sk_s).unwrap()).unwrap();

        let res = encap(&pk_r).unwrap();
        assert_eq!(res.enc.len(), K::KEM.enc_length());
        assert_eq!(res.shared_secret.len(), K::KEM.secret_length());
        assert_eq!(decap(&res.enc, &sk_r).unwrap(), res.shared_secret);

        // each encapsulation uses a new ephemeral key
        let res2 = encap(&pk_r).unwrap();
        assert_ne!(res.enc, res2.enc);
        assert_ne!(res.shared_secret, res2.shared_secret);

        // authenticated mode produces a different secret
        let res_auth = auth_encap(&pk_r, &sk_s).unwrap();
        assert_eq!(
            auth_decap(&res_auth.enc, &sk_r, &pk_s).unwrap(),
            res_auth.shared_secret
        );
        let other = K::random().unwrap();
        let other_pk = K::from_kem_public(&serialize_public(&other).unwrap()).unwrap();
        assert_ne!(
            auth_decap(&res_auth.enc, &sk_r, &other_pk).unwrap(),
            res_auth.shared_secret
        );
        // and cannot be recovered with the base mode
        assert_ne!(decap(&res_auth.enc, &sk_r).unwrap(), res_auth.shared_secret);

        // the wrong recipient key cannot recover the secret
        let wrong = K::random().unwrap();
        assert_ne!(decap(&res.enc, &wrong).unwrap(), res.shared_secret);

        // invalid encapsulated key lengths
        assert!(decap(&res.enc[1..], &sk_r).is_err());
        let mut long = res.enc.clone();
        long.push(0);
        assert!(decap(&long, &sk_r).is_err());
        assert!(decap(&[], &sk_r).is_err());

        // a public key cannot be used to decapsulate
        assert!(decap(&res.enc, &pk_r).is_err());
    }

    #[cfg(feature = "ec_curves")]
    mod nist {
        use super::*;
        use crate::alg::{p256::P256KeyPair, p384::P384KeyPair};
        use crate::repr::{KeyPublicBytes, ToPublicBytes};

        #[test]
        // RFC 9180 appendix A.3.1
        fn p256_rfc9180_expected() {
            let sk_r = P256KeyPair::from_secret_bytes(&hex!(
                "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"
            ))
            .unwrap();
            let pk_r = P256KeyPair::from_kem_public(&hex!(
                "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70
                 6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"
            ))
            .unwrap();
            let sk_e = P256KeyPair::from_secret_bytes(&hex!(
                "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"
            ))
            .unwrap();
            let enc = hex!(
                "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32
                 5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
            );
            let shared_secret =
                hex!("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8");

            assert_eq!(
                serialize_public(&sk_r).unwrap(),
                serialize_public(&pk_r).unwrap()
            );
            let res = encap_inner(&pk_r, &sk_e, None).unwrap();
            assert_eq!(res.enc, enc);
            assert_eq!(res.shared_secret, &shared_secret[..]);
            assert_eq!(decap(&enc, &sk_r).unwrap(), &shared_secret[..]);
        }

        #[test]
        fn p256_vector() {
            check_vector::<P256KeyPair>(&Vector {
                sk_r: &hex!("5cbee5d69ad4669b44ea0822ff6f0910a7b9e5f119298ed1333cb703f2d78db6"),
                pk_r: &hex!("04f791112c804e47e8c1eafdac919f5723271d09610917699d39714bde35f7cdec809572e69748b68207f0ca7a7a76dfa9b2c5df97515cc444a478494868c0ae1f"),
                sk_e: &hex!("a4f2ab39a3475ac66e4bae9edea78e4b5b8cdd1dc766c4bf74c529c2f036c899"),
                enc: &hex!("049882f5f512d7f21b4f47e193c0bb684dec66fd19cc2b8980a75c933e5305268d58d9ac4cec385dea5b2499599a7192005dc898b7867b984e3f82c78a33449af3"),
                sk_s: &hex!("15c25fccfede4ed559a207342dfd17daffdd461a3dcf66b8b96c96ccf83953c7"),
                pk_s: &hex!("04d93c1e7accd3e5e7f975c204a420c269e75ae1cdd7c9272e9764f49fa5a7d9a96a340c2555220402f66b4ec409f0cf904e9ba492a7151a7c412d421efba0b27a"),
                base: &hex!("e5b993caf6bacc4dfc8119807444cd6b1ffd388daecf883f9e512c2d0e95a3d7"),
                auth: Some(&hex!("1c037c8ce40041b00c670ff9e46a6d2e0a1a66a055af2e93da6b82a359d84d4e")),
            });
        }

        #[test]
        fn p384_vector() {
            check_vector::<P384KeyPair>(&Vector {
                sk_r: &hex!("0488ab1cba289e2d43f0b067c22ba64126339467732bdd16b393ca0962eecd977a029e9c0b0f5b80558a7b01288a897e"),
                pk_r: &hex!("0423d3d1cf7c2c5abe1e22e5203ad042ba6bd583c691396a2149a548282087f211fb19885b46df52fe4a64bb93238d8334af987fccebbf809832208da20eba854e912480da0fe9fa42d22ef2607ad826c69c40327501805c59725dab41157a0125"),
                sk_e: &hex!("05f2053c58b1366e634477c7d940961261529a824420bba6661ec3fc5895e6cac92c97c002f68f78f31a2644ef9453b8"),
                enc: &hex!("041cbec9ff9ce817a96f7868960e0b0d344e890d12e2f5a0b425b52fe54ec8f21c717ff1911321aa506f843a6b1286bb5f419886ff0d721a02aea1dcc010ec74e5ae9c1a623bab1831318b782aafa7ed1573bb13d46bd08f85ea6b7fb9a75ab704"),
                sk_s: &hex!("9e8c9cff516ac013d31f50c06bc16bc7c18aa79f560bb7fd59b9523df683b13db7b2629e026b0c98606e2b43f7fa3884"),
                pk_s: &hex!("04106c42abc70c6e5808d682a4ec39639eb4d46a226d06041549861c42a0bd6f12c091245c492f68f197669ef2bb5ed89be3673a240119b5bc96c68a6283dc9fde76e8fa8eefa3d70059b1c8555ba16fea4a1f186b6bc18a13a1c27cb15352d480"),
                base: &hex!("b6b88fb22b09cad8336efdcc8001420112d91d0030b414ed82d5d82b7aa36cab42f97f32c62866922c4b2cc3802f5d7d"),
                auth: Some(&hex!("6723746f6ecf1d93a7cc6cdce0ab5460be27874dff95a831fddf53435ac9651ef1913172e722c121548a506de55cfed0")),
            });
        }

        #[test]
        fn nist_round_trip() {
            check_round_trip::<P256KeyPair>();
            check_round_trip::<P384KeyPair>();
        }

        #[test]
        fn nist_compressed_enc_rejected() {
            let sk_r = P256KeyPair::random().unwrap();
            let pk_r = P256KeyPair::from_kem_public(&serialize_public(&sk_r).unwrap()).unwrap();
            let res = encap(&pk_r).unwrap();
            // the compressed form of a valid ephemeral key is not accepted
            let ephem = P256KeyPair::from_public_bytes(&res.enc).unwrap();
            let compressed = ephem.to_public_bytes().unwrap();
            assert_eq!(compressed.len(), 33);
            assert!(decap(&compressed, &sk_r).is_err());
            // a point not on the curve is not accepted
            let mut invalid = res.enc.clone();
            invalid[64] ^= 1;
            assert!(decap(&invalid, &sk_r).is_err());
        }
    }

    #[cfg(feature = "ed25519")]
    mod x25519 {
        use super::*;
        use crate::alg::x25519::X25519KeyPair;

        #[test]
        fn x25519_vector() {
            check_vector::<X25519KeyPair>(&Vector {
                sk_r: &hex!("7790330b18d76c45446b7d9d1b15e87d7da80ab3b6f8cdcc0871764f1d767c9c"),
                pk_r: &hex!("41852320ff367495fa522c94cb83af391e4e89018392725bbf2098dd931bc424"),
                sk_e: &hex!("95fe8f32f2036438e7f4c0e9157d5f7d730bc04618e1dd569084f67d3919d1fe"),
                enc: &hex!("6080bbe51005ea9acc863580ce57317d46bef6333558d5bfa97e461342985005"),
                sk_s: &hex!("aeb1202142bd84505f6760a671df6aaaeaab9303adbfead3ed330a77973300c9"),
                pk_s: &hex!("90ab790ecbf0704232ffe9436faeccc913b66a60e99c688a40bba4d5e2e61450"),
                base: &hex!("3014e1ac3c9bea2eddee26d2a5ebc9d644f521ecd3627af7f461223ba85b3519"),
                auth: Some(&hex!(
                    "d58cd7e439d7268cc431967240ace390b4072085685ddbe6015f21071e1c6ce9"
                )),
            });
        }

        #[test]
        fn x25519_round_trip() {
            check_round_trip::<X25519KeyPair>();
        }

        #[test]
        fn x25519_small_order_rejected() {
            let sk_r = X25519KeyPair::random().unwrap();
            // a small order point results in an all-zero shared secret
            assert!(decap(&[0u8; 32], &sk_r).is_err());
            let mut one = [0u8; 32];
            one[0] = 1;
            assert!(decap(&one, &sk_r).is_err());
            // also when encapsulating, or in the authenticated mode
            let bad_pk = X25519KeyPair::from_kem_public(&[0u8; 32]).unwrap();
            assert!(encap(&bad_pk).is_err());
            let sk_e = X25519KeyPair::random().unwrap();
            let enc = serialize_public(&sk_e).unwrap();
            assert!(auth_decap(&enc, &sk_r, &bad_pk).is_err());
        }
    }
}
