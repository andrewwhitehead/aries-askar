use super::local_key::LocalKey;
use crate::{
    crypto::{
        alg::{x25519::X25519KeyPair, KeyAlg},
        buffer::SecretBytes,
        encrypt::crypto_box::{
            crypto_box as nacl_box, crypto_box_open as nacl_box_open,
            crypto_box_seal as nacl_box_seal, crypto_box_seal_open as nacl_box_seal_open,
            CBOX_NONCE_LENGTH, CBOX_TAG_LENGTH,
        },
        kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs},
        random::fill_random,
    },
    error::Error,
};

#[inline]
fn cast_x25519(key: &LocalKey) -> Result<&X25519KeyPair, Error> {
    if let Some(kp) = key.inner.downcast_ref::<X25519KeyPair>() {
        Ok(kp)
    } else {
        Err(err_msg!(Input, "x25519 keypair required"))
    }
}

/// Generate a new random nonce for crypto_box
pub fn crypto_box_random_nonce() -> Result<[u8; CBOX_NONCE_LENGTH], Error> {
    let mut nonce = [0u8; CBOX_NONCE_LENGTH];
    fill_random(&mut nonce);
    Ok(nonce)
}

/// Encrypt a message with crypto_box and a detached nonce
pub fn crypto_box(
    recip_x25519: &LocalKey,
    sender_x25519: &LocalKey,
    message: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Error> {
    let recip_pk = cast_x25519(recip_x25519)?;
    let sender_sk = cast_x25519(sender_x25519)?;
    let mut buffer = SecretBytes::from_slice_reserve(message, CBOX_TAG_LENGTH);
    nacl_box(recip_pk, sender_sk, &mut buffer, nonce)?;
    Ok(buffer.into_vec())
}

/// Decrypt a message with crypto_box and a detached nonce
pub fn crypto_box_open(
    recip_x25519: &LocalKey,
    sender_x25519: &LocalKey,
    message: &[u8],
    nonce: &[u8],
) -> Result<SecretBytes, Error> {
    let recip_pk = cast_x25519(recip_x25519)?;
    let sender_sk = cast_x25519(sender_x25519)?;
    let mut buffer = SecretBytes::from_slice(message);
    nacl_box_open(recip_pk, sender_sk, &mut buffer, nonce)?;
    Ok(buffer)
}

/// Perform message encryption equivalent to libsodium's `crypto_box_seal`
pub fn crypto_box_seal(recip_x25519: &LocalKey, message: &[u8]) -> Result<Vec<u8>, Error> {
    let kp = cast_x25519(recip_x25519)?;
    let sealed = nacl_box_seal(kp, message)?;
    Ok(sealed.into_vec())
}

/// Perform message decryption equivalent to libsodium's `crypto_box_seal_open`
pub fn crypto_box_seal_open(
    recip_x25519: &LocalKey,
    ciphertext: &[u8],
) -> Result<SecretBytes, Error> {
    let kp = cast_x25519(recip_x25519)?;
    Ok(nacl_box_seal_open(kp, ciphertext)?)
}

/// Derive an ECDH-1PU shared key for authenticated encryption
#[allow(clippy::too_many_arguments)]
pub fn derive_key_ecdh_1pu(
    key_alg: KeyAlg,
    ephem_key: &LocalKey,
    sender_key: &LocalKey,
    recip_key: &LocalKey,
    alg_id: &[u8],
    apu: &[u8],
    apv: &[u8],
    cc_tag: &[u8],
    receive: bool,
) -> Result<LocalKey, Error> {
    let derive = Ecdh1PU::new(
        &*ephem_key,
        &*sender_key,
        &*recip_key,
        alg_id,
        apu,
        apv,
        cc_tag,
        receive,
    );
    LocalKey::from_key_derivation(key_alg, derive)
}

/// Derive an ECDH-ES shared key for anonymous encryption
pub fn derive_key_ecdh_es(
    key_alg: KeyAlg,
    ephem_key: &LocalKey,
    recip_key: &LocalKey,
    alg_id: &[u8],
    apu: &[u8],
    apv: &[u8],
    receive: bool,
) -> Result<LocalKey, Error> {
    let derive = EcdhEs::new(&*ephem_key, &*recip_key, alg_id, apu, apv, receive);
    LocalKey::from_key_derivation(key_alg, derive)
}
