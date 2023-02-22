//! Compatibility with libsodium's crypto_box construct

use crate::{
    buffer::Writer,
    generic_array::{typenum::Unsigned, GenericArray},
};
use aead::{AeadCore, AeadInPlace};
use blake2::{digest::Update, digest::VariableOutput, Blake2bVar};
use crypto_box_rs::{self as cbox, SalsaBox};

use crate::{
    alg::x25519::X25519KeyPair,
    buffer::{ResizeBuffer, SecretVec, WriteBuffer},
    error::Error,
    key::KeyGen,
    repr::FromPublicBytes,
};

/// The length of the salsa box nonce
pub const CBOX_NONCE_LENGTH: usize = NonceSize::<SalsaBox>::USIZE;
/// The length of the salsa box key (x25519 public key)
pub const CBOX_KEY_LENGTH: usize = crate::alg::x25519::PUBLIC_KEY_LENGTH;
/// The length of the salsa box tag
pub const CBOX_TAG_LENGTH: usize = TagSize::<SalsaBox>::USIZE;

type NonceSize<A> = <A as AeadCore>::NonceSize;

type TagSize<A> = <A as AeadCore>::TagSize;

#[inline]
fn secret_key_from(kp: &X25519KeyPair) -> Result<cbox::SecretKey, Error> {
    if let Some(sk) = kp.secret.as_ref() {
        Ok(cbox::SecretKey::from(sk.to_bytes()))
    } else {
        Err(err_msg!(MissingSecretKey))
    }
}

#[inline]
fn nonce_from(nonce: &[u8]) -> Result<&GenericArray<u8, NonceSize<SalsaBox>>, Error> {
    if nonce.len() == NonceSize::<SalsaBox>::USIZE {
        Ok(GenericArray::from_slice(nonce))
    } else {
        Err(err_msg!(InvalidNonce))
    }
}

/// Encrypt a message into a crypto box with a given nonce
pub fn crypto_box<B: ResizeBuffer>(
    recip_pk: &X25519KeyPair,
    sender_sk: &X25519KeyPair,
    buffer: &mut B,
    nonce: &[u8],
) -> Result<(), Error> {
    let sender_sk = secret_key_from(sender_sk)?;
    let nonce = nonce_from(nonce)?;
    let pk = recip_pk.public.to_bytes().into();
    let box_inst = SalsaBox::new(&pk, &sender_sk);
    let tag = box_inst
        .encrypt_in_place_detached(nonce, &[], buffer.as_mut())
        .map_err(|_| err_msg!(Encryption, "Crypto box AEAD encryption error"))?;
    buffer.buffer_insert(0, &tag[..])?;
    Ok(())
}

/// Unencrypt a crypto box
pub fn crypto_box_open<B: ResizeBuffer>(
    recip_sk: &X25519KeyPair,
    sender_pk: &X25519KeyPair,
    buffer: &mut B,
    nonce: &[u8],
) -> Result<(), Error> {
    let recip_sk = secret_key_from(recip_sk)?;
    let nonce = nonce_from(nonce)?;
    let buf_len = buffer.as_ref().len();
    if buf_len < CBOX_TAG_LENGTH {
        return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
    }
    // the tag is prepended
    let tag = GenericArray::clone_from_slice(&buffer.as_ref()[..CBOX_TAG_LENGTH]);
    let pk = sender_pk.public.to_bytes().into();
    let box_inst = SalsaBox::new(&pk, &recip_sk);
    box_inst
        .decrypt_in_place_detached(nonce, &[], &mut buffer.as_mut()[CBOX_TAG_LENGTH..], &tag)
        .map_err(|_| err_msg!(Encryption, "Crypto box AEAD decryption error"))?;
    buffer.buffer_remove(0..CBOX_TAG_LENGTH)?;
    Ok(())
}

/// Construct a deterministic nonce for an ephemeral and recipient key
pub fn crypto_box_seal_nonce(
    ephemeral_pk: &[u8],
    recip_pk: &[u8],
) -> Result<[u8; CBOX_NONCE_LENGTH], Error> {
    let mut key_hash = Blake2bVar::new(CBOX_NONCE_LENGTH).unwrap();
    key_hash.update(ephemeral_pk);
    key_hash.update(recip_pk);
    let mut nonce = [0u8; CBOX_NONCE_LENGTH];
    key_hash.finalize_variable(&mut nonce).unwrap();
    Ok(nonce)
}

/// Encrypt a message for a recipient using an ephemeral key and deterministic nonce
// Could add a non-alloc version, if needed
pub fn crypto_box_seal(recip_pk: &X25519KeyPair, message: &[u8]) -> Result<SecretVec, Error> {
    let ephem_kp = X25519KeyPair::random()?;
    let ephem_pk_bytes = ephem_kp.public.as_bytes();
    let buf_len = CBOX_KEY_LENGTH + CBOX_TAG_LENGTH + message.len();
    let mut buffer = SecretVec::with_capacity(buf_len);
    buffer.buffer_write(ephem_pk_bytes)?;
    buffer.buffer_write(message)?;
    let mut writer = Writer::from_vec_skip(buffer.as_vec_mut(), CBOX_KEY_LENGTH);
    let nonce = crypto_box_seal_nonce(ephem_pk_bytes, recip_pk.public.as_bytes())?.to_vec();
    crypto_box(recip_pk, &ephem_kp, &mut writer, &nonce[..])?;
    Ok(buffer)
}

/// Unseal a sealed crypto box
pub fn crypto_box_seal_open(
    recip_sk: &X25519KeyPair,
    ciphertext: &[u8],
) -> Result<SecretVec, Error> {
    let ephem_pk = X25519KeyPair::from_public_bytes(&ciphertext[..CBOX_KEY_LENGTH])?;
    let mut buffer = SecretVec::from_slice(&ciphertext[CBOX_KEY_LENGTH..]);
    let nonce = crypto_box_seal_nonce(ephem_pk.public.as_bytes(), recip_sk.public.as_bytes())?;
    crypto_box_open(recip_sk, &ephem_pk, &mut buffer, &nonce)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::SecretVec;
    use crate::repr::{FromSecretBytes, ToPublicBytes};

    #[test]
    fn crypto_box_round_trip_expected() {
        let sk = X25519KeyPair::from_secret_bytes(&hex!(
            "a8bdb9830f8790d242f66e04b11cc2a14c752a7b63c073f3c68e9adb151cc854"
        ))
        .unwrap();
        let pk = X25519KeyPair::from_public_bytes(&hex!(
            "07d0b594683bdb6af5f4eacb1a392687d580a58db196a752dca316dedb7d251c"
        ))
        .unwrap();
        let message = b"hello there";
        let nonce = b"012345678912012345678912";
        let mut buffer = SecretVec::from_slice(message);
        crypto_box(&pk, &sk, &mut buffer, nonce).unwrap();
        assert_eq!(
            buffer,
            &hex!("848dc97d373f7aa2223b57780c60f7731cc8721d567baa8f2b5583")[..]
        );

        crypto_box_open(&sk, &pk, &mut buffer, nonce).unwrap();
        assert_eq!(buffer, &message[..]);
    }

    #[test]
    fn crypto_box_seal_round_trip() {
        let recip = X25519KeyPair::random().unwrap();

        let recip_public =
            X25519KeyPair::from_public_bytes(recip.to_public_bytes().unwrap().as_ref()).unwrap();

        let message = b"hello there";
        let sealed = crypto_box_seal(&recip_public, message).unwrap();
        assert_ne!(sealed, &message[..]);

        let open = crypto_box_seal_open(&recip, &sealed).unwrap();
        assert_eq!(open, &message[..]);
    }

    #[test]
    fn crypto_box_unseal_expected() {
        use crate::alg::ed25519::Ed25519KeyPair;
        let recip = Ed25519KeyPair::from_secret_bytes(b"testseed000000000000000000000001")
            .unwrap()
            .to_x25519_keypair();
        let ciphertext = hex!(
            "ed443c0377a579857f2f00543e0da0f2585b6119cd9e43c871e4f1114c7ce9050b
            a8811edf39d257bbeec0d423a0a7ff98d424fbfa9d52e0c5b3f674738f75d8e727f
            5526296482fd0fd013d71d50ce4ce5ebe9c2fa1c230298419a9"
        );
        crypto_box_seal_open(&recip, &ciphertext).unwrap();
    }
}
