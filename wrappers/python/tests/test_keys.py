import json

from aries_askar import (
    KeyAlg,
    Key,
    SeedMethod,
)


def test_aes_cbc_hmac():
    key = Key.generate(KeyAlg.A128CBC_HS256)
    assert key.algorithm == KeyAlg.A128CBC_HS256

    data = b"test message"
    nonce = key.aead_random_nonce()
    params = key.aead_params()
    assert params.nonce_length == 16
    assert params.tag_length == 16
    enc = key.aead_encrypt(data, nonce=nonce, aad=b"aad")
    dec = key.aead_decrypt(enc, nonce=nonce, aad=b"aad")
    assert data == bytes(dec)


def test_aes_gcm():
    key = Key.generate(KeyAlg.A128GCM)
    assert key.algorithm == KeyAlg.A128GCM

    data = b"test message"
    nonce = key.aead_random_nonce()
    params = key.aead_params()
    assert params.nonce_length == 12
    assert params.tag_length == 16
    enc = key.aead_encrypt(data, nonce=nonce, aad=b"aad")
    dec = key.aead_decrypt(enc, nonce=nonce, aad=b"aad")
    assert data == bytes(dec)


def test_bls_keygen():
    key = Key.from_seed(
        KeyAlg.BLS12_381_G1G2,
        b"testseed000000000000000000000001",
        method=SeedMethod.BlsKeyGen,
    )
    assert key.get_jwk_public(KeyAlg.BLS12_381_G1) == (
        '{"crv":"BLS12381_G1","kty":"OKP","x":'
        '"h56eYI8Qkq5hitICb-ik8wRTzcn6Fd4iY8aDNVc9q1xoPS3lh4DB_B4wNtar1HrV"}'
    )
    assert key.get_jwk_public(KeyAlg.BLS12_381_G2) == (
        '{"crv":"BLS12381_G2","kty":"OKP",'
        '"x":"iZIOsO6BgLV72zCrBE2ym3DEhDYcghnUMO4O8IVVD8yS-C_zu6OA3L-ny-AO4'
        'rbkAo-WuApZEjn83LY98UtoKpTufn4PCUFVQZzJNH_gXWHR3oDspJaCbOajBfm5qj6d"}'
    )
    assert key.get_jwk_public() == (
        '{"crv":"BLS12381_G1G2","kty":"OKP",'
        '"x":"h56eYI8Qkq5hitICb-ik8wRTzcn6Fd4iY8aDNVc9q1xoPS3lh4DB_B4wNtar1H'
        "rViZIOsO6BgLV72zCrBE2ym3DEhDYcghnUMO4O8IVVD8yS-C_zu6OA3L-ny-AO4rbk"
        'Ao-WuApZEjn83LY98UtoKpTufn4PCUFVQZzJNH_gXWHR3oDspJaCbOajBfm5qj6d"}'
    )


def test_ed25519():
    key = Key.generate(KeyAlg.ED25519)
    assert key.algorithm == KeyAlg.ED25519
    message = b"test message"
    sig = key.sign_message(message)
    assert key.verify_signature(message, sig)
    x25519_key = key.convert_key(KeyAlg.X25519)

    x25519_key_2 = Key.generate(KeyAlg.X25519)
    kex = x25519_key.key_exchange(KeyAlg.XC20P, x25519_key_2)
    assert isinstance(kex, Key)

    jwk = json.loads(key.get_jwk_public())
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"

    jwk = json.loads(key.get_jwk_secret())
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert "d" in jwk


def test_p256():
    key = Key.generate(KeyAlg.P256)
    assert key.algorithm == KeyAlg.P256
    message = b"test message"
    sig = key.sign_message(message)
    assert key.verify_signature(message, sig)

    key2 = Key.generate(KeyAlg.P256)
    kex = key.key_exchange(KeyAlg.XC20P, key2)
    assert isinstance(kex, Key)

    jwk = json.loads(key.get_jwk_public())
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"


def test_p384():
    key = Key.generate(KeyAlg.P384)
    assert key.algorithm == KeyAlg.P384
    message = b"test message"
    sig = key.sign_message(message)
    assert key.verify_signature(message, sig)

    key2 = Key.generate(KeyAlg.P384)
    kex = key.key_exchange(KeyAlg.XC20P, key2)
    assert isinstance(kex, Key)

    jwk = json.loads(key.get_jwk_public())
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-384"
