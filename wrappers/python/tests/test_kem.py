import pytest

from aries_askar import AskarError, Key, KeyAlg

KEMS = {
    KeyAlg.X25519: "DHKEM-X25519-HKDF-SHA256",
    KeyAlg.P256: "DHKEM-P256-HKDF-SHA256",
    KeyAlg.P384: "DHKEM-P384-HKDF-SHA384",
}
KEM_ALGS = list(KEMS)
ENC_LENGTHS = {KeyAlg.X25519: 32, KeyAlg.P256: 65, KeyAlg.P384: 97}
SECRET_LENGTHS = {KeyAlg.X25519: 32, KeyAlg.P256: 32, KeyAlg.P384: 48}


def public_key(key: Key) -> Key:
    return Key.from_public_bytes(key.algorithm, key.get_public_bytes())


@pytest.mark.parametrize("alg", KEM_ALGS)
def test_kem(alg: KeyAlg):
    kem = KEMS[alg]
    recip = Key.generate(alg)
    recip_pk = public_key(recip)

    enc, secret = recip_pk.kem_encap(kem)
    assert len(enc) == ENC_LENGTHS[alg]
    assert len(secret) == SECRET_LENGTHS[alg]
    assert recip.kem_decap(kem, enc) == secret

    # a different recipient cannot recover the secret
    other = Key.generate(alg)
    assert other.kem_decap(kem, enc) != secret


@pytest.mark.parametrize("alg", KEM_ALGS)
def test_kem_auth(alg: KeyAlg):
    kem = KEMS[alg]
    recip = Key.generate(alg)
    recip_pk = public_key(recip)
    sender = Key.generate(alg)
    sender_pk = public_key(sender)

    enc, secret = recip_pk.kem_auth_encap(kem, sender)
    assert recip.kem_auth_decap(kem, enc, sender_pk) == secret

    # the sender key must match
    other_pk = public_key(Key.generate(alg))
    assert recip.kem_auth_decap(kem, enc, other_pk) != secret

    # the unauthenticated mode produces a different secret
    assert recip.kem_decap(kem, enc) != secret


@pytest.mark.parametrize("alg", KEM_ALGS)
def test_kem_invalid(alg: KeyAlg):
    kem = KEMS[alg]
    recip = Key.generate(alg)
    enc, _ = public_key(recip).kem_encap(kem)
    with pytest.raises(AskarError):
        recip.kem_decap(kem, enc[:-1])
    with pytest.raises(AskarError):
        # a public key cannot be used to decapsulate
        public_key(recip).kem_decap(kem, enc)


def test_kem_unsupported_alg():
    key = Key.generate(KeyAlg.ED25519)
    with pytest.raises(AskarError):
        key.kem_encap("DHKEM-X25519-HKDF-SHA256")


def test_kem_mismatch():
    pk = public_key(Key.generate(KeyAlg.P256))
    with pytest.raises(AskarError):
        pk.kem_encap(KEMS[KeyAlg.P384])
    with pytest.raises(AskarError):
        pk.kem_encap("unknown-kem")
