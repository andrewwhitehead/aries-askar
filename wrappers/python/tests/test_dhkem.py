import pytest

from aries_askar import AskarError, Key, KeyAlg

DHKEM_ALGS = [KeyAlg.X25519, KeyAlg.P256, KeyAlg.P384]
ENC_LENGTHS = {KeyAlg.X25519: 32, KeyAlg.P256: 65, KeyAlg.P384: 97}
SECRET_LENGTHS = {KeyAlg.X25519: 32, KeyAlg.P256: 32, KeyAlg.P384: 48}


def public_key(key: Key) -> Key:
    return Key.from_public_bytes(key.algorithm, key.get_public_bytes())


@pytest.mark.parametrize("alg", DHKEM_ALGS)
def test_dhkem(alg: KeyAlg):
    recip = Key.generate(alg)
    recip_pk = public_key(recip)

    enc, secret = recip_pk.dhkem_encap()
    assert len(enc) == ENC_LENGTHS[alg]
    assert len(secret) == SECRET_LENGTHS[alg]
    assert recip.dhkem_decap(enc) == secret

    # a different recipient cannot recover the secret
    other = Key.generate(alg)
    assert other.dhkem_decap(enc) != secret


@pytest.mark.parametrize("alg", DHKEM_ALGS)
def test_dhkem_auth(alg: KeyAlg):
    recip = Key.generate(alg)
    recip_pk = public_key(recip)
    sender = Key.generate(alg)
    sender_pk = public_key(sender)

    enc, secret = recip_pk.dhkem_auth_encap(sender)
    assert recip.dhkem_auth_decap(enc, sender_pk) == secret

    # the sender key must match
    other_pk = public_key(Key.generate(alg))
    assert recip.dhkem_auth_decap(enc, other_pk) != secret

    # the unauthenticated mode produces a different secret
    assert recip.dhkem_decap(enc) != secret


@pytest.mark.parametrize("alg", DHKEM_ALGS)
def test_dhkem_invalid(alg: KeyAlg):
    recip = Key.generate(alg)
    enc, _ = public_key(recip).dhkem_encap()
    with pytest.raises(AskarError):
        recip.dhkem_decap(enc[:-1])
    with pytest.raises(AskarError):
        # a public key cannot be used to decapsulate
        public_key(recip).dhkem_decap(enc)


def test_dhkem_unsupported_alg():
    key = Key.generate(KeyAlg.ED25519)
    with pytest.raises(AskarError):
        key.dhkem_encap()
