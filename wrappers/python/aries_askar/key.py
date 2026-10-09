"""Handling of Key instances."""

from typing import Union, Optional, Sequence, Tuple

from . import bindings
from .bindings import AeadParams, Encrypted, LocalKeyHandle
from .types import KeyAlg, KeyBackend, SeedMethod


class Key:
    """An active key or keypair instance."""

    def __init__(self, handle: LocalKeyHandle):
        """Initialize the Key instance."""
        self._handle = handle

    @classmethod
    def generate(
        cls,
        alg: Union[str, KeyAlg],
        *,
        key_backend: Optional[KeyBackend] = None,
        ephemeral: bool = False,
    ) -> "Key":
        return cls(bindings.key_generate(alg, key_backend, ephemeral))

    @classmethod
    def from_seed(
        cls,
        alg: Union[str, KeyAlg],
        seed: Union[str, bytes],
        *,
        method: Union[str, SeedMethod, None] = None,
    ) -> "Key":
        return cls(bindings.key_from_seed(alg, seed, method))

    @classmethod
    def from_secret_bytes(cls, alg: Union[str, KeyAlg], secret: bytes) -> "Key":
        return cls(bindings.key_from_secret_bytes(alg, secret))

    @classmethod
    def from_public_bytes(cls, alg: Union[str, KeyAlg], public: bytes) -> "Key":
        return cls(bindings.key_from_public_bytes(alg, public))

    @classmethod
    def from_jwk(cls, jwk: Union[dict, str, bytes]) -> "Key":
        return cls(bindings.key_from_jwk(jwk))

    @classmethod
    def get_supported_backends(cls) -> Sequence[str]:
        return bindings.key_get_supported_backends()

    @property
    def handle(self) -> LocalKeyHandle:
        """Accessor for the key handle."""
        return self._handle

    @property
    def algorithm(self) -> KeyAlg:
        alg_str = bindings.key_get_algorithm(self._handle)
        alg = KeyAlg.from_key_alg(alg_str)
        assert alg, "Key without alg is invalid"
        return alg

    @property
    def ephemeral(self) -> bool:
        return bindings.key_get_ephemeral(self._handle)

    def convert_key(self, alg: Union[str, KeyAlg]) -> "Key":
        return self.__class__(bindings.key_convert(self._handle, alg))

    def key_exchange(self, alg: Union[str, KeyAlg], pk: "Key") -> "Key":
        return self.__class__(bindings.key_exchange(alg, self._handle, pk._handle))

    def get_public_bytes(self) -> bytes:
        return bytes(bindings.key_get_public_bytes(self._handle))

    def get_secret_bytes(self) -> bytes:
        return bytes(bindings.key_get_secret_bytes(self._handle))

    def get_jwk_public(self, alg: Union[str, KeyAlg, None] = None) -> str:
        return bindings.key_get_jwk_public(self._handle, alg)

    def get_jwk_secret(self) -> bytes:
        return bytes(bindings.key_get_jwk_secret(self._handle))

    def get_jwk_thumbprint(self, alg: Union[str, KeyAlg, None] = None) -> str:
        return bindings.key_get_jwk_thumbprint(self._handle, alg)

    def aead_params(self) -> AeadParams:
        return bindings.key_aead_get_params(self._handle)

    def aead_random_nonce(self) -> bytes:
        return bytes(bindings.key_aead_random_nonce(self._handle))

    def aead_encrypt(
        self, message: Union[str, bytes], *, nonce: Optional[bytes] = None, aad: Optional[bytes] = None
    ) -> Encrypted:
        return bindings.key_aead_encrypt(self._handle, message, nonce, aad)

    def aead_decrypt(
        self,
        ciphertext: Union[bytes, Encrypted],
        *,
        nonce: bytes,
        tag: Optional[bytes] = None,
        aad: Optional[bytes] = None,
    ) -> bytes:
        return bytes(
            bindings.key_aead_decrypt(self._handle, ciphertext, nonce, tag, aad)
        )

    def sign_message(self, message: Union[str, bytes], sig_type: Optional[str] = None) -> bytes:
        return bytes(bindings.key_sign_message(self._handle, message, sig_type))

    def verify_signature(
        self, message: Union[str, bytes], signature: bytes, sig_type: Optional[str] = None
    ) -> bool:
        return bindings.key_verify_signature(self._handle, message, signature, sig_type)

    def wrap_key(self, other: "Key", *, nonce: Optional[bytes] = None) -> Encrypted:
        return bindings.key_wrap_key(self._handle, other._handle, nonce)

    def unwrap_key(
        self,
        alg: Union[str, KeyAlg],
        ciphertext: Union[bytes, Encrypted],
        *,
        nonce: Optional[bytes] = None,
        tag: Optional[bytes] = None,
    ) -> "Key":
        return Key(bindings.key_unwrap_key(self._handle, alg, ciphertext, nonce, tag))

    def dhkem_encap(self) -> Tuple[bytes, bytes]:
        """Encapsulate a new shared secret for this (recipient) public key.

        Performs the `Encap` operation of the Diffie-Hellman KEM defined in
        RFC 9180, for P-256, P-384 and X25519 keys.

        Returns:
            A tuple of the encapsulated key (to send to the recipient) and the
            KEM shared secret
        """
        enc, secret = bindings.key_dhkem_encap(self._handle)
        return bytes(enc), bytes(secret)

    def dhkem_decap(self, enc: bytes) -> bytes:
        """Recover the KEM shared secret from an encapsulated key.

        Performs the `Decap` operation using this (recipient) secret key.
        """
        return bytes(bindings.key_dhkem_decap(self._handle, enc))

    def dhkem_auth_encap(self, sender_key: "Key") -> Tuple[bytes, bytes]:
        """Encapsulate a new shared secret for this (recipient) public key.

        Performs the `AuthEncap` operation, authenticated by the sender secret key.

        Returns:
            A tuple of the encapsulated key and the KEM shared secret
        """
        enc, secret = bindings.key_dhkem_auth_encap(self._handle, sender_key._handle)
        return bytes(enc), bytes(secret)

    def dhkem_auth_decap(self, enc: bytes, sender_key: "Key") -> bytes:
        """Recover the KEM shared secret from an encapsulated key.

        Performs the `AuthDecap` operation using this (recipient) secret key and
        the sender public key.
        """
        return bytes(
            bindings.key_dhkem_auth_decap(self._handle, enc, sender_key._handle)
        )

    def __repr__(self) -> str:
        return (
            f"<Key(handle={self._handle}, alg={self.algorithm}, "
            f"ephemeral={self.ephemeral})>"
        )
