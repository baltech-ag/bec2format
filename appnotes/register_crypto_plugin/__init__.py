from bec2format import AES128 as AES128Base
from bec2format import PrivateEccKey as PrivateEccKeyBase
from bec2format import PublicEccKey as PublicEccKeyBase
from bec2format import register_AES128, register_PrivateEccKey, register_PublicEccKey

from .ecdsa import ECDH, NIST256p, SigningKey, VerifyingKey
from .pyaes import aes, blockfeeder


@register_AES128
class AES128Proxy(AES128Base):
    def __init__(self, key: bytes, iv: bytes | None = None) -> None:
        super().__init__(key, iv)
        self._key = key
        self._iv = iv

    def encrypt(self, data: bytes) -> bytes:
        mode = aes.AESModeOfOperationCBC(self._key, self._iv)
        encryptor = blockfeeder.Encrypter(mode, padding="none")
        pad_length = -len(data) % AES128Base.BLOCK_SIZE
        pad = bytes() if pad_length == 0 else bytes([0x00] * pad_length)
        ciphertext = encryptor.feed(data + pad)
        ciphertext += encryptor.feed()
        return ciphertext

    def decrypt(self, data: bytes) -> bytes:
        mode = aes.AESModeOfOperationCBC(self._key, self._iv)
        decryptor = blockfeeder.Decrypter(mode, padding="none")
        plaintext_padded = decryptor.feed(data)
        plaintext_padded += decryptor.feed()
        plaintext = plaintext_padded.rstrip(b"\0")
        return plaintext

    def mac(self, data: bytes) -> bytes:
        return self.encrypt(data)[-16:]


@register_PublicEccKey
class PublicEccKeyProxy(PublicEccKeyBase):
    def __init__(self, public_key: VerifyingKey) -> None:
        super().__init__()
        self.public_key = public_key

    @classmethod
    def create_from_der_fmt(cls, der_fmt: bytes) -> PublicEccKeyBase:
        return PublicEccKeyProxy(VerifyingKey.from_der(der_fmt))

    def to_der_fmt(self) -> bytes:
        return self.public_key.to_der()


@register_PrivateEccKey
class PrivateEccKeyProxy(PrivateEccKeyBase):
    CURVE = NIST256p  # SECP256R1

    def __init__(self, private_key: SigningKey) -> None:
        super().__init__()
        self.private_key = private_key

    @classmethod
    def create_from_der_fmt(cls, private_key_der_fmt: bytes) -> PrivateEccKeyBase:
        return PrivateEccKeyProxy(SigningKey.from_der(private_key_der_fmt))

    @classmethod
    def generate(cls) -> PrivateEccKeyBase:
        return cls(SigningKey.generate(curve=cls.CURVE))

    @property
    def public_key(self) -> PublicEccKeyBase:
        return PublicEccKeyProxy(self.private_key.verifying_key)

    def compute_dh_secret(self, public_key: PublicEccKeyBase) -> bytes:
        ecdh = ECDH(curve=self.CURVE)
        ecdh.load_private_key_der(self.private_key.to_der())
        ecdh.load_received_public_key_der(public_key.to_der_fmt())
        return ecdh.generate_sharedsecret_bytes()
