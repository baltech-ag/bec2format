from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from bec2format import AES128, register_AES128


@register_AES128
class AES128Proxy(AES128):
    def __init__(self, key: bytes, iv: bytes) -> None:
        super().__init__(key, iv)
        self._cipher = Cipher(
            algorithms.AES128(self._key),
            modes.CBC(self._iv or b"\x00" * self.BLOCK_SIZE),
        )

    def encrypt(self, data: bytes) -> bytes:
        pad_length = -len(data) % AES128.BLOCK_SIZE
        pad = b"" if pad_length == 0 else bytes([0x00] * pad_length)
        encryptor = self._cipher.encryptor()
        return encryptor.update(data + pad) + encryptor.finalize()

    def decrypt(self, data: bytes) -> bytes:
        decryptor = self._cipher.decryptor()
        plaintext_padded = decryptor.update(data) + decryptor.finalize()
        return plaintext_padded.rstrip(b"\0")

    def mac(self, data: bytes) -> bytes:
        return self.encrypt(data)[-16:]
