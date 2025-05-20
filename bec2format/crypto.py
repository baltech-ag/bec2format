from typing import Callable, Optional, Type


class AES128:
    BLOCK_SIZE = 16
    KEY_SIZE = 16

    def __init__(self, key: bytes, iv: Optional[bytes] = None) -> None:
        self._key = key
        self._iv = iv

    def encrypt(self, data: bytes) -> bytes:
        raise NotImplementedError()

    def decrypt(self, data: bytes) -> bytes:
        raise NotImplementedError()

    def mac(self, data: bytes) -> bytes:
        raise NotImplementedError()


class PublicEccKey:
    @classmethod
    def create_from_der_fmt(cls, der_fmt: bytes) -> "PublicEccKey":
        raise NotImplementedError()

    @classmethod
    def create_from_raw_fmt(cls, raw_fmt: bytes):
        der_header = bytes.fromhex(
            "3059301306072A8648CE3D020106082A8648CE3D03010703420004"
        )
        return cls.create_from_der_fmt(der_header + raw_fmt)

    def to_der_fmt(self) -> bytes:
        raise NotImplementedError()

    def to_raw_bin_fmt(self) -> bytes:
        der_header_len = 27
        der_fmt = self.to_der_fmt()
        return der_fmt[der_header_len:]


class PrivateEccKey:
    @classmethod
    def create_from_der_fmt(cls, private_key_der_fmt: bytes) -> "PrivateEccKey":
        raise NotImplementedError()

    @classmethod
    def generate(cls) -> "PrivateEccKey":
        raise NotImplementedError()

    @property
    def public_key(self) -> PublicEccKey:
        raise NotImplementedError()

    def compute_dh_secret(self, public_key: PublicEccKey) -> bytes:
        raise NotImplementedError()


RandomBytesFunc = Callable[[int], bytes]


def __random_bytes_impl(num_bytes: int) -> bytes:
    raise NotImplementedError()


def pad(data: bytes) -> bytes:
    pad_length = -len(data) % __AES128.BLOCK_SIZE
    return data + bytes([0x00] * pad_length)


__AES128: Type[AES128] = AES128
__PublicEccKey: Type[PublicEccKey] = PublicEccKey
__PrivateEccKey: Type[PrivateEccKey] = PrivateEccKey
__random_bytes: RandomBytesFunc = __random_bytes_impl


def register_AES128(impl: Type[__AES128]) -> Type[__AES128]:
    global __AES128
    __AES128 = impl
    return __AES128


def register_PublicEccKey(impl: Type[__PublicEccKey]) -> Type[__PublicEccKey]:
    global __PublicEccKey
    __PublicEccKey = impl
    return __PublicEccKey


def register_PrivateEccKey(impl: Type[__PrivateEccKey]) -> Type[__PrivateEccKey]:
    global __PrivateEccKey
    __PrivateEccKey = impl
    return __PrivateEccKey


def register_random_bytes(impl: RandomBytesFunc) -> RandomBytesFunc:
    global __random_bytes
    __random_bytes = impl
    return __random_bytes


def create_AES128(key: bytes, iv: Optional[bytes] = None) -> __AES128:
    return __AES128(key, iv)


def create_public_ecc_key_from_der_fmt(der_fmt: bytes) -> __PublicEccKey:
    return __PublicEccKey.create_from_der_fmt(der_fmt)


def create_public_ecc_key_from_raw_fmt(raw_fmt: bytes) -> __PublicEccKey:
    return __PublicEccKey.create_from_raw_fmt(raw_fmt)


def generate_private_ecc_key() -> __PrivateEccKey:
    return __PrivateEccKey.generate()


def random_bytes(num_bytes: int) -> bytes:
    return __random_bytes(num_bytes)
