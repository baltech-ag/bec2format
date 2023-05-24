from abc import ABC, abstractmethod
from typing import Type


class AES128(ABC):
    BLOCK_SIZE = 16
    KEY_SIZE = 16

    @abstractmethod
    def __init__(self, key: bytes, iv: bytes | None = None) -> None:
        ...

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        ...

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        ...

    @abstractmethod
    def mac(self, data: bytes) -> bytes:
        ...


class PublicEccKey:
    @classmethod
    @abstractmethod
    def create_from_der_fmt(cls, der_fmt: bytes) -> "PublicEccKey":
        raise NotImplementedError()

    @abstractmethod
    def to_der_fmt(self) -> bytes:
        ...

    def to_raw_bin_fmt(self) -> bytes:
        der_header_len = 27
        der_fmt = self.to_der_fmt()
        return der_fmt[der_header_len:]


class PrivateEccKey:
    @classmethod
    @abstractmethod
    def create_from_der_fmt(cls, private_key_der_fmt: bytes) -> "PrivateEccKey":
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def generate(cls) -> "PrivateEccKey":
        raise NotImplementedError()

    @property
    @abstractmethod
    def public_key(self) -> PublicEccKey:
        ...

    @abstractmethod
    def compute_dh_secret(self, public_key: PublicEccKey) -> bytes:
        ...


def pad(data: bytes) -> bytes:
    pad_length = -len(data) % __AES128.BLOCK_SIZE
    return data + bytes([0x00] * pad_length)


__AES128: Type[AES128] = AES128
__PublicEccKey: Type[PublicEccKey] = PublicEccKey
__PrivateEccKey: Type[PrivateEccKey] = PrivateEccKey


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


def create_AES128(key: bytes, iv: bytes | None = None) -> __AES128:
    return __AES128(key, iv)


def create_public_ecc_key_from_der_fmt(der_fmt: bytes) -> __PublicEccKey:
    return __PublicEccKey.create_from_der_fmt(der_fmt)


def generate_private_ecc_key() -> __PrivateEccKey:
    return __PrivateEccKey.generate()
