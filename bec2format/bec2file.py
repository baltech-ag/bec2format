from hashlib import sha256
from io import BytesIO
from typing import Callable, ClassVar, Iterable, Optional, TextIO, Type, TypeVar

from .bf3file import Bf3File
from .bytes_reader import BytesReader
from .configid import (
    ConfigId,
    MissingDeviceSettingsNameError,
    MissingProjectSettingsNameError,
)
from .crypto import (
    AES128,
    PrivateEccKey,
    PublicEccKey,
    create_AES128,
    create_public_ecc_key_from_der_fmt,
    create_public_ecc_key_from_raw_fmt,
    generate_private_ecc_key,
    random_bytes,
)
from .error import Bec2FileFormatError

CONFIG_SECURITY_CODE_SIZE = 8
CUSTOMER_KEY_SIZE = 10
BEC2_FILE_SIG = b"BEC2\0"


def crc8404B(data, start_value: int = 0xFFFF) -> int:
    """
    used for MIC Transponder, Mifare ...
    generator Polynom: x^16 + x^12 + x^5 + 1
    """
    cur_crc = int(start_value)
    for c in data:
        byte = c ^ (cur_crc & 0xFF)
        byte ^= (byte << 4) & 0xFF
        cur_crc = (cur_crc >> 8) ^ (byte << 8) ^ (byte << 3) ^ (byte >> 4)
    return cur_crc


class Encryptor:
    """
    Base Class for all kinds of encryptors.

    An encryptor contains the encryption algorithm AND format for AuthBlocks.
    It is externalized into an extra class to support hardware crypto units
    without requiring the AuthBlock (und thus Bec2File) objects to get
    dependencies to I/O objects.

    The class hierarchy for encryptors is:

    - Encryptor (abstract)
      - CustKeyEncryptor (abstract)
        - SoftwareCustKeyEncryptor (only for testing purposes)
      - EccEncryptor
        - EccDecryptor (only for testing purposes)
      - ConfigSecurityCodeEncryptor
    """

    def encrypt(self, plaintext: bytes) -> bytes:
        raise NotImplementedError()

    def decrypt(self, ciphertext: bytes) -> bytes:
        raise NotImplementedError()

    def __repr__(self) -> str:
        return "{class_name}(...)".format(class_name=self.__class__.__name__)


class KeySelectorEncryptor(Encryptor):
    def __init__(self, key_selector: int) -> None:
        self.key_selector = key_selector


class AesEncryptorMixin(Encryptor):
    """
    AES Encryption Logic that simulates the crypto container format
    provided by the BRP command Crypto.EncryptBuffer.

    (https://docs.baltech.de/refman/cmds/crypto/encryptbuffer.html)
    """

    def __init__(self, crypto_key: bytes) -> None:
        self.cipher = create_AES128(crypto_key)

    def encrypt(self, plaintext: bytes) -> bytes:
        self.cipher.iv = bytes([0x00] * AES128.BLOCK_SIZE)
        header_len = 2  # header = 'B' + lenbyte
        min_padding_len = 1  # enforce minimal number of padding bytes
        crc = crc8404B(plaintext).to_bytes(2, "big")
        padding_len = (
            -(header_len + min_padding_len + len(plaintext) + len(crc))
            % AES128.BLOCK_SIZE
        ) + min_padding_len
        plaintext = (
            b"B"
            + (len(plaintext) + len(crc)).to_bytes(1, "big")  # header
            + bytes([0x00] * padding_len)  # header
            + plaintext
            + crc
        )
        return self.cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        self.cipher.iv = bytes([0x00] * AES128.BLOCK_SIZE)
        frame_rdr = BytesReader(self.cipher.decrypt(ciphertext), "Decrypted Frame")
        if frame_rdr.read(1) != b"B":
            raise Bec2FileFormatError('Authblock has to start with "B"')
        payload_plus_crc_len = int.from_bytes(frame_rdr.read(1), "big")
        frame_rdr.seek(len(ciphertext) - payload_plus_crc_len)  # skip padding
        payload = frame_rdr.read(payload_plus_crc_len - 2)
        crc = int.from_bytes(frame_rdr.read(2), "big")
        if crc8404B(payload) != crc:
            raise Bec2FileFormatError("Invalid CRC")
        return payload


class CustKeyEncryptor(Encryptor):
    """
    Baseclass for all CustKeyEncryptors.

    The main feature of CustKeyEncryptors is, that they insert the custom key
    into the given plain data before encrypting it.
    """

    pass


class SoftwareCustKeyEncryptor(AesEncryptorMixin, CustKeyEncryptor):
    """
    Softwareimplementation of CustomKey encryptor.

    This encryptor is mainly for testing as it requires knowledge of the
    CustomKey.
    """

    def __init__(
        self,
        crypto_key: bytes,
        customer_key: Optional[bytes] = None,
        customer_key_pos: Optional[int] = None,
    ) -> None:
        super().__init__(crypto_key)
        self.crypto_key = crypto_key
        self.customer_key = customer_key
        self.customer_key_pos = customer_key_pos

    def encrypt(self, plaintext: bytes):
        if self.customer_key and self.customer_key_pos:
            plaintext = bytearray(plaintext)
            plaintext[
                self.customer_key_pos : self.customer_key_pos + CUSTOMER_KEY_SIZE
            ] = self.customer_key
        return super().encrypt(bytes(plaintext))

    def decrypt(self, ciphertext):
        plaintext = super().decrypt(ciphertext)
        if self.customer_key and self.customer_key_pos:
            ck_pos = self.customer_key_pos
            if plaintext[ck_pos : ck_pos + CUSTOMER_KEY_SIZE] != self.customer_key:
                raise Bec2FileFormatError("CustomerKey does not match")
            plaintext = bytearray(plaintext)
            plaintext[ck_pos : ck_pos + CUSTOMER_KEY_SIZE] = bytes(
                [0x00] * CUSTOMER_KEY_SIZE
            )
        return bytes(plaintext)


class EccEncryptor(KeySelectorEncryptor):
    """
    Standard encryptor for ECC

    is it contains only the public key it can be used only for encryption
    """

    KEYSEL_FW_STD = 0
    KEYSEL_KEYSTORE_STD = 1
    KEYSEL_KEYSTORE_ALT0 = 2
    KEYSEL_KEYSTORE_ALT1 = 3

    DEFAULT_PUBLIC_KEYS: dict[int, bytes] = {
        KEYSEL_FW_STD: bytes.fromhex(
            "3059301306072A8648CE3D020106082A8648CE3D03010703420004057B565D976"
            "A3306E8BD094A4671138198707D0BB67C88A45E8F375DCB1416C9519884E2109A"
            "02792072AF237911A612EB16213836E90FDD421B479EBD98158E"
        ),
        KEYSEL_KEYSTORE_STD: bytes.fromhex(
            "3059301306072A8648CE3D020106082A8648CE3D03010703420004D7B1B5CBD05"
            "87AE22E91AEE229B9534A920C905F58513CB4391F8C3F5A1B464CCC05917E5C59"
            "C3AE3E1197992B2FBB24F34238D1E4BBC62DC0DBC8F36903E92B"
        ),
        KEYSEL_KEYSTORE_ALT0: bytes.fromhex(
            "3059301306072A8648CE3D020106082A8648CE3D030107034200040CD731ED373"
            "0E53F7244EE71D8D54F5300885FF645EC8FD27FA3D9D1C4629FAF6536A1F5B46F"
            "0C7CA923EE284C115B9D6514EDEF9AA1FDBF1F54030B49AEF8A6"
        ),
        KEYSEL_KEYSTORE_ALT1: bytes.fromhex(
            "3059301306072A8648CE3D020106082A8648CE3D03010703420004B6BC3D31841"
            "7AE9099A228C29A0DE85AC053EAB5B3AA508BF4A438BF15FF8B551A0400405180"
            "1A3D08A6055715C9DFF38FD2EFAA311C8154BD9A302597C86053"
        ),
    }

    def __init__(
        self,
        key_selector: int = KEYSEL_FW_STD,
        public_key: Optional[PublicEccKey] = None,
    ) -> None:
        super().__init__(key_selector)
        self.public_key = public_key or create_public_ecc_key_from_der_fmt(
            self.DEFAULT_PUBLIC_KEYS[key_selector]
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        temp_privatekey = generate_private_ecc_key()
        ecdh_secret = temp_privatekey.compute_dh_secret(self.public_key)
        ecdh_sha_secret = sha256(ecdh_secret).digest()
        temp_aes_key = create_AES128(ecdh_sha_secret[: AES128.KEY_SIZE])
        return (
            b"\x04"
            + temp_privatekey.public_key.to_raw_bin_fmt()
            + temp_aes_key.encrypt(plaintext)
        )


class EccDecryptor(EccEncryptor):
    """
    Decryptor AND Encryptor for ECC

    It has to be constructed with a private key. As the actual private keys are
    secret it only for testing purposes.
    """

    def __init__(self, key_selector: int, private_key: PrivateEccKey) -> None:
        super().__init__(key_selector, private_key.public_key)
        self.private_key = private_key

    def decrypt(self, ciphertext: bytes) -> bytes:
        auth_block = BytesReader(ciphertext, self.__class__.__name__)
        if auth_block.read(1) != b"\x04":
            raise ValueError("Invalid encrypted ECC Block format")
        temp_publickey_raw = auth_block.read(64)
        temp_publickey = create_public_ecc_key_from_raw_fmt(temp_publickey_raw)
        encrypted_session_key = auth_block.read(AES128.BLOCK_SIZE)
        ecdh_secret = self.private_key.compute_dh_secret(temp_publickey)
        ecdh_sha_secret = sha256(ecdh_secret).digest()
        temp_aes_key = create_AES128(ecdh_sha_secret[: AES128.KEY_SIZE])
        return temp_aes_key.decrypt(encrypted_session_key)


class ConfigSecurityCodeEncryptor(AesEncryptorMixin, Encryptor):
    """
    Encrypt authblock with the ConfigSecurityCode

    As the ConfigSecurityCode is no AES key (too short) it requiers
    preprocessing which is the job of this class. The actual encryption is
    based on the standard AES crypto format (see AesEncryptionMixin).
    """

    def __init__(self, config_security_code: bytes) -> None:
        csc_digest = sha256(config_security_code).digest()
        trimmed_csc_digest = csc_digest[: AES128.BLOCK_SIZE]
        super().__init__(crypto_key=trimmed_csc_digest)
        self.config_security_code = config_security_code


class AuthBlock:
    TAG: Optional[int] = None
    REQUIRED_ENCRYPTOR_CLS: Type[Encryptor] = Encryptor

    @classmethod
    def select_encryptor(
        cls,
        ext_encryptors: Iterable[Encryptor] = (),
        fallback_encryptor: Optional[Encryptor] = None,
        encryptor_filter: Optional[Callable[[Encryptor], bool]] = None,
    ) -> Encryptor:
        for encryptor in ext_encryptors or []:
            if isinstance(encryptor, cls.REQUIRED_ENCRYPTOR_CLS):
                if not encryptor_filter or encryptor_filter(encryptor):
                    return encryptor
        else:
            if fallback_encryptor is None:
                raise KeyError(
                    "No matching Encryptor of type {.__name__!r}".format(
                        cls.REQUIRED_ENCRYPTOR_CLS
                    )
                )
            else:
                return fallback_encryptor

    def __init__(self, tag: Optional[int] = None) -> None:
        self.tag = self.TAG or tag

    def pack(
        self, session_key: bytes, ext_encryptors: Iterable[Encryptor] = ()
    ) -> bytes:
        raise NotImplementedError()

    @classmethod
    def unpack(
        cls, raw: bytes, ext_encryptors: Iterable[Encryptor] = ()
    ) -> tuple["AuthBlock", bytes]:
        raise NotImplementedError()


class InitCustKeyAuthBlock(AuthBlock):
    TAG = 0x01
    REQUIRED_ENCRYPTOR_CLS = CustKeyEncryptor

    CUSTOMER_KEY_PLACEHOLDER = bytes([0x00] * 10)

    def pack(
        self, session_key: bytes, ext_encryptors: Iterable[Encryptor] = ()
    ) -> bytes:
        auth_block = self.CUSTOMER_KEY_PLACEHOLDER + session_key
        return self.select_encryptor(ext_encryptors).encrypt(auth_block)

    @classmethod
    def unpack(
        cls, raw: bytes, ext_encryptors: Iterable[Encryptor] = ()
    ) -> tuple[AuthBlock, bytes]:
        auth_block = cls.select_encryptor(ext_encryptors).decrypt(raw)
        session_key = auth_block[-AES128.BLOCK_SIZE :]
        return InitCustKeyAuthBlock(), session_key

    def __repr__(self) -> str:
        return "InitAuthBlock()"


class InitEccAuthBlock(AuthBlock):
    TAG = 0x03
    REQUIRED_ENCRYPTOR_CLS = EccEncryptor

    def __init__(self, key_selector: int = 0) -> None:
        super().__init__()
        self.key_selector = key_selector

    def pack(
        self, session_key: bytes, ext_encryptors: Iterable[KeySelectorEncryptor] = ()
    ) -> bytes:
        encryptor = self.select_encryptor(
            ext_encryptors,
            fallback_encryptor=EccEncryptor(),
            encryptor_filter=lambda e: e.key_selector == self.key_selector,
        )
        return self.key_selector.to_bytes(1, "big") + encryptor.encrypt(session_key)

    @classmethod
    def unpack(
        cls, raw: bytes, ext_encryptors: Iterable[KeySelectorEncryptor] = ()
    ) -> tuple[AuthBlock, bytes]:
        key_selector = raw[0]
        encryptor = cls.select_encryptor(
            ext_encryptors, encryptor_filter=lambda e: e.key_selector == key_selector
        )
        session_key = encryptor.decrypt(raw[1:])
        return InitEccAuthBlock(key_selector), session_key

    def __repr__(self) -> str:
        return "InitEccAuthBlock({key_selector!r})".format(
            key_selector=self.key_selector
        )


class UpdateAuthBlock(AuthBlock):
    TAG = 0x02
    REQUIRED_ENCRYPTOR_CLS = ConfigSecurityCodeEncryptor

    def __init__(self, config_security_code: bytes, version: int = 0) -> None:
        super().__init__(self.TAG)
        self.version = version
        self.config_security_code = config_security_code

    def pack(
        self, session_key: bytes, ext_encryptors: Iterable[Encryptor] = ()
    ) -> bytes:
        default_encryptor = ConfigSecurityCodeEncryptor(self.config_security_code)
        encryptor = self.select_encryptor(ext_encryptors, default_encryptor)
        auth_block = session_key + self.version.to_bytes(1, "big")
        return encryptor.encrypt(auth_block)

    @classmethod
    def unpack(
        cls, raw: bytes, ext_encryptors: Iterable[Encryptor] = ()
    ) -> tuple[AuthBlock, bytes]:
        encryptor: ConfigSecurityCodeEncryptor = cls.select_encryptor(ext_encryptors)  # type: ignore
        auth_block = BytesReader(encryptor.decrypt(raw), cls.__name__)
        session_key = auth_block.read(AES128.BLOCK_SIZE)
        version = int.from_bytes(auth_block.read(1), "big")
        return (UpdateAuthBlock(encryptor.config_security_code, version), session_key)

    def __repr__(self) -> str:
        return "UpdateAuthBlock({config_security_code!r}, {version!r})".format(
            config_security_code=self.config_security_code, version=self.version
        )


class UnknownAuthBlock(AuthBlock):
    def __init__(self, tag: int, binary_value: bytes) -> None:
        super().__init__(tag)
        self.binary_value = binary_value

    def pack(
        self, session_key: bytes, ext_encryptors: Iterable[Encryptor] = ()
    ) -> bytes:
        return self.binary_value

    @classmethod
    def unpack(
        cls, raw: bytes, ext_encryptors: Iterable[Encryptor] = ()
    ) -> tuple[AuthBlock, bytes]:
        raise Bec2FileFormatError("Cannot unpack unknown auth block")

    def __repr__(self) -> str:
        return "UnknownAuthBlock({tag}, {binary_value!r})".format(
            tag=self.tag, binary_value=self.binary_value
        )


class Bec2File:
    AUTH_BLOCK_CLS_MAP: dict[int, Type[AuthBlock]] = {
        c.TAG: c for c in [InitCustKeyAuthBlock, InitEccAuthBlock, UpdateAuthBlock]
    }

    def __init__(
        self,
        bf3file: Bf3File,
        auth_blocks: Iterable[AuthBlock] = (),
        session_key: Optional[bytes] = None,
    ):
        self.bf3file = bf3file
        self.auth_blocks = {block.tag: block for block in auth_blocks}
        self.session_key = session_key or random_bytes(16)

    def add_auth_block(self, auth_block: AuthBlock) -> None:
        self.auth_blocks[auth_block.tag] = auth_block

    def to_binary(self, ext_encryptors: Iterable[Encryptor] = ()) -> bytes:
        header = BEC2_FILE_SIG + self.pack_auth_blocks(ext_encryptors)
        return header + self.bf3file.to_binary(len(header), self.session_key)

    def write_file(
        self, bf3file: str | TextIO, ext_encryptors: Iterable[Encryptor] = ()
    ) -> None:
        self.bf3file.write_bf3_format(
            bf3file, self.bf3file.comments, self.to_binary(ext_encryptors)
        )

    def pack_auth_blocks(self, ext_encryptors: Iterable[Encryptor] = ()) -> bytes:
        packed_auth_blocks = bytes()
        for auth_block in self.auth_blocks.values():
            auth_block_raw = auth_block.pack(self.session_key, ext_encryptors)
            packed_auth_blocks += auth_block.tag.to_bytes(1, "big")
            packed_auth_blocks += len(auth_block_raw).to_bytes(1, "big")
            packed_auth_blocks += auth_block_raw
        # TLV end block
        packed_auth_blocks += bytes([0x00, 0x00])
        return packed_auth_blocks

    @classmethod
    def read_file(
        cls,
        bf3file: str | TextIO,
        ext_encryptors: Iterable[Encryptor] = (),
        check_cmac: bool = True,
    ) -> "Bec2File":
        raw_rdr, comments = Bf3File.parse_bf3_file(bf3file)
        signature = raw_rdr.read(len(BEC2_FILE_SIG))
        if signature != BEC2_FILE_SIG:
            raise Bec2FileFormatError("Signature of BEC2 file invalid")
        auth_blocks, session_key = cls.unpack_auth_blocks(raw_rdr, ext_encryptors)
        if session_key is None:
            raise Bec2FileFormatError(
                "Cannot read bec2 (no decryptable AuthBlock found)"
            )
        return Bec2File(
            Bf3File.from_binary(raw_rdr, comments, check_cmac, session_key),
            auth_blocks,
            session_key,
        )

    @classmethod
    def unpack_auth_blocks(
        cls, raw_rdr: BytesIO, ext_encryptors: Iterable[Encryptor]
    ) -> tuple[Iterable[AuthBlock], Optional[bytes]]:
        common_session_key = None
        auth_blocks: list[AuthBlock] = []
        while True:
            tlv_tag = int.from_bytes(raw_rdr.read(1), "big")
            tlv_len = int.from_bytes(raw_rdr.read(1), "big")
            tlv_value = raw_rdr.read(tlv_len)
            if tlv_tag == 0 and tlv_len == 0:
                break
            try:
                auth_block_cls = cls.AUTH_BLOCK_CLS_MAP[tlv_tag]
                auth_block, session_key = auth_block_cls.unpack(
                    tlv_value, ext_encryptors
                )
            except KeyError:
                auth_blocks.append(UnknownAuthBlock(tlv_tag, tlv_value))
            else:
                auth_blocks.append(auth_block)
                if session_key is not None:
                    if (
                        common_session_key is not None
                        and session_key != common_session_key
                    ):
                        raise Bec2FileFormatError(
                            "not all authblocks contain the same sessionkey"
                        )
                    common_session_key = session_key
        return auth_blocks, common_session_key

    def __repr__(self) -> str:
        return "Bec2File({bf3file!r}, {auth_blocks!r}, " "{session_key!r})".format(
            bf3file=self.bf3file,
            auth_blocks=self.auth_blocks,
            session_key=self.session_key,
        )

    def derive_auth_blocks_from_config(
        self, config: dict, cust_key_support: bool = False
    ) -> None:
        if cust_key_support:
            self.add_auth_block(InitCustKeyAuthBlock())
        else:
            self.add_auth_block(InitEccAuthBlock())

        try:
            config_id = ConfigId.create_from_prj_settings(config)
        except MissingProjectSettingsNameError:
            try:
                config_id = ConfigId.create_from_dev_settings(config)
            except MissingDeviceSettingsNameError:
                config_id = None
        config_security_code = config.get((0x0202, 0x82))
        if config_security_code is not None and config_id is not None:
            self.add_auth_block(
                UpdateAuthBlock(config_security_code, config_id.version or 0)
            )
