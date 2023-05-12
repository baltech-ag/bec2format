from baltech.tools.common import crc8404B
from .bf3file import Bf3File, Bf3Component, BufReader
from bal27.core import buf
from bal27.crypto.cbc import CBC
from bal27.crypto.aes import AES128
from bal27.crypto.ecc import PublicEccKey, PrivateEccKey
from bal27.formats.base import FormatError
from .configid import ConfigId
from hashlib import sha256
from functools import reduce


CONFIG_SECURITY_CODE_SIZE = 8
CUSTOMER_KEY_SIZE = 10
BEC2_FILE_SIG = "BEC2\0"


class Encryptor(object):
    """
    Base Class for all kinds of encryptors.

    An encryptor contains the encryption algorithm AND format for AuthBlocks.
    It is externalized into an extra class to support hardware crypto units
    without requiring the AuthBlock (und thus Bec2File) objects to get
    dependencies to I/O objects.

    The class hierarchy for encryptors is:

    - Encryptor (abstract)
      - CustKeyEncryptor (abstract)
        - HardwareCustKeyEncryptor
        - SoftwareCustKeyEncryptor (only for testing purposes)
      - EccEncryptor
        - EccDecryptor (only for testing purposes)
      - ConfigSecurityCodeEncryptor
    """

    def encrypt(self, plaintext):
        raise NotImplementedError()

    def decrypt(self, ciphertext):
        raise NotImplementedError()

    def __repr__(self):
        return '{0.__class__.__name__}(...)'.format(self)


class AesEncryptorMixin(Encryptor):
    """
    AES Encryption Logic that simulates the crypto container format
    provided by the BRP command Crypto.EncryptBuffer.

    (https://docs.baltech.de/refman/cmds/crypto/encryptbuffer.html)
    """

    def __init__(self, crypto_key):
        self.cipher = CBC(AES128(crypto_key))

    def encrypt(self, plaintext):
        self.cipher.iv = buf("00" * AES128.BLOCK_SIZE)
        header_len = 2          # header = 'B' + lenbyte
        min_padding_len = 1     # enforce minimal number of padding bytes
        crc = buf.int16(crc8404B(plaintext))
        padding_len = (
                -(header_len + min_padding_len + len(plaintext) + len(crc))
                % AES128.BLOCK_SIZE
            ) + min_padding_len
        return self.cipher.encrypt(
            buf.raw('B') +                          # header
            buf.int8(len(plaintext) + len(crc)) +   # header
            buf("00" * padding_len) +
            plaintext +
            crc
        )

    def decrypt(self, ciphertext):
        self.cipher.iv = buf("00" * AES128.BLOCK_SIZE)
        frame_rdr = BufReader(self.cipher.decrypt(ciphertext), 'Decrypted Frame')
        if frame_rdr.read(1) != buf.raw('B'):
            raise FormatError('Authblock has to start with "B"')
        payload_plus_crc_len = frame_rdr.readInt(8)
        frame_rdr.pos = len(ciphertext) - payload_plus_crc_len  # skip padding
        payload = frame_rdr.read(payload_plus_crc_len - 2)
        crc = frame_rdr.readInt(16)
        if crc8404B(payload) != crc:
            raise FormatError('Invalid CRC')
        return payload


class CustKeyEncryptor(Encryptor):
    """
    Baseclass for all CustKeyEncryptors.

    The main feature of CustKeyEncryptors is, that they insert the custom key
    into the given plain data before encrypting it.
    """


class SoftwareCustKeyEncryptor(AesEncryptorMixin, CustKeyEncryptor):
    """
    Softwareimplementation of CustomKey encryptor.

    This encryptor is mainly for testing as it requires knowledge of the
    CustomKey.
    """

    def __init__(self, crypto_key, customer_key=None, customer_key_pos=0):
        super(SoftwareCustKeyEncryptor, self).__init__(crypto_key)
        self.crypto_key = crypto_key
        self.customer_key = customer_key
        self.customer_key_pos = customer_key_pos

    def encrypt(self, plaintext):
        if self.customer_key:
            plaintext[self.customer_key_pos:self.customer_key_pos + CUSTOMER_KEY_SIZE] = \
                self.customer_key
        return super(SoftwareCustKeyEncryptor, self).encrypt(plaintext)

    def decrypt(self, ciphertext):
        plaintext = super(SoftwareCustKeyEncryptor, self).decrypt(ciphertext)
        if self.customer_key:
            ck_pos = self.customer_key_pos
            if plaintext[ck_pos:ck_pos + CUSTOMER_KEY_SIZE] != self.customer_key:
                raise FormatError("CustomerKey does not match")
            plaintext[ck_pos:ck_pos+CUSTOMER_KEY_SIZE] = buf("00"*CUSTOMER_KEY_SIZE)
        return plaintext


class HardwareCustKeyEncryptor(CustKeyEncryptor):
    """
    Standardimplementation for CustomKey encryptor

    It forwards the actual encryption to a baltech reader that contains
    the customkey
    """

    # this value specifiys the key slot where to store the customkey.
    # It is passed to Crypto.CopyConfigKey and is the highest possible value
    # to avoid interference with application
    KEY_NDX = 0x3F

    def __init__(self, dev, has_customer_key=True, customer_key_pos=0,
                 prepared=False):
        self.dev = dev
        self.has_customer_key = has_customer_key
        self.customer_key_pos = customer_key_pos
        self.prepared = prepared

    def encrypt(self, plaintext):
        if self.has_customer_key and not self.prepared:
            self.dev.Crypto.CopyConfigKey(self.KEY_NDX)
            self.prepared = True
        enc_payload, iv = self.dev.Crypto.BalKeyEncryptBuffer(
            KeyVersion=3,  # AES
            EmbeddedKeyIndex=self.KEY_NDX if self.has_customer_key else 0,
            EmbeddedKeyPos=self.customer_key_pos,
            Buffer=plaintext + buf.int16(crc8404B(plaintext)),
            InitialVector=buf("00" * AES128.BLOCK_SIZE))
        return enc_payload


class EccEncryptor(Encryptor):
    """
    Standard encryptor for ECC

    is it contains only the public key it can be used only for encryption
    """

    KEYSEL_FW_STD = 0
    KEYSEL_KEYSTORE_STD = 1
    KEYSEL_KEYSTORE_ALT0 = 2
    KEYSEL_KEYSTORE_ALT1 = 3

    DEFAULT_KEYS = {
        KEYSEL_FW_STD: PublicEccKey.createFromRawBinFmt(bytes(buf(
            "05 7B 56 5D 97 6A 33 06 E8 BD 09 4A 46 71 13 81 "
            "98 70 7D 0B B6 7C 88 A4 5E 8F 37 5D CB 14 16 C9 "
            "51 98 84 E2 10 9A 02 79 20 72 AF 23 79 11 A6 12 "
            "EB 16 21 38 36 E9 0F DD 42 1B 47 9E BD 98 15 8E "))),
        KEYSEL_KEYSTORE_STD: PublicEccKey.createFromRawBinFmt(bytes(buf(
            "D7 B1 B5 CB D0 58 7A E2 2E 91 AE E2 29 B9 53 4A " 
            "92 0C 90 5F 58 51 3C B4 39 1F 8C 3F 5A 1B 46 4C " 
            "CC 05 91 7E 5C 59 C3 AE 3E 11 97 99 2B 2F BB 24 "
            "F3 42 38 D1 E4 BB C6 2D C0 DB C8 F3 69 03 E9 2B "))),
        KEYSEL_KEYSTORE_ALT0: PublicEccKey.createFromRawBinFmt(bytes(buf(
            "0C D7 31 ED 37 30 E5 3F 72 44 EE 71 D8 D5 4F 53 "
            "00 88 5F F6 45 EC 8F D2 7F A3 D9 D1 C4 62 9F AF "
            "65 36 A1 F5 B4 6F 0C 7C A9 23 EE 28 4C 11 5B 9D "
            "65 14 ED EF 9A A1 FD BF 1F 54 03 0B 49 AE F8 A6 "))),
        KEYSEL_KEYSTORE_ALT1: PublicEccKey.createFromRawBinFmt(bytes(buf(
            "B6 BC 3D 31 84 17 AE 90 99 A2 28 C2 9A 0D E8 5A "
            "C0 53 EA B5 B3 AA 50 8B F4 A4 38 BF 15 FF 8B 55 "
            "1A 04 00 40 51 80 1A 3D 08 A6 05 57 15 C9 DF F3 "
            "8F D2 EF AA 31 1C 81 54 BD 9A 30 25 97 C8 60 53 "))),
    }

    def __init__(self, key_selector=KEYSEL_FW_STD, public_key=None):
        super(EccEncryptor, self).__init__()
        self.key_selector = key_selector
        self.public_key = public_key or self.DEFAULT_KEYS[key_selector]

    def encrypt(self, plaintext):
        temp_privatekey = PrivateEccKey.generate()
        ecdh_secret = temp_privatekey.computeDhSecret(self.public_key)
        ecdh_sha_secret = sha256(ecdh_secret).digest()
        temp_aes_key = AES128(buf.raw(ecdh_sha_secret[:AES128.KEY_SIZE]))
        return (
            buf("04") + buf.raw(temp_privatekey.publicKey.toRawBinFmt()) +
            temp_aes_key.encryptBlock(plaintext) )


class EccDecryptor(EccEncryptor):
    """
    Decryptor AND Encryptor for ECC

    It has to be constructed with a private key. As the actual private keys are
    secret it only for testing purposes.
    """


    def __init__(self, key_selector, private_key):
        super(EccDecryptor, self).__init__(key_selector, private_key.publicKey)
        self.private_key = private_key

    def decrypt(self, ciphertext):
        auth_block = BufReader(ciphertext, self.__class__.__name__)
        if auth_block.readInt(8) != 0x04:
            raise ValueError("Invalid encrypted ECC Block format")
        temp_publickey_bytes = bytes(auth_block.read(64))
        temp_publickey = PublicEccKey.createFromRawBinFmt(temp_publickey_bytes)
        encrypted_session_key = auth_block.read(AES128.BLOCK_SIZE)

        ecdh_secret = self.private_key.computeDhSecret(temp_publickey)
        ecdh_sha_secret = sha256(ecdh_secret).digest()
        temp_aes_key = AES128(buf.raw(ecdh_sha_secret[:AES128.KEY_SIZE]))
        return temp_aes_key.decryptBlock(encrypted_session_key)


class ConfigSecurityCodeEncryptor(AesEncryptorMixin, Encryptor):
    """
    Encrypt authblock with the ConfigSecurityCode

    As the ConfigSecurityCode is no AES key (too short) it requiers
    preprocessing which is the job of this class. The actual encryption is
    based on the standard AES crypto format (see AesEncryptionMixin).
    """

    def __init__(self, config_security_code):
        csc_digest = sha256(config_security_code).digest()
        trimmed_csc_digest = csc_digest[:AES128.BLOCK_SIZE]
        crypto_key = buf.raw(trimmed_csc_digest)
        super(ConfigSecurityCodeEncryptor, self).__init__(crypto_key)
        self.config_security_code = config_security_code


class AuthBlock(object):

    TAG = None
    REQUIRED_ENCRYPTOR_CLS = None

    @classmethod
    def select_encryptor(cls, ext_encryptors=None, fallback_encryptor=None,
                         encryptor_filter=None):
        for encryptor in (ext_encryptors or []):
            if isinstance(encryptor, cls.REQUIRED_ENCRYPTOR_CLS):
                if not encryptor_filter or encryptor_filter(encryptor):
                    return encryptor
        else:
            if fallback_encryptor is None:
                raise KeyError("No matching Encryptor of type {.__name__!r}"
                               .format(cls.REQUIRED_ENCRYPTOR_CLS))
            else:
                return fallback_encryptor

    def __init__(self, tag=None):
        self.tag = self.TAG or tag

    def pack(self, session_key, ext_encryptors=None):
        raise NotImplementedError()

    @classmethod
    def unpack(cls, raw_buf, ext_encryptors=None):
        raise NotImplementedError()


class InitCustKeyAuthBlock(AuthBlock):

    TAG = 0x01
    REQUIRED_ENCRYPTOR_CLS = CustKeyEncryptor

    CUSTOMER_KEY_PLACEHOLDER = buf("00" * 10)

    def pack(self, session_key, ext_encryptors=None):
        auth_block = self.CUSTOMER_KEY_PLACEHOLDER + session_key
        return self.select_encryptor(ext_encryptors).encrypt(auth_block)

    @classmethod
    def unpack(cls, raw_buf, ext_encryptors=None):
        auth_block = cls.select_encryptor(ext_encryptors).decrypt(raw_buf)
        session_key = auth_block[-AES128.BLOCK_SIZE:]
        return InitCustKeyAuthBlock(), session_key

    def __repr__(self):
        return 'InitAuthBlock()'



class InitEccAuthBlock(AuthBlock):

    TAG = 0x03
    REQUIRED_ENCRYPTOR_CLS = EccEncryptor

    def __init__(self, key_selector=0):
        super(InitEccAuthBlock, self).__init__()
        self.key_selector = key_selector

    def pack(self, session_key, ext_encryptors=None):
        encryptor = self.select_encryptor(
            ext_encryptors,
            fallback_encryptor=EccEncryptor(),
            filter=lambda e: e.key_selector==self.key_selector)
        return buf([self.key_selector]) + encryptor.encrypt(session_key)

    @classmethod
    def unpack(cls, raw_buf, ext_encryptors=None):
        key_selector = raw_buf[0]
        encryptor = cls.select_encryptor(
            ext_encryptors,
            filter=lambda e: e.key_selector==key_selector)
        session_key = encryptor.decrypt(raw_buf[1:])
        return InitEccAuthBlock(key_selector), session_key

    def __repr__(self):
        return 'InitEccAuthBlock({0.key_selector!r})'\
            .format(self)


class UpdateAuthBlock(AuthBlock):

    TAG = 0x02
    REQUIRED_ENCRYPTOR_CLS = ConfigSecurityCodeEncryptor

    def __init__(self, config_security_code, version=0):
        super(UpdateAuthBlock, self).__init__(self.TAG)
        self.version = version
        self.config_security_code = config_security_code

    def pack(self, session_key, ext_encryptors=None):
        default_encryptor = ConfigSecurityCodeEncryptor(
            self.config_security_code)
        encryptor = self.select_encryptor(ext_encryptors, default_encryptor)
        auth_block = session_key + buf.int8(self.version)
        return encryptor.encrypt(auth_block)

    @classmethod
    def unpack(cls, raw_buf, ext_encryptors=None):
        encryptor = cls.select_encryptor(ext_encryptors)
        auth_block = BufReader(encryptor.decrypt(raw_buf), cls.__name__)
        session_key = auth_block.read(AES128.BLOCK_SIZE)
        version = auth_block.readInt(8)
        return (UpdateAuthBlock(encryptor.config_security_code, version),
                session_key)

    def __repr__(self):
        return 'UpdateAuthBlock({0.config_security_code!r}, {0.version!r})'.format(self)


class UnknownAuthBlock(AuthBlock):

    def __init__(self, tag, binary_value):
        super(UnknownAuthBlock, self).__init__(tag)
        self.binary_value = binary_value

    def pack(self, session_key, ext_encryptors=None):
        return self.binary_value

    @classmethod
    def unpack(cls, raw_buf, ext_encryptors=None):
        raise FormatError("Cannot unpack unknown auth block")

    def __repr__(self):
        return 'UnknownAuthBlock({0.tag}, {0.binary_value!r})'.format(self)


class Bec2File(object):

    AUTH_BLOCK_CLS_MAP = {c.TAG: c for c in [
        InitCustKeyAuthBlock,
        InitEccAuthBlock,
        UpdateAuthBlock,
    ]}

    def __init__(self, bf3file, auth_blocks=(), session_key=None):
        self.bf3file = bf3file
        self.auth_blocks = {block.tag: block for block in auth_blocks}
        self.session_key = session_key or buf.random(16)

    def add_auth_block(self, auth_block):
        self.auth_blocks[auth_block.tag] = auth_block

    def to_binary(self, ext_encryptors=None):
        header = buf.raw(BEC2_FILE_SIG) + \
                 self.pack_auth_blocks(ext_encryptors)
        return header + self.bf3file.to_binary(len(header), self.session_key)

    def write_file(self, bf3file, ext_encryptors=None):
        self.bf3file.write_bf3_format(
            bf3file,
            self.bf3file.comments,
            self.to_binary(ext_encryptors),
        )

    def pack_auth_blocks(self, ext_encryptors=None):
        packed_auth_blocks = []
        for auth_block in list(self.auth_blocks.values()):
            auth_block_raw = auth_block.pack(self.session_key, ext_encryptors)
            packed_auth_blocks += [
                buf().writeInt8(auth_block.tag),
                buf().writeInt8(len(auth_block_raw)),
                auth_block_raw,
            ]
        # TLV end block
        packed_auth_blocks += [
            buf().writeInt8(0),
            buf().writeInt8(0),
        ]
        return reduce(buf.__add__, packed_auth_blocks)

    @classmethod
    def read_file(cls, bf3file, ext_encryptors=None, check_cmac=True):
        raw_rdr, comments = Bf3File.parse_bf3_file(bf3file)
        signature = raw_rdr.read(len(BEC2_FILE_SIG))
        if signature != buf.raw(BEC2_FILE_SIG):
            raise FormatError('Signature of BEC2 file invalid')
        auth_blocks, session_key = cls.unpack_auth_blocks(raw_rdr, ext_encryptors)
        if session_key is None:
            raise FormatError(
                "Cannot read bec2 (no decryptable AuthBlock found)")
        return Bec2File(
            Bf3File.from_binary(raw_rdr, comments, check_cmac, session_key),
            auth_blocks,
            session_key)

    @classmethod
    def unpack_auth_blocks(cls, raw_rdr, ext_encryptors):
        common_session_key = None
        auth_blocks = []
        while True:
            tlv_tag = raw_rdr.readInt(8)
            tlv_len = raw_rdr.readInt(8)
            tlv_value = raw_rdr.read(tlv_len)
            if tlv_tag == 0 and tlv_len == 0:
                break
            try:
                auth_block_cls = cls.AUTH_BLOCK_CLS_MAP[tlv_tag]
                auth_block, session_key = auth_block_cls.unpack(tlv_value,
                                                                ext_encryptors)
            except KeyError:
                auth_blocks.append(UnknownAuthBlock(tlv_tag, tlv_value))
            else:
                auth_blocks.append(auth_block)
                if session_key is not None:
                    if common_session_key is not None \
                            and session_key != common_session_key:
                        raise FormatError(
                            "not all authblocks contain the same sessionkey")
                    common_session_key = session_key
        return auth_blocks, common_session_key

    def __repr__(self):
        return 'Bec2File({0.bf3file!r}, {0.auth_blocks!r}, ' \
               '{0.session_key!r})'.format(self)

    def derive_auth_blocks_from_config(self, config, custKeySupport=True):
        if custKeySupport:
            self.add_auth_block(InitCustKeyAuthBlock())
        else:
            self.add_auth_block(InitEccAuthBlock())

        try:
            config_id = ConfigId.create_from_prj_settings(config)
        except ValueError:
            try:
                config_id = ConfigId.create_from_dev_settings(config)
            except ValueError:
                config_id = None
        config_security_code = config.get((0x0202, 0x82))
        if config_security_code is not None and config_id is not None:
            self.add_auth_block(
                UpdateAuthBlock(config_security_code, config_id.version))
