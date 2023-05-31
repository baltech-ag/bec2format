import sys

if sys.implementation.name == "micropython":
    import bec2format.micropython_compatibility_quirks


from .bec2file import (
    CONFIG_SECURITY_CODE_SIZE,
    Bec2File,
    ConfigSecurityCodeEncryptor,
    CustKeyEncryptor,
    EccDecryptor,
    EccEncryptor,
    Encryptor,
    SoftwareCustKeyEncryptor,
)
from .bf3file import BF3FMT, Bf2BinLine, Bf3Component, Bf3File, cmac
from .configid import ConfigId
from .crypto import (
    AES128,
    PrivateEccKey,
    PublicEccKey,
    create_AES128,
    create_public_ecc_key_from_der_fmt,
    generate_private_ecc_key,
    random_bytes,
    register_AES128,
    register_PrivateEccKey,
    register_PublicEccKey,
    register_random_bytes,
)
from .error import (
    Bec2FileFormatError,
    Bf3FileFormatError,
    ConfigIdFormatError,
    FormatError,
    UnsupportedLegacyFirmwareError,
)
