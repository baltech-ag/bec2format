from io import StringIO

import register_crypto_plugin

from bec2format import (
    CONFIG_SECURITY_CODE_SIZE,
    Bec2File,
    Bf3Component,
    Bf3File,
    ConfigSecurityCodeEncryptor,
    Encryptor,
    SoftwareCustKeyEncryptor,
)

soft_encryptor = SoftwareCustKeyEncryptor(crypto_key=bytes([0x12, 0x34] * 8))

testdata = b"Das ist ein Testtext"
encrypted_data = soft_encryptor.encrypt(testdata)
decrypted = soft_encryptor.decrypt(encrypted_data)
assert decrypted == testdata

encryptors: list[Encryptor] = [soft_encryptor]

config_security_code = bytes([0x45] * CONFIG_SECURITY_CODE_SIZE)
config = {
    (0x1111, 0x22): bytes([0x33, 0x33, 0x33]),
    (0x1111, 0x77): bytes([0x55, 0x66, 0x77, 0x88]),
    (0x0202, 0x82): config_security_code,
    (0x0620, 0x01): (10234).to_bytes(4, byteorder="big"),
    (0x0620, 0x05): (5678).to_bytes(2, byteorder="big"),
    (0x0620, 0x02): (6789).to_bytes(2, byteorder="big"),
    (0x0620, 0x07): (9).to_bytes(1, byteorder="big"),
    (0x0620, 0x06): b"Testname",
}

bec2 = Bec2File(
    Bf3File(
        comments={
            "FirmwareId": "1053",
            "FirmwareVersion": "1.02.03",
            "LegicFwVersion": "123.43",
        },
        components=[
            Bf3Component(
                {0xC1: bytes([0x11, 0x22, 0x33]), 0xC3: bytes([0x12, 0x33])},
                bytes(list(range(0x100))),
            )
        ],
    ),
    session_key=bytes(
        [
            0x44,
            0x55,
            0x16,
            0xFF,
            0x12,
            0x6F,
            0x57,
            0x02,
            0xD7,
            0x03,
            0x44,
            0xA0,
            0x94,
            0x33,
            0x44,
            0x55,
        ]
    ),
)

bec2.derive_auth_blocks_from_config(config, cust_key_support=True)
bec2.bf3file.derive_comments_from_config(config)
bec2.bf3file.set_config(config)

# Write to stream
bec2_file_obj = StringIO()
bec2.write_file(bec2_file_obj, encryptors)

# Read from stream
bec2_file_obj.seek(0)
print(
    Bec2File.read_file(
        bec2_file_obj, encryptors + [ConfigSecurityCodeEncryptor(config_security_code)]
    )
)
