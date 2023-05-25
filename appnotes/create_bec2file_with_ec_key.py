from io import StringIO

import register_crypto_plugin

from bec2format import CONFIG_SECURITY_CODE_SIZE, Bec2File, Bf3File, EccEncryptor

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

bec2 = Bec2File(Bf3File())
bec2.derive_auth_blocks_from_config(config)
bec2.bf3file.derive_comments_from_config(config)
bec2.bf3file.set_config(config)

# Write to stream
bec2_file_obj = StringIO()
bec2.write_file(bec2_file_obj, [EccEncryptor()])
