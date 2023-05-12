from io import StringIO
from bec2format.bf3file import Bf3File, Bf3Component

import register_crypto_plugin


bf3_file = Bf3File({"FirmwareId": '1053',
                    "FirmwareVersion": "1.02.03",
                    "LegicFwVersion": "123.43"},
                   [Bf3Component({0xC1: bytes([0x11, 0x22, 0x33]),
                                  0xC3: bytes([0x12, 0x33])},
                                 bytes(list(range(0x100)))),
                    Bf3Component({0xC4: bytes([0x11])},
                                 bytes([0x23, 0x44, 0x53, 0x56, 0x46, 0x53,
                                        0x47, 0x56, 0x75, 0x67, 0x42, 0x52,
                                        0x34, 0x52, 0x03]))])

# Write to stream
bf3_file_obj = StringIO()
bf3_file.write_file(bf3_file_obj)
print(bf3_file_obj.getvalue())

# Read from stream
bf3_file_obj.seek(0)
print(Bf3File.read_file(bf3_file_obj))
