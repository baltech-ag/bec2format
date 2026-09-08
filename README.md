# [BALTECH AG](https://www.baltech.de/?lang=en) - BEC2 file format

* Authors: Baltech AG <info@baltech.de>
* License: [MIT](LICENSE.md)

## Add the dependency to your project

#### CPython

* Compatible with [CPython](https://www.python.org/) >= 3.10

```bash
pip install git+https://github.com/baltech-ag/bec2format.git#v1.04.00
# or
poetry add git+https://github.com/baltech-ag/bec2format.git#v1.04.00
```

#### Micropython

* Compatible with [Micropython](https://micropython.org/) >= 1.20.0
* Tested with the [Unix port](https://github.com/micropython/micropython/tree/v1.20.0/ports/unix) on Ubuntu 20.04

```python
import mip
mip.install("github:baltech-ag/bec2format/package.json", version="v1.04.00")
```

## How to use

```python
from bec2format.bf3file import Bf3Component, Bf3File

Bf3File(
    {"FirmwareId": "1100", "FirmwareVersion": "2.05.01"},
    [
        Bf3Component(
            {
                0xC1: bytes([0x11, 0x22, 0x33]), 
                0xC3: bytes([0x12, 0x33]),
            },
            bytes(list(range(0x100))),
        ),
    ],
)
```

## Command line interface

The `bec2format` console script is available with the CPython installation
(it is not part of the micropython package).

### `bec2format pack-bf3`

Creates a BF3 file from a JSON manifest that is read from **stdin**:

```bash
bec2format pack-bf3 < manifest.json
```

> **The manifest contains key material.** Pass it through stdin - never write
> it to a file and never put it on the command line, where it would show up in
> the process list. `pack-bf3` therefore takes no arguments at all, never logs
> the manifest and never prints a traceback. Errors are reported as
> `ERROR: <message>` on stderr with a non-zero exit code.

Components that need AES (`"encryption": "FWKEY"` or `"SESSIONKEY"`) require an
AES implementation, so install the package with the `aes` extra:

```bash
uvx --from "bec2format[aes] @ git+https://github.com/baltech-ag/bec2format.git@v1.04.00" \
    bec2format pack-bf3 < manifest.json
```

#### Manifest format

```json
{
  "dest": "1100_id_engine_z_firmware.bf3",
  "fw_key": "401D6C7E98A9B469A6F598DB8E69862B",
  "comments": {"CustomerId": "4711"},
  "components": [
    {"tagtype": 132,
     "format": "MEMIMAGE",
     "encryption": "FWKEY",
     "payload": "intermediate/bf3_cmp00.bin",
     "instrs": {"Firmware": "1100 IDE Z     2.05.01",
                "Creator": "make2",
                "Bf3Update": "Supported",
                "CRC": "0x1234ABCD",
                "SELECT": {"FILTER": "010100B6"},
                "SELECT_IF": {"PROTOCOL": "*"},
                "CHECK_FWVER": {"VERSIONDESC": "*"},
                "REBOOT": {}}}
  ]
}
```

| Key | | Description |
|---|---|---|
| `dest` | required | Path of the BF3 file to create. |
| `fw_key` | optional | The 16 byte firmware key as a hex string. Required if at least one component uses `"encryption": "FWKEY"`. |
| `comments` | optional | Comments that are written to the header of the BF3 file. `FirmwareId`, `FirmwareVersion`, `Creator`, `Bf3Update` and the `Component<N>` annotations are derived from the components and do not have to be listed here. |
| `components` | required | The components of the BF3 file, in the order in which they would appear in a BF2 stream. |

Every entry of `components` describes one component:

| Key | | Description |
|---|---|---|
| `tagtype` | required | The BF2 tag type of the component (`0x84` main firmware, `0x70`/`0x83` loader, `0x35`/`0x39`/`0x3D`/`0x40` peripheral firmware). The tag types `0x34` and `0x48` are control tags and are skipped. |
| `format` | required | `MEMIMAGE`, `BF2COMPATIBLE`, `BLOB` or `TLVCFG`. Peripheral firmware (`0x35`/`0x39`/`0x3D`/`0x40`) has to use `BLOB`. |
| `encryption` | optional | `PLAIN` (default), `FWKEY` (AES-128-CBC with `fw_key`, an all zero IV and zero padding) or `SESSIONKEY`. |
| `payload` | required | Path of the file that contains the payload of the component. |
| `instrs` | optional | The BF2 instructions of the component, see below. |

`instrs` accumulates over the components in exactly the same way as while
parsing a BF2 stream: every entry stays in effect until a later component
overrides it. `REBOOT`, `CRC` and `CHECK_FWVER` apply to a single component
only, `SELECT`, `SELECT_IF`, `Firmware`, `Creator` and `Bf3Update` apply to all
following ones as well.

## Run appnotes

#### CPython

```bash
git clone https://github.com/baltech-ag/bec2format.git
cd bec2format
cd appnotes
py create_bec2file_with_ec_key.py
```

#### Micropython

```bash
git clone https://github.com/baltech-ag/bec2format.git
cd bec2format
cd appnotes
micropython install_depepencies.py
micropython create_bec2file_with_ec_key.py
```
