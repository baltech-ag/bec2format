# [BALTECH AG](https://www.baltech.de/?lang=en) - BEC2 file format

* Authors: Baltech AG <info@baltech.de>

## Add the dependency to your project

#### CPython

* Compatible with [CPython](https://www.python.org/) >= 3.10

```bash
pip install git+https://github.com/baltech-ag/bec2format.git#0.01.00
# or
poetry add git+https://github.com/baltech-ag/bec2format.git#0.01.00
```

#### Micropython

* Compatible with [Micropython](https://micropython.org/) >= 1.20.0
* Tested with the [Unix port](https://github.com/micropython/micropython/tree/v1.20.0/ports/unix) on Ubuntu 20.04

```python
import mip
mip.install("github:baltech-ag/bec2format/package.json", version="v0.01.00")
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
