from bec2format.bf3file import BF3FMT, Bf2BinLine, Bf3File

BF2_LINE_SIZE = 128
TAGTYPE = 0x84


def create_bf2line(tagtype: int, offs: int, payload: bytes) -> Bf2BinLine:
    """Creates a BF2 line as it is emitted by Bf2File.addIntelHex()."""
    fwtag = bytes([len(payload) + 2]) + offs.to_bytes(2, "big") + payload
    return Bf2BinLine(tagtype, 0, fwtag, b"")


def create_bf2lines(start_adr: int, data: bytes) -> list:
    """Splits a memory area into BF2 lines of 128 bytes each.

    ``start_adr`` is the address relative to the first BF2 line of the whole
    component, as the 64K bank is encoded in the tagtype.
    """
    return [
        create_bf2line(
            TAGTYPE + (start_adr + offs) // 0x10000,
            (start_adr + offs) % 0x10000,
            data[offs : offs + BF2_LINE_SIZE],
        )
        for offs in range(0, len(data), BF2_LINE_SIZE)
    ]


def create_memimage_area(start_adr: int, data: bytes) -> bytes:
    return start_adr.to_bytes(4, "big") + len(data).to_bytes(4, "big") + data


def test_unpack_payload_of_contiguous_area_returns_a_single_block() -> None:
    data = bytes(range(0x100))

    blocks = Bf3File.bf2_unpack_payload(create_bf2lines(0x4000, data))

    assert blocks == {0x4000: data}


def test_unpack_payload_keeps_the_first_line_after_a_gap() -> None:
    """Regression test: the line that triggered the gap must not be dropped.

    bf2_unpack_payload() used to flush the current block on a gap without
    appending the payload of the triggering line, which silently corrupted
    every memory area but the first one.
    """
    area1 = bytes(range(0x100))
    area2 = bytes(ndx % 0x100 for ndx in range(0x180))

    blocks = Bf3File.bf2_unpack_payload(
        create_bf2lines(0x4000, area1) + create_bf2lines(0x10000, area2)
    )

    assert blocks == {0x4000: area1, 0x10000: area2}


def test_unpack_payload_of_three_areas() -> None:
    areas = {
        0x0000: bytes([0xA5] * 0x80),
        0x8000: bytes([0x5A] * 0x100),
        0x20000: bytes([0x11] * 0x180),
    }
    bf2lines: list = []
    for start_adr, data in sorted(areas.items()):
        bf2lines += create_bf2lines(start_adr, data)

    assert Bf3File.bf2_unpack_payload(bf2lines) == areas


def test_convert_payload_to_memoryimage_covers_all_areas() -> None:
    area1 = bytes(range(0x100))
    area2 = bytes(ndx % 0x100 for ndx in range(0x180))
    bf2lines = create_bf2lines(0x4000, area1) + create_bf2lines(0x10000, area2)

    memimage = Bf3File.bf2_convert_payload(bf2lines, BF3FMT.MEMORYIMAGE)

    assert memimage == create_memimage_area(0x4000, area1) + create_memimage_area(
        0x10000, area2
    )
