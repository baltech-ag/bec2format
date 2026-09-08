import io

from bec2format.bf3file import BF3TAG, BF3TYPE, Bf3File

# exec_bf2instrs() reads the firmware id from [:4] and the version from
# [15:22] of the firmware string
FIRMWARE_STRING = "1100 IDE Z".ljust(15) + "2.05.01"
MAIN_TAGTYPE = 0x84
SM4200_PREPARE_TAGTYPE = 0x34


def create_bf2_line(tagtype: int, offs: int = 0, payload: bytes = b"") -> str:
    """Creates a BF2 line as it is emitted by Bf2File.addIntelHex()."""
    fwtag = bytes([len(payload) + 2]) + offs.to_bytes(2, "big") + payload
    rawdata = b"\x00\x00" + bytes([tagtype, len(fwtag)]) + fwtag
    return ":" + rawdata.hex().upper()


END_OF_TAG_LINE = ":0000FF00"


def create_bf2_file(*fw_lines: str) -> io.StringIO:
    return io.StringIO(
        "\n".join(
            [
                "##Firmware: " + FIRMWARE_STRING,
                "##Creator: make2",
                "##Bf3Update: Supported",
                *fw_lines,
            ]
        )
        + "\n"
    )


def test_bf2_import_reads_a_main_firmware_tag() -> None:
    bf2_file = create_bf2_file(
        create_bf2_line(MAIN_TAGTYPE, 0, bytes(range(0x10))), END_OF_TAG_LINE
    )

    bf3_file = Bf3File.bf2_import(bf2_file)

    assert [comp.description[BF3TAG.TYPE] for comp in bf3_file.components] == [
        bytes([BF3TYPE.MAIN])
    ]


def test_bf2_import_silently_skips_bf2_control_tags() -> None:
    """Legacy .bf2 files legitimately contain control tags.

    Unlike the pack-bf3 CLI, the importer must keep dropping them without any
    complaint, otherwise already released .bf2 files become unreadable.
    """
    bf2_file = create_bf2_file(
        create_bf2_line(SM4200_PREPARE_TAGTYPE),
        END_OF_TAG_LINE,
        create_bf2_line(MAIN_TAGTYPE, 0, bytes(range(0x10))),
        END_OF_TAG_LINE,
    )

    bf3_file = Bf3File.bf2_import(bf2_file)

    assert [comp.description[BF3TAG.TYPE] for comp in bf3_file.components] == [
        bytes([BF3TYPE.MAIN])
    ]
