from binascii import unhexlify
from collections import namedtuple
from re import sub
from typing import Any, Iterable, Iterator, Optional, TextIO

from .bytes_reader import BytesReader
from .configid import ConfDict, ConfigId
from .crypto import create_AES128, pad
from .error import (
    Bf3FileFormatError,
    MissingDeviceSettingsNameError,
    MissingProjectSettingsNameError,
    UnsupportedBf2InstrError,
    UnsupportedLegacyFirmwareError,
    UnsupportedTagTypeError,
)
from .hwcids import HWCID_MAP, REV_HWCID_MAP

_space_chars = " \t\r\n,-/:"
_hex2bin_translate_table = str.maketrans(_space_chars, " " * len(_space_chars))


def hex2bin(hex_value: str) -> bytes:
    clean_hex_str = hex_value.translate(_hex2bin_translate_table)
    clean_hex_str = sub(r"\s", r"", clean_hex_str)
    if len(clean_hex_str) % 2 == 1:
        clean_hex_str = clean_hex_str[:-1] + "0" + clean_hex_str[-1]
    return unhexlify(clean_hex_str)


def cmac(data: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
    return create_AES128(key, iv).mac(data)


MAX_TLVBLOCK_SIZE = (
    127 - 10
)  # maximum size of a single unencrypted TLV block. During encryption up to 10 bytes may be added


def conf_dict_to_tlv(conf_dict: ConfDict) -> list[bytes]:
    """Converts a configuration Dictionary into a list of TLV blocks."""

    # create sorted list of tuples Key, Value, Content (conf_list)
    conf_list = conf_dict_to_list(conf_dict)
    # convert entries of conf_list into TLV parts (tuples Preface, Data, Postface)
    tlv_parts = []
    for key, value, content in conf_list:
        if value is None:
            # delete key
            tlv_parts.append((bytes([0x02, key >> 8, key & 0xFF]), bytes(), bytes()))
        elif content is None:
            # delete value
            tlv_parts.append(
                (
                    bytes([0x01, key >> 8, key & 0xFF]),
                    bytes([value, 0xFF]),
                    bytes([0xFF]),
                )
            )
        else:
            # set value
            tlv_parts.append(
                (
                    bytes([0x01, key >> 8, key & 0xFF]),
                    bytes([value, len(content)]) + content,
                    bytes([0xFF]),
                )
            )

    # merge TLV parts into TLV blocks of up to MAX_TLV_BLOCK_SIZE bytes
    tlv_blocks = [bytes()]
    last_preface = bytes()
    last_postface = bytes()
    for preface, data, postface in tlv_parts:
        if (
            len(tlv_blocks[-1] + last_postface + preface + data + postface)
            > MAX_TLVBLOCK_SIZE
        ):
            tlv_blocks[-1] += last_postface
            tlv_blocks.append(preface + data)
            last_preface, last_postface = preface, postface
        elif preface == last_preface and postface == last_postface:
            tlv_blocks[-1] += data
        else:
            tlv_blocks[-1] += last_postface + preface + data
            last_preface, last_postface = preface, postface

    if len(tlv_blocks[-1]) == 0:
        tlv_blocks.pop()
    return tlv_blocks


def conf_dict_to_list(conf_dict: ConfDict) -> list[tuple[int, int, bytes]]:
    """Converts a configuration Dictionary to a sorted list of value tuples"""
    conf_list = [
        (key, value, content)
        for (key, value), content in conf_dict.items()
        if value is not None and content is not None
    ]
    conf_list.sort()
    del_key_list = [
        (key, value, content)
        for (key, value), content in conf_dict.items()
        if value is None or content is None
    ]
    del_key_list.sort()
    return del_key_list + conf_list


class BF3TAG:
    FMT = 0xC1
    ENC = 0xC2
    TYPE = 0xC3
    HWCID = 0xC4
    REBOOT = 0xC5
    INTF = 0xC6
    CRC = 0xC7
    FWVER = 0xC8
    PFID2 = 0xC9


class BF3FMT:
    BLOB = 0
    MEMORYIMAGE = 1
    BF2COMPATIBLE = 2
    TLVCFG = 3


class BF3ENC:
    PLAIN = 0
    FWKEY = 1
    SESSIONKEY = 2


class BF3TYPE:
    LOADER = 0
    PERIPHERAL = 1
    MAIN = 2
    CONFIGURATION = 3


class BF3INTF:
    BRP_HID = 0
    BRP_SER = 1
    BRP_CCID = 2
    BRP_TCP = 3
    OSDP = 4
    NFC = 5


KEY_SIZE = 16
CMAC_SIZE = 16
END_OF_LINE = 80
DEFAULT_SESSION_KEY = bytes([0x00] * KEY_SIZE)
BF3_FILE_SIG = b"BF3\0\0"
BF2_TAGTYPE_MAP = {
    0x34: (None, None, None, None),  # ignore SM4200 prepare tag
    0x35: (BF3TYPE.PERIPHERAL, HWCID_MAP["SM4200"], BF3FMT.BLOB, BF3INTF.NFC),
    0x39: (BF3TYPE.PERIPHERAL, HWCID_MAP["BGM12X"], BF3FMT.BLOB, None),
    0x3D: (BF3TYPE.PERIPHERAL, HWCID_MAP["PN5180"], BF3FMT.BLOB, BF3INTF.NFC),
    0x70: (BF3TYPE.LOADER, None, BF3FMT.BF2COMPATIBLE, None),
    0x83: (BF3TYPE.LOADER, None, BF3FMT.BF2COMPATIBLE, None),
    0x84: (BF3TYPE.MAIN, None, BF3FMT.BF2COMPATIBLE, None),
}


def is_known_tagtype(tagtype):
    known_tagtypes = [
        (0x35, 0x38),  # SM4200
        (0x39, 0x3C),  # BLE
        (0x3D, 0x3E),  # PN5180
        (0x70, 0x73),  # UC_LOADER_V3
        (0x83, 0x83),  # UC_LOADER_V3_SINGLEBANK
        (0x84, 0xA3),  # UC_V3
    ]
    return any(
        base_tagtype <= tagtype <= end_tagtype
        for (base_tagtype, end_tagtype) in known_tagtypes
    )


PFID2FILTER_TO_HWCID_SPECIAL_CASES = {
    "01 01 00 B6": HWCID_MAP["BGM12X"],
    "01 02 80 B6 00 BE": HWCID_MAP["BGM12X"],
    "01 02 80 BE 00 B6": HWCID_MAP["BGM12X"],
}


BF2_INTERFACES = {
    "BRP": BF3INTF.BRP_HID,
    "BRP-SER": BF3INTF.BRP_SER,
    "BRP-CCID": BF3INTF.BRP_CCID,
    "BRP-TCP": BF3INTF.BRP_TCP,
    "BRP-OSDP": BF3INTF.OSDP,
    "ISO7816-4": BF3INTF.NFC,
}


Bf2BinLine = namedtuple("Bf2BinLine", "fwtagtype, fwtagndx, fwtag, rawdata")


def pfid2_filter_to_str(pfid2filter: bytes) -> str:
    if (
        len(pfid2filter) < 2
        or pfid2filter[0] != 0x01
        or 2 + pfid2filter[1] * 2 != len(pfid2filter)
    ):
        raise Bf3FileFormatError(
            "Invalid PFID2 Filter String: " + pfid2filter.hex(" ").upper()
        )
    group_strs = []
    hwcid_strs = []
    for pos in range(2, len(pfid2filter), 2):
        filter_entry = int.from_bytes(pfid2filter[pos : pos + 2], byteorder="big")
        hwcid = filter_entry & 0x3FFF
        hwcid_str = REV_HWCID_MAP.get(hwcid, "0x{:04X}".format(hwcid))
        if filter_entry & 0x4000:
            hwcid_str = "!" + hwcid_str
        hwcid_strs.append(hwcid_str)
        if not filter_entry & 0x8000:
            if len(hwcid_strs) == 1:
                group_strs += hwcid_strs
            else:
                group_strs.append("(" + " | ".join(hwcid_strs) + ")")
            hwcid_strs = []
    return " & ".join(group_strs)


class Bf3Component:
    """
    This is data component in a BF3 file.
    It can be encrypted by sessionkey or plain.
    """

    def __init__(
        self,
        description: dict,
        blob: bytes,
        actual_len: Optional[int] = None,
        encrypt_by_session_key: bool = False,
    ) -> None:
        self.description = description
        self.blob = blob
        self.actual_len = actual_len or len(blob)
        self.encrypt_by_session_key = encrypt_by_session_key

    @classmethod
    def from_encrypted_raw_data(
        cls,
        description: dict,
        raw_data: bytes,
        actual_len: Optional[int],
        session_key: bytes,
    ) -> "Bf3Component":
        session_cipher = create_AES128(session_key)
        return cls(
            description,
            session_cipher.decrypt(raw_data),
            actual_len,
            encrypt_by_session_key=True,
        )

    def __repr__(self) -> str:
        if len(self.blob) > 20:
            blob = repr(self.blob[:20])[:-2] + " ...')"
        else:
            blob = repr(self.blob)
        return "Bf3Component({!r}, {}{}{})".format(
            self.description,
            blob,
            ", actual_len=" + str(self.actual_len) if self.actual_len else "",
            ", encrypt_by_session_key=True" if self.encrypt_by_session_key else "",
        )

    def get_raw_data(self, session_key: bytes) -> bytes:
        if not self.encrypt_by_session_key:
            return self.blob
        else:
            cipher = create_AES128(session_key)
            return cipher.encrypt(pad(self.blob))


class Bf3File:
    def __init__(
        self, comments: Optional[dict] = None, components: Iterable[Bf3Component] = ()
    ) -> None:
        self.comments = comments or {}
        self.components = list(components)

    def __repr__(self) -> str:
        return "Bf3File({0.comments!r}, {0.components!r})".format(self)

    def dir_to_binary(
        self, next_blob_adr: int = 0, session_key: bytes = DEFAULT_SESSION_KEY
    ) -> bytes:
        directory = bytes()
        for comp_ndx, comp in enumerate(self.components):
            raw_data = comp.get_raw_data(session_key)
            payload_cmac = cmac(raw_data, session_key)
            dir_entry = bytes()
            dir_entry += next_blob_adr.to_bytes(4, byteorder="big")
            dir_entry += len(raw_data).to_bytes(4, byteorder="big")
            dir_entry += comp.actual_len.to_bytes(4, byteorder="big")
            dir_entry += payload_cmac
            sorted_tags = list(comp.description.items())
            if not isinstance(comp.description, dict):
                sorted_tags.sort()
            tlv_entries = bytes()
            for tag_id, tag_value in sorted_tags:
                tlv_entries += tag_id.to_bytes(1, byteorder="big")
                tlv_entries += len(tag_value).to_bytes(1, byteorder="big")
                tlv_entries += tag_value
            dir_entry += len(tlv_entries).to_bytes(1, byteorder="big")
            dir_entry += tlv_entries
            next_blob_adr += len(raw_data)
            iv = (1 + comp_ndx).to_bytes(CMAC_SIZE, byteorder="big")
            dir_entry += cmac(dir_entry, session_key, iv)
            directory += len(dir_entry).to_bytes(1, byteorder="big") + dir_entry
        directory += 0x00.to_bytes(
            1, byteorder="big"
        )  # sentinel which marks end of directory
        return len(directory).to_bytes(4, byteorder="big") + directory

    def to_binary(
        self, offset: int = 0, session_key: bytes = DEFAULT_SESSION_KEY
    ) -> bytes:
        directory = self.dir_to_binary()
        dir_size = len(directory)
        raw_dir = self.dir_to_binary(offset + dir_size, session_key)
        comps = b"".join(c.get_raw_data(session_key) for c in self.components)
        return raw_dir + comps

    @staticmethod
    def write_bf3_format(
        bf3file: str | TextIO, comments: dict[str, str], rawdata: bytes
    ) -> None:
        is_file_path = isinstance(bf3file, str)
        bf3fileobj = open(bf3file, "w") if is_file_path else bf3file
        try:
            sorted_comments = comments.items()
            if not isinstance(comments, dict):
                sorted_comments.sort()
            lines = map("{0[0]}: {0[1]}\n".format, sorted_comments)
            bf3fileobj.write("".join(lines))
            bf3fileobj.write("\n")
            for pos in range(0, len(rawdata) + END_OF_LINE // 2 - 1, END_OF_LINE // 2):
                line = rawdata[pos : pos + END_OF_LINE // 2]
                bf3fileobj.write(line.hex().upper() + "\n")
        finally:
            if is_file_path:
                bf3fileobj.close()

    def write_file(
        self, bf3file: str | TextIO, session_key: bytes = DEFAULT_SESSION_KEY
    ) -> None:
        self.write_bf3_format(
            bf3file,
            self.comments,
            BF3_FILE_SIG + self.to_binary(len(BF3_FILE_SIG), session_key),
        )

    @classmethod
    def dir_from_binary(
        cls,
        raw_rdr: BytesReader,
        check_cmac: bool,
        session_key: bytes = DEFAULT_SESSION_KEY,
    ) -> list:
        dir_entries = []
        total_dir_size = raw_rdr.read_int(4)
        dir_rdr = BytesReader(raw_rdr.read(total_dir_size), "Directory")
        dir_entry_len = dir_rdr.read_int(1)
        dir_entry_ndx = 1
        while dir_entry_len != 0:
            dir_entry = dir_rdr.read(dir_entry_len)
            dir_entry_rdr = BytesReader(
                dir_entry, "Directory Entry " + str(dir_entry_ndx)
            )
            payload_adr = dir_entry_rdr.read_int(4)
            total_len = dir_entry_rdr.read_int(4)
            payload_len = dir_entry_rdr.read_int(4)
            if total_len < payload_len:
                raise Bf3FileFormatError(
                    "PayloadLen Directoryentry has to be smaller "
                    "than TotalLen DirectoryEntry"
                )
            payload_cmac = dir_entry_rdr.read(CMAC_SIZE)
            iv = dir_entry_ndx.to_bytes(CMAC_SIZE, byteorder="big")
            description = {}
            description_len = dir_entry_rdr.read_int(1)
            description_rdr = BytesReader(
                dir_entry_rdr.read(description_len),
                "Description Tag of Directory Entry " + str(dir_entry_ndx),
            )
            while not description_rdr.eof():
                tag_id = description_rdr.read_int(1)
                tag_len = description_rdr.read_int(1)
                tag_value = description_rdr.read(tag_len)
                if tag_id in description:
                    raise Bf3FileFormatError(
                        "TagID {:02X} is contained twice in "
                        "BF3 component".format(tag_id)
                    )
                description[tag_id] = tag_value
            description_rdr.ensure_eof()
            stored_cmac = dir_entry_rdr.read(CMAC_SIZE)
            if check_cmac:
                actual_cmac = cmac(dir_entry[:-CMAC_SIZE], session_key, iv)
                if stored_cmac != actual_cmac:
                    raise Bf3FileFormatError("Invalid CMAC of BF3 directory entry")
            dir_entries.append(
                (payload_adr, total_len, payload_len, payload_cmac, description)
            )
            dir_entry_len = dir_rdr.read_int(1)
            dir_entry_ndx += 1
            dir_entry_rdr.ensure_eof()
        dir_rdr.ensure_eof()
        return dir_entries

    @classmethod
    def from_binary(
        cls,
        raw_rdr: BytesReader,
        comments: Optional[dict] = None,
        check_cmac: bool = True,
        session_key: bytes = DEFAULT_SESSION_KEY,
    ) -> "Bf3File":
        dir_entries = cls.dir_from_binary(raw_rdr, check_cmac, session_key)
        components = []
        for (
            payload_adr,
            total_len,
            payload_len,
            payload_cmac,
            description,
        ) in dir_entries:
            if payload_adr != raw_rdr.tell():
                raise Bf3FileFormatError("Invalid Address reference")
            payload = raw_rdr.read(total_len)
            if check_cmac:
                if cmac(payload, session_key) != payload_cmac:
                    raise Bf3FileFormatError("Invalid CMAC of BF3 component")
            if description.get(BF3TAG.ENC) == BF3ENC.SESSIONKEY:
                comp = Bf3Component.from_encrypted_raw_data(
                    description, payload, payload_len, session_key
                )
            else:
                comp = Bf3Component(description, payload, payload_len)
            components.append(comp)
        raw_rdr.ensure_eof()
        return cls(comments, components)

    @classmethod
    def parse_bf3_file(
        cls, bf3file: str | TextIO
    ) -> tuple[BytesReader, dict[str, str]]:
        is_file_path = isinstance(bf3file, str)
        bf3fileobj = open(bf3file, "r") if is_file_path else bf3file
        bf3_line_iter = iter(bf3fileobj.readline, "\n")
        try:
            try:
                key_val_list = (l.split(":", 1) for l in bf3_line_iter)
                comments = {k: v.strip() for k, v in key_val_list}
            except ValueError:
                raise Bf3FileFormatError("Invalid Comment Field Format")
            try:
                rawdata = bf3fileobj.read()
                binary = hex2bin(rawdata)
            except ValueError:
                raise Bf3FileFormatError("Binary Data of BF3 file not in Hex format")
        finally:
            if is_file_path:
                bf3fileobj.close()
        raw_rdr = BytesReader(binary, "BF3 files Binary Data")
        return raw_rdr, comments

    @classmethod
    def read_file(
        cls,
        bf3file: str | TextIO,
        check_cmac: bool = True,
        session_key: bytes = DEFAULT_SESSION_KEY,
    ) -> "Bf3File":
        raw_rdr, comments = cls.parse_bf3_file(bf3file)
        header = raw_rdr.read(len(BF3_FILE_SIG))
        if header != BF3_FILE_SIG:
            raise Bf3FileFormatError("Invalid Signature for BF3 file")
        return cls.from_binary(raw_rdr, comments, check_cmac, session_key)

    @classmethod
    def parse_bf2_file(cls, bf2fileobj: TextIO) -> Iterator[tuple[str, Any]]:
        fwdata: list[Bf2BinLine] = []
        for line in bf2fileobj:
            if line.startswith(":"):
                rdata = hex2bin(line)
                bf2line_rdr = BytesReader(rdata, "BF2Line")
                fwtagndx = bf2line_rdr.read_int(2)
                fwtagtype = bf2line_rdr.read_int(1)
                fwtaglen = bf2line_rdr.read_int(1)
                fwtag = bf2line_rdr.read(fwtaglen)
                if fwtagtype == 0xFF:  # is end of tag marker
                    if fwdata:
                        yield "load", fwdata
                        fwdata = []
                elif fwtagtype != 0xFE:  # is not start of tag marker
                    fwdata.append(Bf2BinLine(fwtagtype, fwtagndx, fwtag, rdata))
            elif line.startswith("#>"):
                cmd_params_tuple = line[2:].split(None, 1)
                if len(cmd_params_tuple) == 1:
                    cmd, params_str = cmd_params_tuple + [""]
                else:
                    cmd, params_str = cmd_params_tuple
                params = dict(p.strip().split("=") for p in params_str.split(",") if p)
                yield cmd, params
            elif line.startswith("##"):
                name, value = line[2:].split(":")
                yield name, value.strip()

    @classmethod
    def exec_bf2instrs(
        cls, bf2_instrs: dict, bf3desc: dict, bf3comments: dict[str, str]
    ) -> None:
        if "REBOOT" in bf2_instrs:
            bf3desc[BF3TAG.REBOOT] = b"\x01"
            del bf2_instrs["REBOOT"]
        if "CRC" in bf2_instrs:
            crcval = bf2_instrs.pop("CRC")
            bf3desc[BF3TAG.CRC] = int(crcval[2:], 16).to_bytes(4, byteorder="big")
        if "SELECT" in bf2_instrs:
            bf3desc[BF3TAG.PFID2] = hex2bin(bf2_instrs["SELECT"]["FILTER"])
            if bf3desc[BF3TAG.TYPE] == BF3TYPE.PERIPHERAL.to_bytes(1, byteorder="big"):
                pfid2 = bf3desc[BF3TAG.PFID2].hex(" ").upper()
                if pfid2 in PFID2FILTER_TO_HWCID_SPECIAL_CASES:
                    hwcid = PFID2FILTER_TO_HWCID_SPECIAL_CASES[pfid2].to_bytes(
                        2, byteorder="big"
                    )
                elif pfid2.startswith("01 01"):
                    hwcid = bf3desc[BF3TAG.PFID2][-2:]
                else:
                    raise Bf3FileFormatError("Invalid PlatformID2 " + pfid2)
                bf3desc[BF3TAG.HWCID] = hwcid
        if "CHECK_FWVER" in bf2_instrs:
            versiondesc = bf2_instrs.pop("CHECK_FWVER")["VERSIONDESC"]
            if versiondesc != "*":
                version = hex2bin(versiondesc)
                bf3desc[BF3TAG.FWVER] = version[3 : 3 + version[2]]
        if "Firmware" in bf2_instrs:
            bf3comments["FirmwareId"] = bf2_instrs["Firmware"][:4]
            bf3comments["FirmwareVersion"] = bf2_instrs["Firmware"][15:22]
            debug_fw = bf3comments["FirmwareVersion"].startswith("D-")
            if not debug_fw:
                fwid_buf = int(bf3comments["FirmwareId"]).to_bytes(
                    2, byteorder="big"
                ) + bytes(list(map(int, bf3comments["FirmwareVersion"].split("."))))
                if bf3desc[BF3TAG.TYPE] in (
                    bytes([BF3TYPE.LOADER]),
                    bytes([BF3TYPE.MAIN]),
                ):
                    bf3desc[BF3TAG.FWVER] = fwid_buf
        if "Creator" in bf2_instrs:
            bf3comments["Creator"] = bf2_instrs["Creator"] + " + bf2-to-bf3-converter"
        if "Bf3Update" in bf2_instrs:
            bf3comments["Bf3Update"] = bf2_instrs["Bf3Update"]
        if "SELECT_IF" in bf2_instrs:
            protocol = bf2_instrs["SELECT_IF"]["PROTOCOL"]
            if protocol != "*":
                if protocol not in BF2_INTERFACES:
                    raise UnsupportedBf2InstrError()
                bf3desc[BF3TAG.INTF] = BF2_INTERFACES[protocol].to_bytes(
                    1, byteorder="big"
                )

    @classmethod
    def annotations(cls, comps: list[Bf3Component]) -> Iterator[tuple[str, str]]:
        for ndx, comp in enumerate(comps):
            comptype = int.from_bytes(comp.description[BF3TAG.TYPE], byteorder="big")
            if comptype == BF3TYPE.MAIN:
                comp_comment = "Main Firmware"
            elif comptype == BF3TYPE.LOADER:
                rev_intf_map = {v: k for k, v in BF3INTF.__dict__.items()}
                intf = int.from_bytes(comp.description[BF3TAG.INTF], byteorder="big")
                comp_comment = rev_intf_map[intf] + " Loader Firmware"
            elif comptype == BF3TYPE.PERIPHERAL:
                hwcid = int.from_bytes(comp.description[BF3TAG.HWCID], byteorder="big")
                hwcname = REV_HWCID_MAP.get(hwcid, "HWC 0x{:X}".format(hwcid))
                hwcversion = comp.description.get(BF3TAG.FWVER)
                if not hwcversion:
                    hwcversionstr = ""
                elif hwcname[:3] == "SM4" and len(hwcversion) >= 4:
                    hwcversionstr = " {}.{}.{}.{}".format(*hwcversion)
                elif hwcname[:3] == "BGM" and len(hwcversion) >= 7:
                    hwcversionstr = " Version {}".format(hwcversion.decode())
                else:
                    hwcversionstr = " Version " + hwcversion.hex().upper()
                comp_comment = "{} Firmware{}".format(hwcname, hwcversionstr)
            else:
                raise Bf3FileFormatError("Unexpected Component type in BF2 File")
            if BF3TAG.PFID2 in comp.description:
                pfid2_filter_ftr = pfid2_filter_to_str(comp.description[BF3TAG.PFID2])
                comp_comment += "    [PFID2-Filter: " + pfid2_filter_ftr + "]"
            yield "Component" + str(ndx), comp_comment

    @staticmethod
    def bf2_unpack_payload(bf2lines: list[Bf2BinLine]) -> dict[int, bytes]:
        blocks: dict[int, bytes] = {}
        start_tagtype = bf2lines[0].fwtagtype
        cur_block_start_adr = None
        cur_block_end_adr = 0
        cur_block = []
        for bf2line in bf2lines:
            fwtag_rdr = BytesReader(bf2line.fwtag, "BF2 Line")
            payload_len = fwtag_rdr.read_int(1) - 2
            payload_offs = (
                bf2line.fwtagtype - start_tagtype
            ) * 0x10000 + fwtag_rdr.read_int(2)
            payload = fwtag_rdr.read(payload_len)
            if payload_offs != cur_block_end_adr and cur_block:
                blocks[cur_block_start_adr] = b"".join(cur_block)
                cur_block = []
                cur_block_start_adr = payload_offs
            else:
                cur_block.append(payload)
            if cur_block_start_adr is None:
                cur_block_start_adr = payload_offs
            cur_block_end_adr = payload_offs + payload_len
        if cur_block:
            blocks[cur_block_start_adr] = b"".join(cur_block)
        return blocks

    @staticmethod
    def bf2_convert_payload(bf2lines: list, bf3tag_fmt: int) -> bytes:
        if bf3tag_fmt == BF3FMT.BF2COMPATIBLE:
            return b"".join(l.rawdata for l in bf2lines)
        elif bf3tag_fmt == BF3FMT.BLOB:
            blocks = Bf3File.bf2_unpack_payload(bf2lines)
            if len(blocks) != 1 or 0 not in blocks:
                raise Bf3FileFormatError(
                    "BLOB tagtype {:04X} is expected to start at "
                    "address 0 and must not have gaps".format(bf2lines[0].fwtagtype)
                )
            return blocks[0]
        elif bf3tag_fmt == BF3FMT.MEMORYIMAGE:
            content = b""
            blocks = Bf3File.bf2_unpack_payload(bf2lines)
            for adr, data in sorted(blocks.items()):
                content += adr.to_bytes(4, byteorder="big")
                content += len(data).to_bytes(4, byteorder="big")
                content += data
            return content
        else:
            raise NotImplementedError("Format not supported by bf2 importer")

    @classmethod
    def bf2_import(
        cls, bf2file: str | TextIO, enforce_bf3_compatibility: bool = True
    ) -> "Bf3File":
        is_file_path = isinstance(bf2file, str)
        bf2fileobj = open(bf2file) if is_file_path else bf2file
        bf2_fwdata = []
        bf2_instrs = {}
        components = []
        comments = {}

        def emit_bf3comp():
            fwtagtype = bf2_fwdata[0].fwtagtype
            if fwtagtype not in BF2_TAGTYPE_MAP:
                raise UnsupportedTagTypeError(
                    "TagType 0x{:02X} is not recognized by ConfigEditor".format(
                        fwtagtype
                    )
                )
            bf3tag_type, hwcid, bf3tag_fmt, interface = BF2_TAGTYPE_MAP[fwtagtype]
            if bf3tag_type is None:
                return
            desc = {
                BF3TAG.FMT: bf3tag_fmt.to_bytes(1, byteorder="big"),
                BF3TAG.TYPE: bf3tag_type.to_bytes(1, byteorder="big"),
            }
            if hwcid is not None:
                desc[BF3TAG.HWCID] = hwcid.to_bytes(2, byteorder="big")
            if interface is not None:
                desc[BF3TAG.INTF] = interface.to_bytes(1, byteorder="big")
            try:
                cls.exec_bf2instrs(bf2_instrs, desc, comments)
            except UnsupportedBf2InstrError:
                pass
            except (ValueError, IndexError, KeyError):
                raise Bf3FileFormatError("Invalid BF2 Instruction")
            else:
                content = cls.bf2_convert_payload(bf2_fwdata, bf3tag_fmt)
                components.append(Bf3Component(desc, content))
                bf2_fwdata[:] = []

        try:
            bf2_objs = list(cls.parse_bf2_file(bf2fileobj))
        except (ValueError, IndexError, KeyError):
            raise Bf3FileFormatError("Invalid Bf2 File Format")
        finally:
            if is_file_path:
                bf2fileobj.close()
        for instr, params in bf2_objs:
            if instr == "load":
                if bf2_fwdata:
                    fwtagtype = params[0].fwtagtype
                    if not is_known_tagtype(fwtagtype):
                        raise Bf3FileFormatError(
                            "TagType 0x{:02X} is not recognized by ConfigEditor".format(
                                fwtagtype
                            )
                        )
                    if fwtagtype in BF2_TAGTYPE_MAP:
                        emit_bf3comp()
                        bf2_fwdata = []
                bf2_fwdata = bf2_fwdata + params
            else:
                if instr == "CHECK_FWVER" and "CHECK_FWVER" in bf2_instrs:
                    emit_bf3comp()
                bf2_instrs[instr] = params
                if instr == "REBOOT":
                    emit_bf3comp()
        if bf2_fwdata:
            emit_bf3comp()
        if enforce_bf3_compatibility and "Bf3Update" not in comments:
            raise UnsupportedLegacyFirmwareError(
                "This is a legacy firmware that does not support BF3 upload"
            )
        sort_cmps = sorted(components, key=lambda c: c.description[BF3TAG.TYPE])
        comments.update(cls.annotations(sort_cmps))
        return cls(comments, sort_cmps)

    def _get_config_ndx(self) -> int:
        for ndx, comp in enumerate(self.components):
            if comp.description[BF3TAG.TYPE] == bytes([BF3TYPE.CONFIGURATION]):
                return ndx
        else:
            raise KeyError("Bf3 Package does not contain configuration")

    def set_config(
        self, config: dict, additional_tvl_blocks: Iterable[bytes] = ()
    ) -> None:
        try:
            del self.components[self._get_config_ndx()]
        except KeyError:
            pass

        tlvcfg_list = conf_dict_to_tlv(config)

        if additional_tvl_blocks:
            tlvcfg_list += list(additional_tvl_blocks)

        tlvcfg_blob = (
            b"".join(
                [
                    len(tlv_block).to_bytes(1, byteorder="big") + tlv_block
                    for tlv_block in tlvcfg_list
                ]
            )
            + b"\x00"
        )

        bf3_comp = Bf3Component(
            {
                BF3TAG.TYPE: BF3TYPE.CONFIGURATION.to_bytes(1, byteorder="big"),
                BF3TAG.ENC: BF3ENC.SESSIONKEY.to_bytes(1, byteorder="big"),
                BF3TAG.FMT: BF3FMT.TLVCFG.to_bytes(1, byteorder="big"),
                BF3TAG.REBOOT: True.to_bytes(1, byteorder="big"),
            },
            tlvcfg_blob,
            len(tlvcfg_blob),
            encrypt_by_session_key=True,
        )
        self.components.append(bf3_comp)

    def derive_comments_from_config(self, config: ConfDict) -> None:
        try:
            prj_settings_id = ConfigId.create_from_prj_settings(config)
        except MissingProjectSettingsNameError:
            self.comments.pop("Configuration", "")
        else:
            self.comments["Configuration"] = str(prj_settings_id)

        try:
            dev_settings_id = ConfigId.create_from_dev_settings(config)
        except MissingDeviceSettingsNameError:
            self.comments.pop("DeviceSettings", "")
        else:
            self.comments["DeviceSettings"] = str(dev_settings_id)

        if config.get((0x0620, 0x20), 0):
            self.comments["RequiresBusAddress"] = "Yes"
        else:
            self.comments.pop("RequiresBusAddress", "")
