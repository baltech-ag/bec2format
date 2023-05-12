from collections import namedtuple, OrderedDict
from bal27.crypto.aes import AES128
from bal27.crypto.cbc import CBC, cmac
from bal27.core import buf
from bal27.core.buf_reader import BufReader
from bal27.formats.base import FormatError
from .hwcids import HWCID_MAP, REV_HWCID_MAP
from baltech.configuration.confconvert import confDictToTlv
from .configid import ConfigId

class BF3TAG(object):
    FMT = 0xC1
    ENC = 0xC2
    TYPE = 0xC3
    HWCID = 0xC4
    REBOOT = 0xC5
    INTF = 0xC6
    CRC = 0xC7
    FWVER = 0xC8
    PFID2 = 0xC9

class BF3FMT(object):
    BLOB = 0
    MEMORYIMAGE = 1
    BF2COMPATIBLE = 2
    TLVCFG = 3

class BF3ENC(object):
    PLAIN = 0
    FWKEY = 1
    SESSIONKEY = 2

class BF3TYPE(object):
    LOADER = 0
    PERIPHERAL = 1
    MAIN = 2
    CONFIGURATION = 3

class BF3INTF(object):
    BRP_HID = 0
    BRP_SER = 1
    BRP_CCID = 2
    BRP_TCP = 3
    OSDP = 4
    NFC = 5


KEY_SIZE = 16
CMAC_SIZE = 16
END_OF_LINE = 80
DEFAULT_SESSION_KEY = buf("00" * KEY_SIZE)
BF3_FILE_SIG = "BF3\0\0"
BF2_TAGTYPE_MAP = {
    0x34: (None, None, None, None),                  # ignore SM4200 prepare tag
    0x35: (BF3TYPE.PERIPHERAL, HWCID_MAP['SM4200'], BF3FMT.BLOB, BF3INTF.NFC),
    0x39: (BF3TYPE.PERIPHERAL, HWCID_MAP['BGM12X'], BF3FMT.BLOB, None),
    0x3D: (BF3TYPE.PERIPHERAL, HWCID_MAP['PN5180'], BF3FMT.BLOB, BF3INTF.NFC),
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
    '01 01 00 B6':       HWCID_MAP['BGM12X'],
    '01 02 80 B6 00 BE': HWCID_MAP['BGM12X'],
    '01 02 80 BE 00 B6': HWCID_MAP['BGM12X'],
}

BF2_INTERFACES = {
    'BRP':       BF3INTF.BRP_HID,
    'BRP-SER':   BF3INTF.BRP_SER,
    'BRP-CCID':  BF3INTF.BRP_CCID,
    'BRP-TCP':   BF3INTF.BRP_TCP,
    'BRP-OSDP':  BF3INTF.OSDP,
    'ISO7816-4': BF3INTF.NFC,
}

Bf2BinLine = namedtuple('Bf2BinLine', 'fwtagtype, fwtagndx, fwtag, rawdata')

class UnsupportedBf2Instr(FormatError): pass  # internal excpetion

class UnsupportedTagType(FormatError):
    """
    The firmware contains an unsupported tagtype
    """

class UnsupportedLegacyFirmwareError(FormatError):
    """
    The imported firmware does not support BF3 upload
    """

def pfid2FilterToStr(pfid2filter):
    if len(pfid2filter) < 2 or \
            pfid2filter[0] != 0x01 or \
            2+pfid2filter[1]*2 != len(pfid2filter):
        raise ValueError('Invalid PFID2 Filter String: ' + pfid2filter.asStr())
    group_strs = []
    hwcid_strs = []
    for pos in range(2, len(pfid2filter), 2):
        filter_entry = pfid2filter.readInt16(pos)
        hwcid = filter_entry & 0x3FFF
        hwcid_str = REV_HWCID_MAP.get(hwcid, '0x{:04X}'.format(hwcid))
        if filter_entry & 0x4000:
            hwcid_str = '!' + hwcid_str
        hwcid_strs.append(hwcid_str)
        if not filter_entry & 0x8000:
            if len(hwcid_strs) == 1:
                group_strs += hwcid_strs
            else:
                group_strs.append('(' + ' | '.join(hwcid_strs) + ')')
            hwcid_strs = []
    return ' & '.join(group_strs)

class Bf3Component(object):
    """
    This is data component in a BF3 file.
    It can be encrypted by sessionkey or plain.
    """

    def __init__(self, description, blob, actual_len=None,
                 encrypt_by_session_key=False):
        self.description = description
        self.blob = blob
        self.actual_len = actual_len or len(blob)
        self.encrypt_by_session_key = encrypt_by_session_key

    @classmethod
    def from_encrypted_raw_data(cls, description, raw_data, actual_len,
                                session_key):
        session_cipher = CBC(AES128(session_key))
        return cls(description, session_cipher.decrypt(raw_data), actual_len,
                   encrypt_by_session_key=True)

    def __repr__(self):
        if len(self.blob) > 20:
            blob = repr(self.blob[:20])[:-2] + " ...')"
        else:
            blob = repr(self.blob)
        return 'Bf3Component({!r}, {}{}{})'.format(
            self.description,
            blob,
            ', actual_len='+str(self.actual_len) if self.actual_len else '',
            ', encrypt_by_session_key=True' if self.encrypt_by_session_key else '')

    def get_raw_data(self, session_key):
        if not self.encrypt_by_session_key:
            return self.blob
        else:
            return CBC(AES128(session_key)).padAndEncrypt(self.blob)


class Bf3File(object):

    def __init__(self, comments=None, components=None):
        self.comments = comments or OrderedDict()
        self.components = components or []

    def __repr__(self):
        return 'Bf3File({0.comments!r}, {0.components!r})'.format(self)

    def dir_to_binary(self, next_blob_adr=0, session_key=DEFAULT_SESSION_KEY):
        directory = buf()
        for comp_ndx, comp in enumerate(self.components):
            raw_data = comp.get_raw_data(session_key)
            payload_cmac = cmac(raw_data, session_key)
            dir_entry = buf()
            dir_entry += buf.int32(next_blob_adr)
            dir_entry += buf.int32(len(raw_data))
            dir_entry += buf.int32(comp.actual_len)
            dir_entry += payload_cmac
            sorted_tags = list(comp.description.items())
            if not isinstance(comp.description, OrderedDict):
                sorted_tags.sort()
            tlv_entries = buf()
            for tag_id, tag_value in sorted_tags:
                tlv_entries += buf.int8(tag_id)
                tlv_entries += buf.int8(len(tag_value))
                tlv_entries += tag_value
            dir_entry += buf.int8(len(tlv_entries))
            dir_entry += tlv_entries
            next_blob_adr += len(raw_data)
            iv = buf.int(1 + comp_ndx, CMAC_SIZE)
            dir_entry += cmac(dir_entry, session_key, iv)
            directory += buf.int8(len(dir_entry)) + dir_entry
        directory += buf.int8(0)  # sentinel which marks end of directory
        return buf.int32(len(directory)) + directory

    def to_binary(self, offset=0, session_key=DEFAULT_SESSION_KEY):
        dir_size = len(self.dir_to_binary())
        return self.dir_to_binary(offset + dir_size, session_key) \
               + buf().join(c.get_raw_data(session_key)
                            for c in self.components)

    @staticmethod
    def write_bf3_format(bf3file, comments, binary):
        is_file_path = isinstance(bf3file, str)
        bf3fileobj = open(bf3file, 'w') if is_file_path else bf3file
        try:
            sorted_comments = list(comments.items())
            if not isinstance(comments, OrderedDict):
                sorted_comments.sort()
            lines = list(map('{0[0]}: {0[1]}\n'.format, sorted_comments))
            bf3fileobj.write(''.join(lines))
            bf3fileobj.write('\n')
            rawdata = binary
            for pos in range(0, len(rawdata) + END_OF_LINE // 2 - 1, END_OF_LINE // 2):
                line = rawdata[pos:pos + END_OF_LINE // 2]
                bf3fileobj.write(format(line, 'c') + '\n')
        finally:
            if is_file_path:
                bf3fileobj.close()

    def write_file(self, bf3file, session_key=DEFAULT_SESSION_KEY):
        self.write_bf3_format(bf3file,
                              self.comments,
                              buf.raw(BF3_FILE_SIG)
                              + self.to_binary(len(BF3_FILE_SIG), session_key))

    @classmethod
    def dir_from_binary(cls, raw_rdr, check_cmac,
                        session_key=DEFAULT_SESSION_KEY):
        dir_entries = []
        total_dir_size = raw_rdr.readInt(32)
        dir_rdr = BufReader(raw_rdr.read(total_dir_size), 'Directory')
        dir_entry_len = dir_rdr.readInt(8)
        dir_entry_ndx = 1
        while dir_entry_len != 0:
            dir_entry = dir_rdr.read(dir_entry_len)
            dir_entry_rdr = BufReader(dir_entry,
                                       'Directory Entry ' + str(dir_entry_ndx))
            payload_adr = dir_entry_rdr.readInt(32)
            total_len = dir_entry_rdr.readInt(32)
            payload_len = dir_entry_rdr.readInt(32)
            if total_len < payload_len:
                raise FormatError('PayloadLen Directoryentry has to be smaller '
                                  'than TotalLen DirectoryEntry')
            payload_cmac = dir_entry_rdr.read(CMAC_SIZE)
            iv = buf.int(dir_entry_ndx, CMAC_SIZE)
            description = OrderedDict()
            description_len = dir_entry_rdr.readInt(8)
            description_rdr = BufReader(dir_entry_rdr.read(description_len),
                                        'Description Tag of Directory Entry '
                                        + str(dir_entry_ndx))
            while not description_rdr.eof():
                tag_id = description_rdr.readInt(8)
                tag_len = description_rdr.readInt(8)
                tag_value = description_rdr.read(tag_len)
                if tag_id in description:
                    raise FormatError('TagID {:02X} is contained twice in '
                                      'BF3 component'.format(tag_id))
                description[tag_id] = tag_value
            description_rdr.ensure_eof()
            stored_cmac = dir_entry_rdr.read(CMAC_SIZE)
            if check_cmac:
                actual_cmac = cmac(dir_entry[:-CMAC_SIZE], session_key, iv)
                if stored_cmac != actual_cmac:
                    raise FormatError('Invalid CMAC of BF3 directory entry')
            dir_entries.append((payload_adr, total_len, payload_len,
                                payload_cmac, description))
            dir_entry_len = dir_rdr.readInt(8)
            dir_entry_ndx += 1
            dir_entry_rdr.ensure_eof()
        dir_rdr.ensure_eof()
        return dir_entries

    @classmethod
    def from_binary(cls, raw_rdr, comments=None, check_cmac=True,
                    session_key=DEFAULT_SESSION_KEY):
        dir_entries = cls.dir_from_binary(raw_rdr, check_cmac, session_key)
        components = []
        for payload_adr, total_len, payload_len, payload_cmac, description in \
                dir_entries:
            if payload_adr != raw_rdr.pos:
                raise FormatError('Invalid Address reference')
            payload = raw_rdr.read(total_len)
            if check_cmac:
                if cmac(payload, session_key) != payload_cmac:
                    raise FormatError('Invalid CMAC of BF3 component')
            if description.get(BF3TAG.ENC) == BF3ENC.SESSIONKEY:
                comp = Bf3Component.from_encrypted_raw_data(
                    description, payload, payload_len, session_key)
            else:
                comp = Bf3Component(description, payload, payload_len)
            components.append(comp)
        raw_rdr.ensure_eof()
        return cls(comments, components)

    @classmethod
    def parse_bf3_file(cls, bf3file):
        is_file_path = isinstance(bf3file, str)
        bf3fileobj = open(bf3file) if is_file_path else bf3file
        bf3_line_iter = iter(bf3fileobj.readline, '\n')
        try:
            try:
                key_val_list = (l.split(':', 1) for l in bf3_line_iter)
                comments = OrderedDict([(k, v.strip())
                                        for k, v in key_val_list])
            except ValueError:
                raise FormatError('Invalid Comment Field Format')
            try:
                rawdata = buf(bf3fileobj.read())
            except ValueError:
                raise FormatError('Binary Data of BF3 file not in Hex format')
        finally:
            if is_file_path:
                bf3fileobj.close()
        raw_rdr = BufReader(rawdata, 'BF3 files Binary Data')
        return raw_rdr, comments

    @classmethod
    def read_file(cls, bf3file, key=None, check_cmac=True,
                  session_key=DEFAULT_SESSION_KEY):
        raw_rdr, comments = cls.parse_bf3_file(bf3file)
        if raw_rdr.read(len(BF3_FILE_SIG)) != buf.raw(BF3_FILE_SIG):
            raise FormatError('Invalid Signature for BF3 file')
        return cls.from_binary(raw_rdr, comments, check_cmac, session_key)

    @classmethod
    def parse_bf2_file(cls, bf2fileobj):
        fwdata = []
        for line in bf2fileobj:
            if line.startswith(':'):
                rdata = buf(line)
                bf2line_rdr = BufReader(rdata, 'BF2Line')
                fwtagndx = bf2line_rdr.readInt(16)
                fwtagtype = bf2line_rdr.readInt(8)
                fwtaglen = bf2line_rdr.readInt(8)
                fwtag = bf2line_rdr.read(fwtaglen)
                if fwtagtype == 0xFF:    # is end of tag marker
                    if fwdata:
                        yield 'load', fwdata
                        fwdata = []
                elif fwtagtype != 0xFE:  # is not start of tag marker
                    fwdata.append(Bf2BinLine(fwtagtype, fwtagndx, fwtag, rdata))
            elif line.startswith('#>'):
                cmd_params_tuple = line[2:].split(None, 1)
                if len(cmd_params_tuple) == 1:
                    cmd, params_str = cmd_params_tuple + ['']
                else:
                    cmd, params_str = cmd_params_tuple
                params = dict(p.strip().split('=')
                              for p in params_str.split(',') if p)
                yield cmd, params
            elif line.startswith('##'):
                name, value = line[2:].split(':')
                yield name, value.strip()

    @classmethod
    def exec_bf2instrs(cls, bf2_instrs, bf3desc, bf3comments):
        if 'REBOOT' in bf2_instrs:
            bf3desc[BF3TAG.REBOOT] = buf("01")
            del bf2_instrs['REBOOT']
        if 'CRC' in bf2_instrs:
            crcval = bf2_instrs.pop('CRC')
            bf3desc[BF3TAG.CRC] = buf.int32(int(crcval[2:], 16))
        if 'SELECT' in bf2_instrs:
            bf3desc[BF3TAG.PFID2] = buf(bf2_instrs['SELECT']['FILTER'])
            if bf3desc[BF3TAG.TYPE].readInt8() == BF3TYPE.PERIPHERAL:
                pfid2 = bf3desc[BF3TAG.PFID2].asStr()
                if pfid2 in PFID2FILTER_TO_HWCID_SPECIAL_CASES:
                    hwcid = buf().writeInt16(PFID2FILTER_TO_HWCID_SPECIAL_CASES[pfid2])
                elif pfid2.startswith('01 01'):
                    hwcid = bf3desc[BF3TAG.PFID2][-2:]
                else:
                    raise FormatError('Invalid PlatformID2 ' + pfid2)
                bf3desc[BF3TAG.HWCID] = hwcid
        if 'CHECK_FWVER' in bf2_instrs:
            versiondesc = bf2_instrs.pop('CHECK_FWVER')['VERSIONDESC']
            if versiondesc != '*':
                bf3desc[BF3TAG.FWVER] = buf(versiondesc)[3:3+buf(versiondesc)[2]]
        if 'Firmware' in bf2_instrs:
            bf3comments['FirmwareId'] = bf2_instrs['Firmware'][:4]
            bf3comments['FirmwareVersion'] = bf2_instrs['Firmware'][15:22]
            debug_fw = bf3comments['FirmwareVersion'].startswith('D-')
            if not debug_fw:
                fwid_buf = buf.int16(int(bf3comments['FirmwareId'])) + \
                           buf(list(map(int, bf3comments['FirmwareVersion'].split('.'))))
                if bf3desc[BF3TAG.TYPE] == buf([BF3TYPE.LOADER]):
                    bf3desc[BF3TAG.FWVER] = fwid_buf
                elif bf3desc[BF3TAG.TYPE] == buf([BF3TYPE.MAIN]):
                    bf3desc[BF3TAG.FWVER] = fwid_buf
        if 'Creator' in bf2_instrs:
            bf3comments['Creator'] = bf2_instrs['Creator'] + ' + bf2-to-bf3-converter'
        if 'Bf3Update' in bf2_instrs:
            bf3comments['Bf3Update'] = bf2_instrs['Bf3Update']
        if 'SELECT_IF' in bf2_instrs:
            protocol = bf2_instrs['SELECT_IF']['PROTOCOL']
            if protocol != '*':
                if protocol not in BF2_INTERFACES:
                    raise UnsupportedBf2Instr()
                bf3desc[BF3TAG.INTF] = buf.int8(BF2_INTERFACES[protocol])

    @classmethod
    def annotations(cls, comps):
        for ndx, comp in enumerate(comps):
            comptype = comp.description[BF3TAG.TYPE].readInt8()
            if comptype == BF3TYPE.MAIN:
                comp_comment = 'Main Firmware'
            elif comptype == BF3TYPE.LOADER:
                rev_intf_map = dict(list(map(reversed, list(BF3INTF.__dict__.items()))))
                intf = comp.description[BF3TAG.INTF].readInt8()
                comp_comment = rev_intf_map[intf] + ' Loader Firmware'
            elif comptype == BF3TYPE.PERIPHERAL:
                hwcid = comp.description[BF3TAG.HWCID].readInt16()
                hwcname = REV_HWCID_MAP.get(hwcid, 'HWC 0x{:X}'.format(hwcid))
                hwcversion = comp.description.get(BF3TAG.FWVER)
                if not hwcversion:
                    hwcversionstr = ''
                elif hwcname[:3] == 'SM4' and len(hwcversion) >= 4:
                    hwcversionstr = ' {}.{}.{}.{}'.format(*hwcversion)
                elif hwcname[:3] == 'BGM' and len(hwcversion) >= 7:
                    hwcversionstr = ' Version {}'.format(str(hwcversion))
                else:
                    hwcversionstr = ' Version {:c}'.format(hwcversion)
                comp_comment = '{} Firmware{}'.format(hwcname, hwcversionstr)
            else:
                raise FormatError('Unexpected Component type in BF2 File')
            if BF3TAG.PFID2 in comp.description:
                pfid2FilterStr = pfid2FilterToStr(comp.description[BF3TAG.PFID2])
                comp_comment += '    [PFID2-Filter: ' + pfid2FilterStr + ']'
            yield 'Component' + str(ndx), comp_comment

    @staticmethod
    def bf2_unpack_payload(bf2lines):
        blocks = {}
        start_tagtype = bf2lines[0].fwtagtype
        cur_block_start_adr = None
        cur_block_end_adr = 0
        cur_block = []
        for bf2line in bf2lines:
            fwtag_rdr = BufReader(bf2line.fwtag, 'BF2 Line')
            payload_len = fwtag_rdr.readInt(8) - 2
            payload_offs = (bf2line.fwtagtype - start_tagtype) * 0x10000 \
                           + fwtag_rdr.readInt(16)
            payload = fwtag_rdr.read(payload_len)
            if payload_offs != cur_block_end_adr and cur_block:
                blocks[cur_block_start_adr] = buf().join(cur_block)
                cur_block = []
                cur_block_start_adr = payload_offs
            else:
                cur_block.append(payload)
            if cur_block_start_adr is None:
                cur_block_start_adr = payload_offs
            cur_block_end_adr = payload_offs + payload_len
        if cur_block:
            blocks[cur_block_start_adr] = buf().join(cur_block)
        return blocks

    @staticmethod
    def bf2_convert_payload(bf2lines, bf3tag_fmt):
        if bf3tag_fmt == BF3FMT.BF2COMPATIBLE:
            return buf().join(l.rawdata for l in bf2lines)
        elif bf3tag_fmt == BF3FMT.BLOB:
            blocks = Bf3File.bf2_unpack_payload(bf2lines)
            if len(blocks) != 1 or 0 not in blocks:
                raise FormatError('BLOB tagtype {:04X} is expected to start at '
                                  'address 0 and must not have gaps'
                                  .format(bf2lines[0].fwtagtype))
            return blocks[0]
        elif bf3tag_fmt == BF3FMT.MEMORYIMAGE:
            content = buf()
            blocks = Bf3File.bf2_unpack_payload(bf2lines)
            for adr, data in sorted(blocks.items()):
                content += buf.int32(adr)
                content += buf.int32(len(data))
                content += data
            return content
        else:
            raise NotImplementedError('Format not supported by bf2 importer')

    @classmethod
    def bf2_import(cls, bf2file, enforce_bf3_compatibility=True):
        is_file_path = isinstance(bf2file, str)
        bf2fileobj = open(bf2file) if is_file_path else bf2file
        bf2_fwdata = []
        bf2_instrs = {}
        components = []
        comments = OrderedDict()

        def emit_bf3comp():
            fwtagtype = bf2_fwdata[0].fwtagtype
            if fwtagtype not in BF2_TAGTYPE_MAP:
                raise UnsupportedTagType(
                    "TagType 0x{:02X} is not recognized by ConfigEditor"
                    .format(fwtagtype))
            bf3tag_type, hwcid, bf3tag_fmt, interface = BF2_TAGTYPE_MAP[fwtagtype]
            if bf3tag_type is None:
                return
            desc = OrderedDict([(BF3TAG.FMT, buf.int8(bf3tag_fmt)),
                                (BF3TAG.TYPE, buf.int8(bf3tag_type))])
            if hwcid is not None:
                desc[BF3TAG.HWCID] = buf.int16(hwcid)
            if interface is not None:
                desc[BF3TAG.INTF] = buf.int8(interface)
            try:
                cls.exec_bf2instrs(bf2_instrs, desc, comments)
            except UnsupportedBf2Instr:
                pass
            except (ValueError, IndexError, KeyError):
                raise FormatError('Invalid BF2 Instruction')
            else:
                content = cls.bf2_convert_payload(bf2_fwdata, bf3tag_fmt)
                components.append(Bf3Component(desc, content))
                bf2_fwdata[:] = []

        try:
            bf2_objs = list(cls.parse_bf2_file(bf2fileobj))
        except (ValueError, IndexError, KeyError):
            raise FormatError('Invalid Bf2 File Format')
        finally:
            if is_file_path:
                bf2fileobj.close()
        for instr, params in bf2_objs:
            if instr == 'load':
                if bf2_fwdata:
                    fwtagtype = params[0].fwtagtype
                    if not is_known_tagtype(fwtagtype):
                        raise FormatError(
                            "TagType 0x{:02X} is not recognized by ConfigEditor"
                            .format(fwtagtype))
                    if fwtagtype in BF2_TAGTYPE_MAP:
                        emit_bf3comp()
                        bf2_fwdata = []
                bf2_fwdata = bf2_fwdata + params
            else:
                if instr == 'CHECK_FWVER' and 'CHECK_FWVER' in bf2_instrs:
                    emit_bf3comp()
                bf2_instrs[instr] = params
                if instr == 'REBOOT':
                    emit_bf3comp()
        if bf2_fwdata:
            emit_bf3comp()
        if enforce_bf3_compatibility and 'Bf3Update' not in comments:
            raise UnsupportedLegacyFirmwareError(
                "This is a legacy firmware that does not support BF3 upload")
        sort_cmps = sorted(components, key=lambda c: c.description[BF3TAG.TYPE])
        comments.update(cls.annotations(sort_cmps))
        return cls(comments, sort_cmps)

    def _get_config_ndx(self):
        for ndx, comp in enumerate(self.components):
            if comp.description[BF3TAG.TYPE] == BF3TYPE.CONFIGURATION:
                return ndx
        else:
            raise KeyError('Bf3 Package does not contain configuration')

    def set_config(self, config, sec_settings={}):
        try:
            del self.components[self._get_config_ndx()]
        except KeyError:
            pass

        tlvcfg_list = confDictToTlv(config, sec_settings)
        tlvcfg_blob = buf().join(buf.int8(len(tlv_block)) + tlv_block
                                 for tlv_block in tlvcfg_list) \
                      + buf('00')    # sentinel
        bf3_comp = Bf3Component({BF3TAG.TYPE: buf.int8(BF3TYPE.CONFIGURATION),
                                 BF3TAG.ENC: buf.int8(BF3ENC.SESSIONKEY),
                                 BF3TAG.FMT: buf.int8(BF3FMT.TLVCFG),
                                 BF3TAG.REBOOT: buf.int8(True)},
                                tlvcfg_blob,
                                len(tlvcfg_blob),
                                encrypt_by_session_key=True)
        self.components.append(bf3_comp)

    def derive_comments_from_config(self, config):
        try:
            prj_settings_id = ConfigId.create_from_prj_settings(config)
        except ValueError:
            self.comments.pop('Configuration', '')
        else:
            self.comments['Configuration'] = str(prj_settings_id)

        try:
            dev_settings_id = ConfigId.create_from_dev_settings(config)
        except ValueError:
            self.comments.pop('DeviceSettings', '')
        else:
            self.comments['DeviceSettings'] = str(dev_settings_id)

        if config.get((0x0620, 0x20), 0):
            self.comments["RequiresBusAddress"] = "Yes"
        else:
            self.comments.pop("RequiresBusAddress", '')


if __name__ == '__main__':
    from io import StringIO
    # ideally OrderedDicts are used instead of dicts for Bf3Files
    bf3_file = Bf3File({"FirmwareId": '1053',
                        "FirmwareVersion": "1.02.03",
                        "LegicFwVersion": "123.43"},
                       [Bf3Component({0xC1: buf("11 22 33"),
                                      0xC3: buf("12 33")},
                                     buf(list(range(0x100)))),
                        Bf3Component({0xC4: buf("11")},
                                     buf("23445356465347567567425234523"))])
    bf3_file_obj = StringIO()
    bf3_file.write_file(bf3_file_obj)
    print(bf3_file_obj.getvalue())
    bf3_file_obj.seek(0)
    print(Bf3File.read_file(bf3_file_obj))

    bf3_1100 = Bf3File.bf2_import(r"T:\bf2files\1100_id_engine_z_firmware_1_08_00.bf2")
    bf3_1100.write_file(r'T:\bf2files\1100_id_engine_z_firmware_1_08_00.bf3')
    bf3_1100_2 = Bf3File.read_file(r'T:\bf2files\1100_id_engine_z_firmware_1_08_00.bf3')
    print((repr(bf3_1100_2)))
