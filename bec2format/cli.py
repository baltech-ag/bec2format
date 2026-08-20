"""Command line interface of bec2format.

This module must NOT be imported by ``bec2format/__init__.py``: the whole
package directory is copied into the micropython library, where neither
``argparse`` nor ``json`` is available. It is loaded exclusively through the
``bec2format`` console script.
"""

import argparse
import json
import sys
from typing import Any, NoReturn, Optional, TextIO

from .bf3file import BF2_TAGTYPE_MAP, BF3ENC, BF3FMT, BF3TAG, Bf3Component, Bf3File
from .crypto import AES128, create_AES128
from .error import FormatError

CMD_PACK_BF3 = "pack-bf3"

FORMATS = {
    "BLOB": BF3FMT.BLOB,
    "MEMIMAGE": BF3FMT.MEMORYIMAGE,
    "BF2COMPATIBLE": BF3FMT.BF2COMPATIBLE,
    "TLVCFG": BF3FMT.TLVCFG,
}
ENCRYPTIONS = {
    "PLAIN": BF3ENC.PLAIN,
    "FWKEY": BF3ENC.FWKEY,
    "SESSIONKEY": BF3ENC.SESSIONKEY,
}

# these tagtypes address peripheral controllers that are always uploaded as a
# single opaque image
BLOB_ONLY_TAGTYPES = frozenset([0x35, 0x39, 0x3D, 0x40])


class Bf3PackError(Exception):
    """A manifest is invalid or no BF3 file can be created from it.

    The message of this exception is written to stderr and must therefore
    never contain key material or raw manifest content.
    """


def _fail(msg: str) -> NoReturn:
    raise Bf3PackError(msg)


def _require_aes_backend() -> None:
    try:
        from .extras import aes  # noqa: F401
    except ImportError:
        _fail(
            "no AES implementation is registered; install bec2format with the "
            "'aes' extra or register an own implementation"
        )


def _parse_fw_key(fw_key: Any) -> Optional[bytes]:
    if fw_key is None:
        return None
    if not isinstance(fw_key, str):
        _fail("'fw_key' must be a hex string")
    try:
        key = bytes.fromhex(fw_key)
    except ValueError:
        # deliberately without the offending value
        _fail("'fw_key' is not a valid hex string")
    if len(key) != AES128.KEY_SIZE:
        _fail(
            "'fw_key' must be {} bytes long, but is {}".format(
                AES128.KEY_SIZE, len(key)
            )
        )
    return key


def _read_payload(path: Any, cmp_name: str) -> bytes:
    if not isinstance(path, str):
        _fail("{}: 'payload' must be a file path".format(cmp_name))
    try:
        with open(path, "rb") as payload_file:
            return payload_file.read()
    except OSError as exc:
        _fail("{}: cannot read payload: {}".format(cmp_name, exc))


def _create_description(cmp_manifest: dict, cmp_name: str) -> Optional[dict]:
    """Derives the BF3 description tags of a component from its manifest.

    Returns None for tagtypes that do not map to a BF3 component at all (the
    SM4200/SM6300 control tags).
    """
    for key in ("tagtype", "format", "payload"):
        if key not in cmp_manifest:
            _fail("{}: manifest is missing the key '{}'".format(cmp_name, key))
    tagtype = cmp_manifest["tagtype"]
    if not isinstance(tagtype, int) or tagtype not in BF2_TAGTYPE_MAP:
        _fail("{}: unsupported tagtype {}".format(cmp_name, tagtype))
    bf3type, hwcid, _default_fmt, interface = BF2_TAGTYPE_MAP[tagtype]
    if bf3type is None:
        return None

    fmt_name = cmp_manifest["format"]
    if fmt_name not in FORMATS:
        _fail("{}: invalid format '{}'".format(cmp_name, fmt_name))
    if tagtype in BLOB_ONLY_TAGTYPES and fmt_name != "BLOB":
        _fail(
            "{}: tagtype 0x{:02X} requires the format BLOB, not '{}'".format(
                cmp_name, tagtype, fmt_name
            )
        )

    desc = {BF3TAG.FMT: bytes([FORMATS[fmt_name]]), BF3TAG.TYPE: bytes([bf3type])}
    if hwcid is not None:
        desc[BF3TAG.HWCID] = hwcid.to_bytes(2, "big")
    if interface is not None:
        desc[BF3TAG.INTF] = bytes([interface])
    return desc


def _encrypt(
    payload: bytes,
    desc: dict,
    cmp_manifest: dict,
    cmp_name: str,
    fw_key: Optional[bytes],
) -> Bf3Component:
    enc_name = cmp_manifest.get("encryption", "PLAIN")
    if enc_name not in ENCRYPTIONS:
        _fail("{}: invalid encryption '{}'".format(cmp_name, enc_name))
    enc = ENCRYPTIONS[enc_name]
    if enc == BF3ENC.PLAIN:
        return Bf3Component(desc, payload)
    desc[BF3TAG.ENC] = bytes([enc])
    if enc == BF3ENC.SESSIONKEY:
        return Bf3Component(
            desc, payload, actual_len=len(payload), encrypt_by_session_key=True
        )
    if fw_key is None:
        _fail("{}: encryption FWKEY requires 'fw_key' in the manifest".format(cmp_name))
    # AES-128-CBC with an all zero IV and zero padding - exactly what the
    # reader firmware expects for BF3_ENCRYPT_FWKEY components
    cipher: AES128 = create_AES128(fw_key, bytes(AES128.BLOCK_SIZE))
    return Bf3Component(desc, cipher.encrypt(payload), actual_len=len(payload))


def _create_component(
    cmp_manifest: Any,
    cmp_name: str,
    instrs: dict,
    comments: dict,
    fw_key: Optional[bytes],
) -> Optional[Bf3Component]:
    if not isinstance(cmp_manifest, dict):
        _fail("{}: manifest entry must be a JSON object".format(cmp_name))
    desc = _create_description(cmp_manifest, cmp_name)
    if desc is None:
        return None

    # BF2 instructions accumulate over all components, exactly as they do
    # while parsing a BF2 stream in Bf3File.bf2_import()
    instrs.update(cmp_manifest.get("instrs") or {})
    try:
        Bf3File.exec_bf2instrs(instrs, desc, comments)
    except FormatError as exc:
        _fail("{}: {}".format(cmp_name, exc))
    except (ValueError, IndexError, KeyError) as exc:
        _fail("{}: invalid BF2 instruction ({})".format(cmp_name, exc))

    payload = _read_payload(cmp_manifest["payload"], cmp_name)
    return _encrypt(payload, desc, cmp_manifest, cmp_name, fw_key)


def pack_bf3(manifest: Any) -> None:
    """Creates the BF3 file described by ``manifest``.

    See the README for a description of the manifest format.
    """
    _require_aes_backend()
    if not isinstance(manifest, dict):
        _fail("manifest must be a JSON object")
    for key in ("dest", "components"):
        if key not in manifest:
            _fail("manifest is missing the key '{}'".format(key))
    fw_key = _parse_fw_key(manifest.get("fw_key"))
    comments = dict(manifest.get("comments") or {})
    instrs: dict = {}
    components = []
    for cmp_ndx, cmp_manifest in enumerate(manifest["components"]):
        component = _create_component(
            cmp_manifest, "component {}".format(cmp_ndx), instrs, comments, fw_key
        )
        if component is not None:
            components.append(component)
    if not components:
        _fail("manifest does not contain a single BF3 component")

    components.sort(key=lambda comp: comp.description[BF3TAG.TYPE])
    comments.update(Bf3File.annotations(components))
    Bf3File(comments, components).write_file(manifest["dest"])


def _load_manifest(stream: TextIO) -> Any:
    try:
        return json.load(stream)
    except ValueError as exc:
        # the message of a JSON error refers to a position, not to content,
        # and thus cannot leak the firmware key
        _fail("cannot parse the manifest: {}".format(exc))


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bec2format", description="Tools for the BALTECH BEC2/BF3 file formats"
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    subparsers.add_parser(
        CMD_PACK_BF3,
        help="create a BF3 file from a manifest that is read from stdin",
        description=(
            "Creates a BF3 file from a JSON manifest that is read from stdin. "
            "The manifest may contain the firmware key, which is why it is "
            "neither passed as a file nor on the command line."
        ),
    )
    return parser


def main(argv: Optional[list] = None) -> int:
    args = create_parser().parse_args(argv)
    try:
        if args.command == CMD_PACK_BF3:
            pack_bf3(_load_manifest(sys.stdin))
    except Bf3PackError as exc:
        sys.stderr.write("ERROR: {}\n".format(exc))
        return 1
    except Exception as exc:
        # never let a traceback escape: it could expose the firmware key or
        # other parts of the manifest
        sys.stderr.write("ERROR: {}: {}\n".format(type(exc).__name__, exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
