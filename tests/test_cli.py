import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from bec2format.bf3file import (
    BF3ENC,
    BF3FMT,
    BF3TAG,
    BF3TYPE,
    DEFAULT_SESSION_KEY,
    Bf3Component,
    Bf3File,
)
from bec2format.cli import main

FW_KEY = "401D6C7E98A9B469A6F598DB8E69862B"
LOADER_PAYLOAD = bytes([0xA5] * 0x40)
MAIN_PAYLOAD = bytes(range(0x100)) + bytes(range(0x2C))

# exec_bf2instrs() reads the firmware id from [:4] and the version from
# [15:22] of the firmware string
FIRMWARE_STRING = "1100 IDE Z".ljust(15) + "2.05.01"

LOADER_INSTRS: dict = {
    "Firmware": FIRMWARE_STRING,
    "Creator": "make2",
    "Bf3Update": "Supported",
    "CRC": "0x1234ABCD",
    "SELECT": {"FILTER": "010100B6", "PFIDS": "0x0000000000"},
    "SELECT_IF": {"PROTOCOL": "BRP"},
    "CHECK_FWVER": {"VERSIONDESC": "*"},
}
MAIN_INSTRS: dict = {
    "CRC": "0x89ABCDEF",
    "SELECT_IF": {"PROTOCOL": "*"},
    "CHECK_FWVER": {"VERSIONDESC": "*"},
    "REBOOT": {},
}


def decrypt(blob: bytes, key: bytes) -> bytes:
    """Decrypts as the reader firmware does: AES-128-CBC with an all zero IV."""
    decryptor = Cipher(algorithms.AES128(key), modes.CBC(bytes(16))).decryptor()
    return decryptor.update(blob) + decryptor.finalize()


def create_manifest(tmp_path: Path) -> dict:
    loader_payload_file = tmp_path / "bf3_cmp00.bin"
    loader_payload_file.write_bytes(LOADER_PAYLOAD)
    main_payload_file = tmp_path / "bf3_cmp01.bin"
    main_payload_file.write_bytes(MAIN_PAYLOAD)
    return {
        "dest": str(tmp_path / "1100_id_engine_z_firmware.bf3"),
        "fw_key": FW_KEY,
        "components": [
            {
                "tagtype": 0x70,
                "format": "BF2COMPATIBLE",
                "encryption": "PLAIN",
                "payload": str(loader_payload_file),
                "instrs": LOADER_INSTRS,
            },
            {
                "tagtype": 0x84,
                "format": "MEMIMAGE",
                "encryption": "FWKEY",
                "payload": str(main_payload_file),
                "instrs": MAIN_INSTRS,
            },
        ],
    }


def run_cli(monkeypatch: pytest.MonkeyPatch, manifest: Any) -> int:
    if not isinstance(manifest, str):
        manifest = json.dumps(manifest)
    monkeypatch.setattr(sys, "stdin", io.StringIO(manifest))
    return main(["pack-bf3"])


def get_component(bf3_file: Bf3File, bf3type: int) -> Bf3Component:
    (comp,) = [
        comp
        for comp in bf3_file.components
        if comp.description[BF3TAG.TYPE] == bytes([bf3type])
    ]
    return comp


def test_pack_bf3_writes_a_readable_bf3_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = create_manifest(tmp_path)

    assert run_cli(monkeypatch, manifest) == 0

    bf3_file = Bf3File.read_file(manifest["dest"])
    assert [comp.description[BF3TAG.TYPE] for comp in bf3_file.components] == [
        bytes([BF3TYPE.LOADER]),
        bytes([BF3TYPE.MAIN]),
    ]


def test_pack_bf3_encrypts_the_payload_with_the_firmware_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = create_manifest(tmp_path)

    run_cli(monkeypatch, manifest)

    main_comp = get_component(Bf3File.read_file(manifest["dest"]), BF3TYPE.MAIN)
    assert main_comp.description[BF3TAG.FMT] == bytes([BF3FMT.MEMORYIMAGE])
    assert main_comp.description[BF3TAG.ENC] == bytes([BF3ENC.FWKEY])
    assert main_comp.actual_len == len(MAIN_PAYLOAD)
    assert main_comp.blob != MAIN_PAYLOAD
    plain = decrypt(main_comp.blob, bytes.fromhex(FW_KEY))
    assert plain[: main_comp.actual_len] == MAIN_PAYLOAD


def test_pack_bf3_stores_plain_components_unmodified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = create_manifest(tmp_path)

    run_cli(monkeypatch, manifest)

    loader_comp = get_component(Bf3File.read_file(manifest["dest"]), BF3TYPE.LOADER)
    assert BF3TAG.ENC not in loader_comp.description
    assert loader_comp.description[BF3TAG.FMT] == bytes([BF3FMT.BF2COMPATIBLE])
    assert loader_comp.blob == LOADER_PAYLOAD


def test_pack_bf3_converts_the_bf2_instructions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = create_manifest(tmp_path)

    run_cli(monkeypatch, manifest)

    bf3_file = Bf3File.read_file(manifest["dest"])
    loader_comp = get_component(bf3_file, BF3TYPE.LOADER)
    main_comp = get_component(bf3_file, BF3TYPE.MAIN)
    assert loader_comp.description[BF3TAG.CRC] == bytes.fromhex("1234ABCD")
    assert loader_comp.description[BF3TAG.PFID2] == bytes.fromhex("010100B6")
    assert loader_comp.description[BF3TAG.INTF] == bytes([0])  # BRP_HID
    assert BF3TAG.REBOOT not in loader_comp.description
    assert main_comp.description[BF3TAG.CRC] == bytes.fromhex("89ABCDEF")
    assert main_comp.description[BF3TAG.REBOOT] == b"\x01"
    # instructions accumulate over the components, just like in bf2_import()
    assert main_comp.description[BF3TAG.PFID2] == bytes.fromhex("010100B6")


def test_pack_bf3_derives_the_comments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = create_manifest(tmp_path)

    run_cli(monkeypatch, manifest)

    comments = Bf3File.read_file(manifest["dest"]).comments
    assert comments["FirmwareId"] == "1100"
    assert comments["FirmwareVersion"] == "2.05.01"
    assert comments["Creator"] == "make2 + bf2-to-bf3-converter"
    assert comments["Bf3Update"] == "Supported"
    assert comments["Component1"].startswith("Main Firmware")


def test_pack_bf3_takes_over_the_comments_of_the_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = create_manifest(tmp_path)
    manifest["comments"] = {"CustomerId": "4711"}

    run_cli(monkeypatch, manifest)

    assert Bf3File.read_file(manifest["dest"]).comments["CustomerId"] == "4711"


def test_pack_bf3_rejects_tagtypes_without_a_bf3_counterpart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """A control tag must never be submitted to pack-bf3.

    It maps to no BF3 component, so silently dropping it would lose a
    component of the firmware (the missing SM4200/SM4500 update of FW-898).
    """
    manifest = create_manifest(tmp_path)
    # 0x34 is the SM4200 prepare tag, which is a control tag without payload
    manifest["components"].insert(
        0,
        {
            "tagtype": 0x34,
            "format": "BLOB",
            "encryption": "PLAIN",
            "payload": str(tmp_path / "does_not_exist.bin"),
            "instrs": {},
        },
    )

    assert run_cli(monkeypatch, manifest) == 1

    stderr = capsys.readouterr().err
    assert "component 0: tagtype 0x34 is a BF2 control tag" in stderr
    assert not Path(manifest["dest"]).exists()


def test_pack_bf3_encrypts_by_session_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = create_manifest(tmp_path)
    manifest["components"][1]["encryption"] = "SESSIONKEY"

    run_cli(monkeypatch, manifest)

    main_comp = get_component(Bf3File.read_file(manifest["dest"]), BF3TYPE.MAIN)
    assert main_comp.description[BF3TAG.ENC] == bytes([BF3ENC.SESSIONKEY])
    assert main_comp.actual_len == len(MAIN_PAYLOAD)
    # Bf3File.from_binary() does not decrypt session key components (it
    # compares the ENC tag with an int), so this has to be done here
    plain = decrypt(main_comp.blob, DEFAULT_SESSION_KEY)
    assert plain[: main_comp.actual_len] == MAIN_PAYLOAD


@pytest.mark.parametrize(
    ("modify_manifest", "expected_error"),
    [
        (lambda mf: mf.pop("dest"), "missing the key 'dest'"),
        (lambda mf: mf.pop("components"), "missing the key 'components'"),
        (lambda mf: mf.update(components=[]), "not contain a single BF3 component"),
        (lambda mf: mf.update(fw_key="0011"), "must be 16 bytes long"),
        (lambda mf: mf.update(fw_key="NOHEX"), "not a valid hex string"),
        (lambda mf: mf.pop("fw_key"), "encryption FWKEY requires 'fw_key'"),
        (lambda mf: mf["components"][1].update(tagtype=0xEE), "unsupported tagtype"),
        (
            lambda mf: mf["components"][1].update(format="MEMORYIMAGE"),
            "invalid format 'MEMORYIMAGE'",
        ),
        (
            lambda mf: mf["components"][1].update(encryption="RSA"),
            "invalid encryption 'RSA'",
        ),
        (lambda mf: mf["components"][1].pop("payload"), "missing the key 'payload'"),
        (
            lambda mf: mf["components"][1].update(payload="does_not_exist.bin"),
            "cannot read payload",
        ),
        (
            lambda mf: mf["components"][1].update(instrs={"SELECT_IF": {}}),
            "invalid BF2 instruction",
        ),
    ],
)
def test_pack_bf3_reports_invalid_manifests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    modify_manifest: Any,
    expected_error: str,
) -> None:
    manifest = create_manifest(tmp_path)
    modify_manifest(manifest)

    assert run_cli(monkeypatch, manifest) == 1

    stderr = capsys.readouterr().err
    assert stderr.startswith("ERROR: ")
    assert expected_error in stderr
    assert not Path(manifest.get("dest", tmp_path / "no_dest")).exists()


def test_pack_bf3_reports_a_broken_manifest(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    assert run_cli(monkeypatch, '{"dest": ') == 1

    assert "ERROR: cannot parse the manifest" in capsys.readouterr().err


def test_pack_bf3_never_writes_the_firmware_key_to_the_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    manifest = create_manifest(tmp_path)
    # provoke as many different errors as possible with a valid fw_key present
    manifest["components"][1]["format"] = "MEMORYIMAGE"

    assert run_cli(monkeypatch, manifest) == 1

    captured = capsys.readouterr()
    assert FW_KEY not in captured.out + captured.err
    assert FW_KEY.lower() not in (captured.out + captured.err).lower()


def test_pack_bf3_requires_blob_for_peripheral_tagtypes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    manifest = create_manifest(tmp_path)
    manifest["components"][1].update(tagtype=0x3D, format="MEMIMAGE")

    assert run_cli(monkeypatch, manifest) == 1

    assert "requires the format BLOB" in capsys.readouterr().err
