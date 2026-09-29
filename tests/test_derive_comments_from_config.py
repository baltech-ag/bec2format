from bec2format.bf3file import Bf3File

REQUIRES_BUS_ADDRESS = (0x0620, 0x20)


def test_requires_bus_address_config_value_adds_no_header() -> None:
    bf3 = Bf3File()

    bf3.derive_comments_from_config({REQUIRES_BUS_ADDRESS: b"\x01"})

    assert "RequiresBusAddress" not in bf3.comments


def test_bus_address_headers_set_by_caller_are_kept() -> None:
    headers = {
        "Cfg#RequiresBusAddress": "DeviceId",
        "Cfg#MinBusAddress": "0",
        "Cfg#MaxBusAddress": "126",
    }
    bf3 = Bf3File(comments=dict(headers))

    bf3.derive_comments_from_config({})

    assert headers.items() <= bf3.comments.items()
