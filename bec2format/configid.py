import re
from typing import Any, Dict, Optional, Tuple

from .error import (
    ConfigIdFormatError,
    MissingDeviceSettingsNameError,
    MissingProjectSettingsNameError,
)

ConfDict = Dict[Tuple[int, Optional[int]], bytes]


UNKNOWN = 9999


class ConfigId:
    def __init__(
        self,
        customer: Optional[int],
        project: Optional[int],
        device: Optional[int],
        version: Optional[int],
        name: Optional[str],
    ):
        self.customer = customer if customer != UNKNOWN else None
        self.project = project if project != UNKNOWN else None
        self.device = device if device != UNKNOWN else None
        self.version = version
        self.name = name

    @classmethod
    def create_from_prj_settings(cls, config: ConfDict) -> "ConfigId":
        try:
            version = int.from_bytes(config[0x620, 0x07], "big")
        except KeyError:
            raise MissingProjectSettingsNameError(
                "This config does not contain its project settings version"
            )
        name = config[(0x620, 0x06)].decode() if (0x620, 0x06) in config else None
        try:
            customer: Optional[int] = int.from_bytes(config[0x620, 0x01], "big")
            project: Optional[int] = int.from_bytes(config[0x620, 0x05], "big")
            device: Optional[int] = int.from_bytes(
                config.get((0x620, 0x02), bytes([0x00, 0x00])), "big"
            )
        except KeyError:
            # Does not correspond to Baltech Naming Scheme
            customer = device = project = None
            if not name:
                raise MissingProjectSettingsNameError(
                    "name is required if not corresponding to baltech naming "
                    "convention"
                )
        return cls(customer, project, device, version, name)

    @classmethod
    def create_from_dev_settings(cls, config: ConfDict) -> "ConfigId":
        try:
            version = int.from_bytes(config[0x620, 0x04], "big")
        except KeyError:
            raise MissingDeviceSettingsNameError(
                "This config does not contain its device settings name"
            )
        name = config[(0x620, 0x03)].decode() if (0x620, 0x03) in config else None
        try:
            customer = int.from_bytes(config[0x620, 0x01], "big")
            device = int.from_bytes(
                config.get((0x620, 0x02), bytes([0x00, 0x00])), "big"
            )
        except KeyError:
            # Does not correspond to Baltech Naming Scheme
            customer = device = None
            if not name:
                raise MissingDeviceSettingsNameError(
                    "name is required if not corresponding to baltech naming "
                    "convention"
                )
        return cls(customer, 0000, device, version, name)

    @classmethod
    def create_from_str(cls, configname: str) -> "ConfigId":
        mobj = re.match(r"(\d{5})-(\d{4})-(\d{4})-(\d{2})( (.*))?", configname)
        if mobj:
            return cls(
                customer=int(mobj.group(1)),
                project=int(mobj.group(2)),
                device=int(mobj.group(3)),
                version=int(mobj.group(4)),
                name=mobj.group(6),
            )
        else:
            mobj = re.match(r"(.*) \(version (\d{2})\)", configname)
            if mobj:
                return cls(
                    customer=None,
                    project=None,
                    device=None,
                    version=int(mobj.group(2)),
                    name=str(mobj.group(1)),
                )
            else:
                raise ConfigIdFormatError(
                    "Invalid ConfigId string format: " + configname
                )

    @property
    def is_device_settings(self) -> bool:
        return self.device == 0

    @property
    def is_baltech_naming_scheme(self) -> bool:
        return self.customer is not None

    def __str__(self) -> str:
        if self.is_baltech_naming_scheme:
            return self.cfgid_str + (" " + self.name if self.name else "")
        else:
            return "{name} (version {version:02})".format(
                name=self.name, version=self.version
            )

    @property
    def cfgid_str(self) -> Optional[str]:
        if self.is_baltech_naming_scheme:
            project_id = UNKNOWN if self.project is None else self.project
            if self.is_device_settings:
                fmtstr = "{customer:05}-{projectId:04}-0000-{version:02}"
            else:
                fmtstr = "{customer:05}-{projectId:04}-{device:04}-{version:02}"
            return fmtstr.format(
                customer=self.customer,
                version=self.version,
                device=self.device,
                projectId=project_id,
            )
        else:
            return None

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, ConfigId):
            return (
                self.customer == other.customer
                and self.project == other.project
                and self.device == other.device
                and self.version == other.version
                and self.name == other.name
            )
        else:
            return False

    def __ne__(self, other: Any) -> bool:
        return not self == other

    def __repr__(self) -> str:
        return "ConfigId({customer}, {project}, {device}, {version}, {name!r})".format(
            customer=self.customer,
            project=self.project,
            device=self.device,
            version=self.version,
            name=self.name,
        )
