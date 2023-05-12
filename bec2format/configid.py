import re
from typing import Any


UNKNOWN = 9999

class ConfigId:

    def __init__(self, customer, project, device, version, name):
        self.customer = customer if customer != UNKNOWN else None
        self.project = project if project != UNKNOWN else None
        self.device = device if device != UNKNOWN else None
        self.version = version
        self.name = name

    @classmethod
    def create_from_prj_settings(cls, config: dict) -> "ConfigId":
        try:
            version = config[0x620, 0x07].readInt8()
        except KeyError:
            raise ValueError('This config does not contain its project settings version')
        name = str(config[(0x620, 0x06)]) if (0x620, 0x06) in config else None
        try:
            customer = config[0x620, 0x01].readInt32()
            project = config[0x620, 0x05].readInt16()
            device = config.get((0x620, 0x02), bytes([0x00, 0x00])).readInt16()
        except KeyError:
            # Does not correspond to Baltech Naming Scheme
            customer = device = project = None
            if not name:
                raise ValueError('name is required if not corresponding to '
                                 'baltech naming convention')
        return cls(customer, project, device, version, name)

    @classmethod
    def create_from_dev_settings(cls, config: dict) -> "ConfigId":
        try:
            version = config[0x620, 0x04].readInt8()
        except KeyError:
            raise ValueError('This config does not contain its device settings name')
        name = str(config[(0x620, 0x03)]) if (0x620, 0x03) in config else None
        try:
            customer = config[0x620, 0x01].readInt32()
            device = config.get((0x620, 0x02), bytes([0x00, 0x00])).readInt16()
        except KeyError:
            # Does not correspond to Baltech Naming Scheme
            customer = device = None
            if not name:
                raise ValueError('name is required if not corresponding to '
                                 'baltech naming convention')
        return cls(customer, 0000, device, version, name)

    @classmethod
    def create_from_str(cls, configname: str) -> "ConfigId":
        mobj = re.match(r'(\d{5})-(\d{4})-(\d{4})-(\d{2})( (.*))?', configname)
        if mobj:
            return cls(
                customer=int(mobj.group(1)),
                project=int(mobj.group(2)),
                device=int(mobj.group(3)),
                version=int(mobj.group(4)),
                name=mobj.group(6))
        else:
            mobj = re.match(r'(.*) \(version (\d{2})\)', configname)
            if mobj:
                return cls(
                    customer=None,
                    project=None,
                    device=None,
                    version=int(mobj.group(2)),
                    name=str(mobj.group(1)))
            else:
                raise ValueError('Invalid ConfigId string format: ' + configname)

    @property
    def is_device_settings(self) -> bool:
        return self.device == 0

    @property
    def is_baltech_naming_scheme(self) -> bool:
        return self.customer is not None

    def __str__(self) -> str:
        if self.is_baltech_naming_scheme:
            return self.cfgid_str + (' ' + self.name if self.name else '')
        else:
            return '{0.name} (version {0.version:02})'.format(self)

    @property
    def cfgid_str(self) -> str | None:
        if self.is_baltech_naming_scheme:
            projectId = UNKNOWN if self.project is None else self.project
            if self.is_device_settings:
                fmtstr = '{0.customer:05}-{projectId:04}-0000-{0.version:02}'
            else:
                fmtstr = '{0.customer:05}-{projectId:04}-{0.device:04}-{0.version:02}'
            return fmtstr.format(self, projectId=projectId)
        else:
            return None

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, ConfigId):
            return self.customer == other.customer and \
                   self.project == other.project and \
                   self.device == other.device and \
                   self.version == other.version and \
                   self.name == other.name
        else:
            return False

    def __ne__(self, other: Any) -> bool:
        return not self == other

    def __repr__(self) -> str:
        return 'ConfigId({0.customer}, {0.project}, {0.device}, {0.version}, {0.name!r})'\
            .format(self)


if __name__ == '__main__':
    assert str(ConfigId(1234, 567, 890, 5, "Testname")) == '01234-0567-0890-05 Testname'
    assert str(ConfigId(1234, 567, 890, 5, None)) == '01234-0567-0890-05'
    assert str(ConfigId(None, 6789, 3456, 8, "Testname")) == 'Testname (version 08)'
    assert str(ConfigId(0, None, 0, 1, '')) == '00000-9999-0000-01'
    assert ConfigId(12345, 6789, 3456, 78, 'Testname').cfgid_str == '12345-6789-3456-78'
    assert ConfigId(12345, 6789, 3456, 78, 'Testname').is_baltech_naming_scheme
    assert ConfigId(12345, 6789, 0, 78, 'Testname').is_device_settings
    assert ConfigId(12345, 6789, 3456, 78, 'Testname') \
           == ConfigId.create_from_str('12345-6789-3456-78 Testname')
    assert ConfigId(12345, 6789, 3456, 78, None) \
           == ConfigId.create_from_str('12345-6789-3456-78')
    assert ConfigId(None, None, None, 12, 'NameOfConfig') \
           == ConfigId.create_from_str('NameOfConfig (version 12)')
