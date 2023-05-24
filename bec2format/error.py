class FormatError(Exception):
    pass


class Bec2FileFormatError(FormatError):
    pass


class Bf3FileFormatError(FormatError):
    pass


class UnsupportedBf2Instr(Bf3FileFormatError):
    pass


class UnsupportedTagType(Bf3FileFormatError):
    pass


class UnsupportedLegacyFirmwareError(Bf3FileFormatError):
    pass


class ConfigIdFormatError(FormatError):
    pass


class MissingProjectSettingsNameError(ConfigIdFormatError):
    pass


class MissingDeviceSettingsNameError(ConfigIdFormatError):
    pass
