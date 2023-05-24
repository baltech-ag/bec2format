from io import BytesIO
from typing import Type


class BytesReader(BytesIO):
    def __init__(
        self,
        raw: bytes,
        source: str | None = None,
        exception: Type[Exception] = ValueError,
    ) -> None:
        super().__init__(raw)
        self.length = len(raw)
        self.source = source
        self.exception = exception

    def read_int(self, num_bytes):
        return int.from_bytes(self.read(num_bytes), byteorder="big")

    def write(self, *args, **kwargs):
        raise self.exception("BytesReader() instance is not writable")

    def eof(self):
        return self.tell() == self.length

    def ensure_eof(self):
        if not self.eof():
            source = "" if self.source is None else " of " + str(self.source)
            raise self.exception("Unexpected data at end" + source)
