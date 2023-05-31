import sys


class _Mock:
    def __getattr__(self, item):
        return self

    def __getitem__(self, item):
        return self

    def __or__(self, other):
        return other

    def __ror__(self, other):
        return other


def mock_module(module_name: str) -> None:
    sys.modules[module_name] = _Mock()  # type: ignore


mock_module("typing")
