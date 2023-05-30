import sys


def install_micropython_dependencies() -> None:
    try:
        import mip
    except ImportError:
        raise RuntimeError(
            "This micropython runtime doesn't provide the mip package mananger. "
            "You need at least micropython 1.20.0."
        )

    dependencies = [
        # register_crypto_plugin/ecdsa
        "base64",
        "functools",
        "hmac",
        "itertools",
        "warnings",
        "__future__",
    ]

    for dep in dependencies:
        mip.install(dep)


if __name__ == "__main__":
    if sys.implementation.name == "micropython":
        install_micropython_dependencies()
