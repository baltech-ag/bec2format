# Update dependencies

Commit 7, the last one on the branch: update all dependencies to their
latest versions, except invoke, which stays on major version 2. It comes
after the uv migration, the ruff switch, the ruff/mypy cleanup, the CI lint
job and the MicroPython spelling fix, so the risky part (new versions never run in CI before) can be
reverted on its own, and the new lint job checks it right away.

## Changes

1. `tox.ini`: `invoke==2.0.0` -> `invoke==2.2.1` (latest 2.x; the dev group
   limit `invoke>=2,<3` is already part of the uv migration commit)
2. `uv lock --upgrade` (all other packages to latest; ruff is already current
   from the ruff commit)
3. CI `verify-bec2format.yml`, all three jobs (test, lint, verify):
   - `actions/checkout@v4` -> `@v7`
   - `astral-sh/setup-uv@v8.1.0` -> `@v10.2.0` (no floating major tags since
     v8; the v9/v10 breaking changes only change defaults of `prune-cache` and
     `enable-cache: auto`, we set `enable-cache: true` explicitly)
   - `micropython_tag` `v1.25.0` -> `v1.29.0`
   - runner `ubuntu-24.04` -> `ubuntu-26.04`
4. Lint change caused by the new versions (lint passes with the old ones,
   see commit 4): mypy 2 no longer treats
   `bytearray` as `bytes` (strict bytes by default). `CustKeyEncryptor.encrypt()`
   assigned a `bytearray` to the `bytes` parameter `plaintext` -> separate
   `buffer` variable, converted once, no behavior change.

5. MicroPython v1.25.0 -> v1.29.0, release notes v1.26.0 to v1.29.0 checked.
   The only breaking change that affects this project (v1.29.0):
   `str.encode()`/`bytes.decode()` only accept "utf-8", "utf8" and "ascii"
   and raise `LookupError` otherwise (before, unsupported encodings silently
   fell back to UTF-8). The ecdsa copy in the appnotes defines
   `b(s) = s.encode("latin-1")` (replacement for `six.b` from the MicroPython
   port) in der.py, ecdsa.py, keys.py and util.py; it runs on import, so all
   four appnotes failed on v1.29.0. `b()` now builds the bytes from the code
   points (`bytes(ord(c) for c in s)`), i.e. latin-1 without the codec: same
   result on CPython, and also fixes non-ASCII input on older MicroPython
   versions (`b("\xff")` was `b"\xc3\xbf"` there). `bec2format/` itself
   only uses `.decode()` without encoding (UTF-8).
   Other breaking changes only concern hardware ports (esp32, stm32, nrf,
   powerpc) and the unix port's MICROPY_FORCE_32BIT flag, which the build
   script doesn't use; `__all__` in star imports (v1.26) and the check for
   incompletely constructed exceptions (v1.28) don't apply (no star imports,
   no custom exception `__init__`).
   Verified by building the unix port v1.25.0 and v1.29.0 (WSL, Ubuntu
   20.04) like CI and running the four appnotes on both: v1.29.0 failed
   before the fix, all pass after it.
6. `README.md`: the "Tested with the Unix port" line only named v1.20.0 on
   Ubuntu 20.04 (CI used that until 2024-10, then v1.24.1 and since 2025-05
   v1.25.0, both on Ubuntu 24.04). It now lists all combinations CI tested,
   plus v1.29.0 on Ubuntu 26.04 from this commit on. The current code runs on
   all four MicroPython versions (unix port built in WSL/Ubuntu 20.04, all
   appnotes pass), so "Compatible with MicroPython >= 1.20.0" still holds.

Switching to ruff first avoided two more adjustments this update would have
needed with the old tools (Black 26 `target-version`, and a `setuptools<82`
pin for flake8-logging-format's `pkg_resources` import).

## Not changed

- `uv_build` (`>=0.12.20,<0.13`) and pyaes 1.6.1 are already current.
- The ecdsa copy in `appnotes/register_crypto_plugin/ecdsa` (0.18.0, patched
  for MicroPython) is not re-ported to 0.19.2: the only change relevant to the
  appnotes is a DER truncation check (CVE-2026-33936), and the appnotes are not
  shipped.

## Verification

- Fresh `.venv` (an exact sync; `uv run` keeps packages that dropped out of
  the lock): `tox -- test` passes.
- `tox -- lint` passes with the new versions (ruff, mypy 2, lock check),
  as it does in the CI lint job added in commit 5.
- appnotes scripts run with `.venv` Python.
