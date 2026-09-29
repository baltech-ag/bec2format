# Fix the mypy errors

Commit 4: bring mypy (1.17, the version before the dependency update) from
43 errors to zero, so `inv lint` passes completely. Commit 5 then adds lint
to CI, the dependency update (mypy 2) follows in commit 7.

None of the errors is a runtime bug; annotations don't match what the code
does. Constraint: `bec2format/` also runs on MicroPython, where `typing` is a
mock. Annotations are not evaluated there (MicroPython `py/compile.c`: the
annotation of `x: y` / `x: y = z` is ignored, a bare `x: y` is a no-op and
`x: y = z` compiles like `x = z`, also for attribute targets), but runtime
typing constructs are off limits (`cast()`, `TypeVar()` would crash;
`TYPE_CHECKING` would be truthy). Module-level aliases with builtin generics
(`tuple[...]`) are evaluated and would fail there, too.

## Changes

A. `crypto.py` registry (18 errors): annotations used the registry variables
   (`Type[__AES128]`, `-> __AES128`) instead of the base classes -> annotate
   with `AES128`, `PublicEccKey`, `PrivateEccKey`. `AES128` gets an
   annotation-only `iv` declaration: `AesEncryptorMixin` sets `cipher.iv`
   before each use, the bundled implementations read `_iv` (None = zero IV,
   so behavior is identical); kept because implementations registered by
   users may read `.iv` (ToolSuite registers none).
B. `bf3file.py` path-or-file-object (10 errors): narrow with `isinstance()`
   directly in the `open(...) if ... else ...` expressions (mypy doesn't
   narrow through a stored bool). The `is_file_path` flag is gone, the
   `finally` blocks use the same `isinstance()` check (the parameters are
   never reassigned).
C. `appnotes/install_dependencies.py` (1): `mip` exists only on MicroPython ->
   mypy override `ignore_missing_imports`.
D. `configid.py` (4): `customer`/`device` annotated `Optional[int]` as in
   `create_from_prj_settings`; `version: int` in the constructor (every caller
   passes an int, also in ToolSuite; `str()` would crash on None anyway);
   `__str__` keeps its `is_baltech_naming_scheme` check and uses the new
   helper `_format_cfgid()`, which always returns `str` (shared with
   `cfgid_str`, which returns None outside the Baltech naming scheme); `device_id = 0` instead of `"0000"` (same
   output with `:04`). ToolSuite's `bal27/formats/test_configid.py`, which
   tests bec2format's `ConfigId`, passes against the change.
E. `bf3file.py` others (4):
   - `conf_dict_to_list` returns the deletion entries with `None` value or
     content on purpose (handled by `conf_dict_to_tlv`) -> return type with
     `Optional`, local lists annotated accordingly
   - `bf2_unpack_payload`: no `None` start marker anymore, the first line of
     each block sets its start address (`if not cur_block` / `elif gap`),
     same logic; covered by `tests/test_bf2_unpack_payload.py`
F. `bec2file.py` (6):
   - `InitEccAuthBlock.pack/unpack` narrowed `ext_encryptors` to
     `KeySelectorEncryptor`, but `Bec2File` passes all encryptors ->
     `Iterable[Encryptor]` as in the base class; the filter lambdas check
     `isinstance(e, KeySelectorEncryptor)` (always true there, since
     `select_encryptor` only filters `EccEncryptor` instances)
   - `AUTH_BLOCK_CLS_MAP` as explicit dict (mypy joins the three classes to
     `type` in the comprehension)
   - `AuthBlock.tag` is never None (subclasses define `TAG`,
     `UnknownAuthBlock` passes its tag) -> `self.tag: int` with a targeted
     `# type: ignore[assignment]`

## Verification

- `tox -- lint` exit code 0 (ruff check, ruff format --check, mypy, uv lock)
- `tox -- test` passes on a fresh `.venv`, appnotes scripts run with `.venv`
  Python, ToolSuite's ConfigId test passes
