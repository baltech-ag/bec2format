# Resolve the ruff findings

Commit 3 on top of the uv migration and the ruff switch: bring `ruff check`
from 73 findings to zero. None of the findings is a bug; they all existed with
flake8 already. The mypy errors (44) follow in commit 4, lint in CI in
commit 5, the dependency update comes last (commit 7).

Constraint: bec2format also runs on MicroPython (typing is mocked, no
`contextlib` by default, `raise ... from err` prints "exception chaining not
supported" there, see `py/vm.c` `MP_BC_RAISE_FROM`).

## Changes

1. Intentional code, marked instead of changed:
   - `bec2format/__init__.py` F401 (re-exports = public API, plus imports for
     side effects): per-file ignore
   - appnotes: example scripts assert and print on purpose -> per-file ignore
     S101/T201; `import register_crypto_plugin` (registers the crypto
     implementation, side effect) and `AES128 as AES128Base` -> `# noqa`
   - N802 on public API names (`crc8404B`, `create_AES128`,
     `register_AES128`, ...) -> `# noqa` at the definitions, the rule stays
     active for new code
2. Style findings: RET505/RET506 via `ruff check --fix`, SIM102, C408, C417,
   RET504 by hand
3. SIM105 (`contextlib.suppress`): `# noqa`, contextlib is not available on
   MicroPython by default
4. SIM115 (open without `with`, 3x in `bf3file.py`): `# noqa`, the file is
   only opened when a path is given and closed in `finally`
5. B904 (9x, `raise` inside `except` without `from`): rule switched off in
   the config, as it was with flake8 (opt-in in flake8-bugbear). `from err`
   would make MicroPython print "exception chaining not supported" whenever
   such an error is raised, and CPython already shows the original error via
   implicit chaining.

## Verification

- `ruff check` and `ruff format --check` pass
- `tox -- test` passes, appnotes scripts run with `.venv` Python
- mypy: still the same 44 errors
