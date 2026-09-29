# Spell MicroPython consistently

Commit 6, before the dependency update (commit 7): write "MicroPython" (capital
P) wherever the project name appears in prose.

## Changes

- `README.md`: headings, the compatibility line, the CLI note
- `.github/workflows/verify-bec2format.yml`: step names
- `.github/workflows/build_micropython.sh`: comments
- `appnotes/install_dependencies.py`: error message
- `bec2format/cli.py`: module docstring

Unchanged on purpose, because they are identifiers, paths or names that are
lowercase by definition: `sys.implementation.name == "micropython"`, module and
function names (`micropython_compatibility_quirks`,
`install_micropython_dependencies`), the `micropython_tag` variable and
`cache-micropython` step id, the `micropython` binary and repository paths,
`$HOME/.micropython/lib` and URLs.

Two typos in the touched places are fixed along the way: `mananger` in the
error message and `install_depepencies.py` in the README's MicroPython
example (the script is `install_dependencies.py`).
