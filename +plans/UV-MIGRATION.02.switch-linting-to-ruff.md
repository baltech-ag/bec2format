# Switch linting and formatting to ruff

Commit 2 on top of the uv migration, before the dependency update: replace
black, isort, flake8 and its plugins (flake8-awesome, flake8-simplify,
Flake8-pyproject) with ruff. mypy stays, ruff is no type checker.

Doing this before the update keeps the update simple: flake8-logging-format
(via flake8-awesome) imports `pkg_resources` without declaring setuptools, so
after `uv lock --upgrade` (setuptools no longer pulled in transitively,
`pkg_resources` removed in setuptools 82) it would need a `setuptools<82` pin;
Black 26 would need `target-version = ["py310"]`. Both tools are gone first.

## Changes

1. `pyproject.toml`
   - dev group: drop black, isort, flake8, flake8-awesome, flake8-simplify,
     Flake8-pyproject, add ruff
   - `[tool.black]`, `[tool.isort]`, `[tool.flake8]` -> `[tool.ruff]`:
     - excludes: vendored `ecdsa` / `pyaes` in the appnotes (Markdown is not
       excluded: ruff also formats the Python code blocks in `README.md`)
     - black's `skip-magic-trailing-comma = true` is not carried over: with
       ruff's default a trailing comma keeps a collection split one entry per
       line (otherwise everything that fits is joined into one line, e.g. the
       dict in the README example). Doesn't change the formatting of the code;
       isort's `split-on-trailing-comma` stays at its matching default too
     - rule selection mapped from the flake8 plugins: E/W/F (pycodestyle,
       pyflakes), I (isort), S (bandit), T10 (breakpoint), B (bugbear),
       A (builtins), C4 (comprehensions), ERA (eradicate), G (logging-format),
       T20 (print), PT (pytest-style), RET (return), N (pep8-naming),
       SIM (simplify)
     - ignore E501 (formatter handles line length), `tests/*`: S101
     - B904 stays enabled (opt-in in flake8-bugbear, default in ruff)
   - no ruff equivalent, dropped: flake8-annotations-complexity,
     flake8-expression-complexity, flake8-pytest; flake8-requirements and
     flake8-if-expr were already ignored (I900, IF100)
2. `tasks.py` `lint`: `ruff check [--fix]`, `ruff format [--check]`, mypy,
   `uv lock --check`
3. `.idea/watcherTasks.xml`: black watcher -> `ruff format`, isort watcher ->
   `ruff check --select I --fix` (same on-save behavior as before)
4. All files formatted once with `ruff format`:
   - `README.md` code examples (blank line after the import, trailing
     whitespace removed)
   - `bec2file.py`: double space in the `typing` import removed (black
     flagged this already); `bec2file.py`, `bf3file.py`, `configid.py`:
     implicitly concatenated strings joined where they fit on one line (the one
     style difference to black, not configurable)
5. `uv lock` without upgrade (60 -> 20 packages, no version changes, ruff
   added at its latest version)

## Verification

- Fresh `.venv`: `tox -- test` passes.
- `tox -- lint`: findings equivalent to the flake8 run (plus B904, minus the
  checks without ruff equivalent); `ruff format --check` flags the file black
  flagged plus the implicit string concatenations ruff joins.
- No `.venv` / `.tox-venv` / vendored files are linted.
