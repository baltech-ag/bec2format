# Migrate bec2format from Poetry to uv

Replace Poetry with uv as project/dependency manager, following the setup of
the ToolSuite repo (tox only bootstraps `invoke` + `uv`, uv manages the project
venv from `uv.lock`, CI calls `uv run inv ...` directly via `astral-sh/setup-uv`).

This is commit 1 of 2: the locked package versions stay exactly as in the
current `poetry.lock`. Updating the dependencies follows in a separate commit
(`uv lock --upgrade`, GitHub Actions, MicroPython tag, invoke pin).

## Differences to ToolSuite

- bec2format is a library that others install (ToolSuite via
  `bec2format @ git+https://github.com/baltech-ag/bec2format.git@...`, CI via
  `pip install .`), so it needs a build backend. ToolSuite has none.
  Backend: `uv_build` with `module-root = ""` (flat layout, no `src/`).
- `requires-python` stays a range (`>=3.10,<4.0`), not an exact version.
  A `.python-version` file (`3.10`) makes uv create the dev venv with 3.10,
  which is what CI tested before.

## Changes

1. `pyproject.toml`
   - `[tool.poetry]` -> `[project]` (name, version, description, authors,
     license, license-files, requires-python)
   - `[tool.poetry.extras] aes` -> `[project.optional-dependencies] aes`
   - `[tool.poetry.scripts]` -> `[project.scripts]`
   - `[tool.poetry.dev-dependencies]` -> `[dependency-groups] dev`, plus `uv`
     and `invoke` (as in ToolSuite); invoke limited to `>=2,<3`, which the tox
     pin `invoke==2.0.0` enforced before (ToolSuite's dev group has no limit,
     so its uv.lock already moved to invoke 3 while its tox.ini pins 2.2.0)
   - build-system `poetry-core` -> `uv_build`, `[tool.uv.build-backend]
     module-root = ""`
   - lint excludes: add `.venv` / `.tox-venv` where the tools don't skip them
     by default
2. `poetry.lock`, `poetry.toml` -> `uv.lock` (resolved with the versions from
   `poetry.lock` pinned via a temporary `constraint-dependencies`), new
   `.python-version`
3. `tox.ini`: ToolSuite pattern (`envdir = .tox-venv`, `skip_install`,
   deps `invoke==2.0.0` + `uv`, command `uv run --all-extras inv {posargs}`).
   `minversion` goes down from 4.4.12 to 3.28 (as in ToolSuite, `envlist`
   instead of `env_list`): with tox 3 installed locally, a tox 4 minversion
   makes tox 3 provision tox 4 into the `[testenv]` envdir `.tox-venv`, and
   tox 4 then fails recreating its own running venv there.
4. `tasks.py`: `install` -> `uv sync --all-extras`, `poetry check` ->
   `uv lock --check`
5. CI `verify-bec2format.yml`: `setup-python` + tox cache + tox replaced by
   `astral-sh/setup-uv` (enable-cache) + `uv run`; the CPython interpreter in
   the verify matrix becomes `.venv/bin/python`, and bec2format is installed
   non-editable into it with `uv sync --all-extras --no-editable` (verifies the
   uv_build package build)
6. `.gitignore`: `.venv/`, `.tox-venv/`; `.idea/watcherTasks.xml`: black/isort
   from `.venv/Scripts`
7. `README.md`: add `uv add git+...@<tag>` as install option; fix the pip
   line to `@<tag>` (pip ignores `#<tag>` and installs master HEAD; Poetry's
   `#<tag>` is correct and stays)

## Verification

- Wheel built by uv_build contains the same files and metadata as the one built
  by poetry-core (compare file list and METADATA).
- `tox -- test` and `tox -- lint` pass (same results as before the migration).
- `uv.lock` contains the same versions as `poetry.lock`.
- appnotes scripts run with `.venv` Python.
