# Run lint in CI

Commit 5: now that `inv lint` passes (ruff check, ruff format --check, mypy,
`uv lock --check`), run it in CI so new findings fail the build.

## Changes

- `.github/workflows/verify-bec2format.yml`: new job `lint`, set up like the
  `test` job (checkout, `astral-sh/setup-uv` with cache, Python from
  `.python-version`), running `uv run --all-extras inv lint`. `--all-extras`
  because mypy needs `cryptography` for `bec2format/extras/aes.py`.
  Same action versions and runner as the other jobs; the dependency update
  (commit 7) bumps all jobs together.

## Verification

- Locally: `uv run --all-extras inv lint` exits with 0.
- CI only after a push (not part of this session).
