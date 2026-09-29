import sys
from pathlib import Path

from invoke import Context, task


@task()
def install(ctx: Context) -> None:
    """install project dependencies"""
    ctx.run("uv sync --all-extras")


@task()
def test(ctx: Context) -> None:
    """runs the unit tests"""
    ctx.run(f"pytest {Path(__file__).parent / 'tests'}")


@task()
def lint(ctx: Context, fix: bool = False) -> None:
    """runs linting jobs"""
    project_path = Path(__file__).parent
    fix_flag = "--fix" if fix else ""
    check_flag = "" if fix else "--check"
    # with --fix, fixes (e.g. import sorting) have to run before formatting
    ok = ctx.run(f"ruff check {fix_flag} {project_path}", warn=True).ok
    ok &= ctx.run(f"ruff format {check_flag} {project_path}", warn=True).ok
    ok &= ctx.run(f"mypy {project_path}", warn=True).ok
    ok &= ctx.run("uv lock --check", warn=True).ok
    if not ok:
        sys.exit(1)
