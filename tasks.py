import sys
from pathlib import Path

from invoke import Context, task


@task()
def install(ctx: Context) -> None:
    """install project dependencies"""
    ctx.run("poetry install")


@task()
def lint(ctx: Context, fix: bool = False) -> None:
    """runs linting jobs"""
    project_path = Path(__file__).parent
    check_flag = "" if fix else "--check"
    ok = ctx.run(f"black {check_flag} {project_path}", warn=True).ok
    ok &= ctx.run(
        f"isort --settings-path={project_path / 'pyproject.toml'} {check_flag} {project_path}",
        warn=True,
    ).ok
    ok &= ctx.run(f"flake8p {project_path}", warn=True).ok
    ok &= ctx.run(f"mypy {project_path}", warn=True).ok
    ok &= ctx.run("poetry check", warn=True).ok
    if not ok:
        sys.exit(1)
