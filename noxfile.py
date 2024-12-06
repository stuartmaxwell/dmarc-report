"""Nox file."""

import nox


@nox.session(venv_backend="uv", python=["3.9", "3.10", "3.11", "3.12", "3.13"])
def test(session: nox.Session) -> None:
    """Run the test suite."""
    session.install("-e", ".", "--extra", "test", "-r", "pyproject.toml")
    session.run("pytest")
